/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.whirr.compute;

import static org.jclouds.ec2.domain.RootDeviceType.EBS;
import static org.jclouds.scriptbuilder.domain.Statements.appendFile;
import static org.jclouds.scriptbuilder.domain.Statements.createOrOverwriteFile;
import static org.jclouds.scriptbuilder.domain.Statements.interpret;
import static org.jclouds.scriptbuilder.domain.Statements.newStatementList;
import static org.jclouds.scriptbuilder.statements.ssh.SshStatements.sshdConfig;
import static org.jclouds.util.Predicates2.retry;

import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import org.apache.whirr.ClusterSpec;
import org.apache.whirr.InstanceTemplate;
import org.apache.whirr.service.jclouds.StatementBuilder;
import org.jclouds.aws.ec2.AWSEC2ApiMetadata;
import org.jclouds.aws.ec2.compute.AWSEC2TemplateOptions;
import org.jclouds.cloudstack.CloudStackApiMetadata;
import org.jclouds.cloudstack.CloudStackClient;
import org.jclouds.cloudstack.compute.options.CloudStackTemplateOptions;
import org.jclouds.cloudstack.domain.IngressRule;
import org.jclouds.cloudstack.domain.SecurityGroup;
import org.jclouds.cloudstack.domain.Zone;
import org.jclouds.cloudstack.options.ListSecurityGroupsOptions;
import org.jclouds.cloudstack.predicates.JobComplete;
import org.jclouds.cloudstack.strategy.BlockUntilJobCompletesAndReturnResult;
import org.jclouds.cloudstack.suppliers.ZoneIdToZoneSupplier;
import org.jclouds.compute.ComputeService;
import org.jclouds.compute.ComputeServiceContext;
import org.jclouds.compute.domain.Template;
import org.jclouds.compute.domain.TemplateBuilder;
import org.jclouds.domain.LoginCredentials;
import org.jclouds.ec2.EC2ApiMetadata;
import org.jclouds.ec2.compute.options.EC2TemplateOptions;
import org.jclouds.ec2.compute.predicates.EC2ImagePredicates;
import org.jclouds.scriptbuilder.domain.OsFamily;
import org.jclouds.scriptbuilder.domain.Statement;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Joiner;
import com.google.common.base.Predicate;
import com.google.common.base.Splitter;
import com.google.common.base.Throwables;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Iterables;

public class BootstrapTemplate {

  private static final Logger LOG =
    LoggerFactory.getLogger(BootstrapTemplate.class);

  public static Template build(
    final ClusterSpec clusterSpec,
    ComputeService computeService,
    StatementBuilder statementBuilder,
    InstanceTemplate instanceTemplate
  ) {
    String name = "bootstrap-" + Joiner.on('_').join(instanceTemplate.getRoles());

    LOG.info("Configuring template for {}", name);

    statementBuilder.name(name);
    ensureUserExistsAndAuthorizeSudo(statementBuilder, clusterSpec.getClusterUser(),
        clusterSpec.getPublicKey(), clusterSpec.getPrivateKey());
    Statement bootstrap = statementBuilder.build(clusterSpec);

    if (LOG.isDebugEnabled()) {
      LOG.debug("Running script {}:\n{}", name, bootstrap.render(OsFamily.UNIX));
    }

    TemplateBuilder templateBuilder = computeService.templateBuilder().from(
        instanceTemplate.getTemplate() != null ? instanceTemplate.getTemplate() :
        clusterSpec.getTemplate());
    Template template = templateBuilder.build();
    template.getOptions().runScript(bootstrap);
    return setSpotInstancePriceIfSpecified(
      computeService.getContext(), clusterSpec, template, instanceTemplate
    );
  }

  private static void ensureUserExistsAndAuthorizeSudo(
      StatementBuilder builder, String user, String publicKey, String privateKey
  ) {
    builder.addExport("NEW_USER", user);
    builder.addExport("DEFAULT_HOME", "/home/users");
    builder.addStatement(0, newStatementList(
        ensureUserExistsWithPublicAndPrivateKey(user, publicKey, privateKey),
        makeSudoersOnlyPermitting(user),
        disablePasswordBasedAuth())
    );
  }

  /**
   * Set maximum spot instance price based on the configuration
   */
  private static Template setSpotInstancePriceIfSpecified(
      ComputeServiceContext context, ClusterSpec spec, Template template, InstanceTemplate instanceTemplate
  ) {

    if (AWSEC2ApiMetadata.CONTEXT_TOKEN.isAssignableFrom(context.getBackendType())) {
      template.getOptions().as(AWSEC2TemplateOptions.class)
            .spotPrice(instanceTemplate.getAwsEc2SpotPrice() != null ? instanceTemplate.getAwsEc2SpotPrice() :
                                                                       spec.getAwsEc2SpotPrice());
    }

    return mapEphemeralIfImageIsEBSBacked(context, spec, template, instanceTemplate);
  }

    /**
     * If this is an EBS-backed volume, map the ephemeral device.
     */
    private static Template mapEphemeralIfImageIsEBSBacked(ComputeServiceContext context,
                                                           ClusterSpec spec,
                                                           Template template,
                                                           InstanceTemplate instanceTemplate) {
        if (EC2ApiMetadata.CONTEXT_TOKEN.isAssignableFrom(context.getBackendType())) {
            if (EC2ImagePredicates.rootDeviceType(EBS).apply(template.getImage())) {
                template.getOptions().as(EC2TemplateOptions.class).mapEphemeralDeviceToDeviceName("/dev/sdc", "ephemeral1");
            }
        }
        return setPlacementGroup(context, spec, template, instanceTemplate);
    }
    
    /**
     * Set the placement group, if desired - if it doesn't already exist, create it.
     */
    private static Template setPlacementGroup(ComputeServiceContext context, ClusterSpec spec,
                                              Template template, InstanceTemplate instanceTemplate) {
        if (AWSEC2ApiMetadata.CONTEXT_TOKEN.isAssignableFrom(context.getBackendType())) {
            if (spec.getAwsEc2PlacementGroup() != null) {
                template.getOptions().as(AWSEC2TemplateOptions.class).placementGroup(spec.getAwsEc2PlacementGroup());
            }
        }

        return setCloudStackKeyPair(context, spec, template, instanceTemplate);
    }

  /**
   * Set the CloudStack keypair, if desired. Use the private key and public key provided in the spec.
   */
  private static Template setCloudStackKeyPair(ComputeServiceContext context, ClusterSpec spec,
                                               Template template, InstanceTemplate instanceTemplate) {
    if (CloudStackApiMetadata.CONTEXT_TOKEN.isAssignableFrom(context.getBackendType())) {
      if (spec.getCloudStackKeyPair() != null) {
        LoginCredentials credentials = LoginCredentials.builder()
          .user(spec.getTemplate().getLoginUser()).privateKey(spec.getPrivateKey()).build();
        context.utils().getCredentialStore().put("keypair#" + spec.getCloudStackKeyPair(), credentials);
        template.getOptions().overrideLoginCredentials(credentials);
        template.getOptions().as(CloudStackTemplateOptions.class).keyPair(spec.getCloudStackKeyPair());
      }
    }
    
    return setCloudStackSecurityGroup(context, spec, template, instanceTemplate);
  }
  
  /**
   * Set the CloudStack security group, if desired - if it doesn't already exist, create it.
   */
  private static Template setCloudStackSecurityGroup(ComputeServiceContext context, ClusterSpec spec,
                                                     Template template, InstanceTemplate instanceTemplate) {
    if (CloudStackApiMetadata.CONTEXT_TOKEN.isAssignableFrom(context.getBackendType())
        && spec.getUseCloudStackSecurityGroup()) {
      
      CloudStackClient csClient = context.unwrap(CloudStackApiMetadata.CONTEXT_TOKEN).getApi();
      BlockUntilJobCompletesAndReturnResult blockTask = context.utils().injector().getInstance(BlockUntilJobCompletesAndReturnResult.class);
      ZoneIdToZoneSupplier zoneIdToZone = context.utils().injector().getInstance(ZoneIdToZoneSupplier.class);

      final String zoneId = template.getLocation().getId();
      Zone zone = null;
      try {
         zone = zoneIdToZone.get().get(zoneId);
      } catch (ExecutionException e) {
         throw Throwables.propagate(e);
      }

      if (zone.isSecurityGroupsEnabled()) {
      
        Set<SecurityGroup> groups =
                csClient.getSecurityGroupClient()
                        .listSecurityGroups(ListSecurityGroupsOptions.Builder.named("jclouds-" + spec.getClusterName()));

        SecurityGroup group = null;
        if (groups.isEmpty()) {
          LOG.warn("Creating security group");
          group = csClient.getSecurityGroupClient().createSecurityGroup("jclouds-" + spec.getClusterName());
        } else {
          LOG.warn("Using existing security group");
          group = Iterables.get(groups, 0);
        }
        
        if (group != null) {
          if (!Iterables.any(group.getIngressRules(), new Predicate<IngressRule>() {
                @Override
                public boolean apply(IngressRule rule) {
                  return rule.getStartPort() == 22;
                }
              })) {
            Predicate<String> jobComplete =  retry(new JobComplete(csClient), 1200, 1, 5, TimeUnit.SECONDS);
            jobComplete.apply(csClient.getSecurityGroupClient().authorizeIngressPortsToCIDRs(group.getId(), "TCP", 22,
                                                                                             22, spec.getClientCidrs()));
          }
          template.getOptions().as(CloudStackTemplateOptions.class).securityGroupId(group.getId());
          template.getOptions().as(CloudStackTemplateOptions.class).setupStaticNat(false);
        }
      }
    }

    return template;
  }

  // must be used inside InitBuilder, as this sets the shell variables used in this statement
  private static Statement ensureUserExistsWithPublicAndPrivateKey(String username,
     String publicKey, String privateKey) {
    // note directory must be created first
    return newStatementList(
      interpret(
        "USER_HOME=$DEFAULT_HOME/$NEW_USER",
        "mkdir -p $USER_HOME/.ssh",
        "useradd -u 2000 --shell /bin/bash -d $USER_HOME $NEW_USER",
        "[ $? -ne 0 ] && USER_HOME=$(grep $NEW_USER /etc/passwd | cut -d \":\" -f6)\n"),
      appendFile(
        "$USER_HOME/.ssh/authorized_keys",
        Splitter.on('\n').split(publicKey)),
      createOrOverwriteFile(
        "$USER_HOME/.ssh/id_rsa.pub",
        Splitter.on('\n').split(publicKey)),
      createOrOverwriteFile(
        "$USER_HOME/.ssh/id_rsa",
        Splitter.on('\n').split(privateKey)),
      interpret(
        "chmod 400 $USER_HOME/.ssh/*",
        "chown -R $NEW_USER $USER_HOME\n"));
  }

  // must be used inside InitBuilder, as this sets the shell variables used in this statement
  private static Statement makeSudoersOnlyPermitting(String username) {
    return newStatementList(
      interpret(
        "rm /etc/sudoers",
        "touch /etc/sudoers",
        "chmod 0440 /etc/sudoers",
        "chown root /etc/sudoers\n"),
      appendFile(
        "/etc/sudoers",
        ImmutableSet.of(
          "root ALL = (ALL) ALL",
          "%adm ALL = (ALL) ALL",
          username + " ALL = (ALL) NOPASSWD: ALL")
        )
    );
  }

  private static Statement disablePasswordBasedAuth() {
    return sshdConfig(ImmutableMap.of("PasswordAuthentication","no"));
  }
}
