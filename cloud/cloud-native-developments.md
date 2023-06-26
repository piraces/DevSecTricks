---
description: Be careful with your cloud ☁️
---

# Cloud native

## About

Cloud-native security refers to a set of security practices and technologies designed specifically for applications built and deployed in cloud environments. It involves a shift in mindset from traditional security approaches, which often rely on network-based protections, to a more application-focused approach that emphasizes identity and access management, container security and workload security, and continuous monitoring and response.

In a cloud-native security approach, security is built into the application and infrastructure from the ground up, rather than added on as an afterthought. This requires a combination of automated security controls, DevOps processes, and skilled security professionals who can manage the complex and dynamic nature of cloud environments. The goal of cloud native-security is to protect against threats and vulnerabilities that are unique to cloud environments, while also ensuring compliance with regulations and standards. \[1]

## Best practices

From [OWASP Cloud-Native Application Security Top 10](https://owasp.org/www-project-cloud-native-application-security-top-10/) \[2] (CNAS, by order), **try to avoid**:

* [ ] Insecure cloud, container or orchestration configuration
  * [ ] Publicly open cloud storage buckets
  * [ ] Improper permissions set on cloud storage buckets
  * [ ] Container runs as root
  * [ ] Container shares resources with the host (network interface, etc.)
  * [ ] Insecure Infrastructure-as-Code (IaC) configuration&#x20;
    * [ ] See [infrastructure-as-code-iac.md](../tools/infrastructure-as-code-iac.md "mention")
* [ ] Injection flaws (app layer, cloud events, cloud services)
  * [ ] SQL injection
  * [ ] XXE
  * [ ] NoSQL injection
  * [ ] OS command injection
  * [ ] Serverless event data injection
* [ ] Improper authentication & authorization
  * [ ] Unauthenticated API access on a microservice
  * [ ] Over-permissive cloud IAM role
  * [ ] Lack of orchestrator node trust rules (e.g. unauthorized hosts joining the cluster)
  * [ ] Unauthenticated orchestrator console access
  * [ ] Unauthorized or overly-permissive orchestrator access
* [ ] CI/CD pipeline & software supply chain flaws
  * [ ] Insufficient authentication on CI/CD pipeline systems
  * [ ] Use of untrusted images
  * [ ] Use of stale images
  * [ ] Insecure communication channels to registries
  * [ ] Overly-permissive registry access
  * [ ] Using a single environment to run CI/CD tasks for projects requiring different levels of security
* [ ] Insecure secrets storage
  * [ ] See [secrets-management.md](../tools/secrets/secrets-management.md "mention")
  * [ ] Orchestrator secrets stored unencrypted
  * [ ] API keys or passwords stored unencrypted inside containers
  * [ ] Hardcoded application secrets
  * [ ] Poorly encrypted secrets (e.g. use of obsolete encryption methods, use of encoding instead of encryption, etc.)
    * [ ] See [cryptography.md](../generic-development/cryptography.md "mention")
  * [ ] Mounting of storage containing sensitive information
* [ ] Over-permissive or insecure network policies
  * [ ] Over-permissive pod to pod communication allowed
  * [ ] Internal microservices exposed to the public Internet
  * [ ] No network segmentation defined
  * [ ] End-to-end communications not encrypted
  * [ ] Network traffic to unknown or potentially malicious domains not monitored and blocked
* [ ] Using components with known vulnerabilities
  * [ ] See [dependency-management.md](../tools/dependency-management.md "mention")
  * [ ] Vulnerable 3rd party open source packages
  * [ ] Vulnerable versions of application components
  * [ ] Use of known vulnerable container images
* [ ] Improper assets management
  * [ ] Undocumented microservices & APIs
  * [ ] Obsolete & unmanaged cloud resources
* [ ] Inadequate "compute" resource quota limits
  * [ ] Resource-unbound containers
  * [ ] Over-permissive request quota set on APIs
* [ ] Ineffective logging & monitoring (e.g. runtime activity)
  * [ ] No container or host process activity monitoring
  * [ ] No network communications monitoring among microservices
  * [ ] No resource consumption monitoring to ensure availability of critical resources
  * [ ] Lack of monitoring on orchestration configuration propagation and stale configs

## Resources

Find here a complete list of resources related to cloud security.

### Governance

#### AWS Governance

* [AWS CloudFormation Guard](https://github.com/aws-cloudformation/cloudformation-guard)
* [AWS CodePipeline Governance](https://github.com/awslabs/aws-codepipeline-governance)
* [AWS Config Rules Development Kit](https://github.com/awslabs/aws-config-rdklib)
* [AWS Control Tower Customizations](https://github.com/awslabs/aws-control-tower-customizations)
* [AWS Security Hub Automated Response and Remediation](https://github.com/awslabs/aws-security-hub-automated-response-and-remediation)
* [AWS Vault](https://github.com/99designs/aws-vault)
* [AWS Well Architected Labs](https://github.com/awslabs/aws-well-architected-labs)

#### MultiCloud Governance

* [Cloud Custodian](https://github.com/cloud-custodian/cloud-custodian)
* [CloudQuary](https://github.com/cloudquery/cloudquery)
* [Cloudsploit](https://github.com/aquasecurity/cloudsploit)
* [ManageIQ by RedHat](https://github.com/ManageIQ/manageiq)
* [Mist.io](https://github.com/mistio/mist-ce)
* [NeuVector](https://github.com/neuvector/neuvector)
* [Triton by Joyent](https://github.com/joyent/triton)

### Standards

#### Compliances

* [CSA STAR](https://cloudsecurityalliance.org/star/)
* [ISO/IEC 27017:2015](https://www.iso.org/standard/43757.html)
* [ISO/IEC 27018:2019](https://www.iso.org/standard/76559.html)
* [MTCS SS 584](https://www.imda.gov.sg/regulations-and-licensing-listing/ict-standards-and-quality-of-service/IT-Standards-and-Frameworks/ComplianceAndCertification)
* [CCM](https://cloudsecurityalliance.org/group/cloud-controls-matrix)
* [NIST 800-53](https://nvd.nist.gov/800-53)

#### Benchmarks

* [CIS Benchmark](https://www.cisecurity.org/cis-benchmarks/)

### Tools

#### Infrastructure

* [aws\_pwn](https://github.com/dagrz/aws\_pwn): A collection of AWS penetration testing junk
* [aws\_ir](https://github.com/ThreatResponse/aws\_ir): Python installable command line utility for mitigation of instance and key compromises.
* [aws-firewall-factory](https://github.com/globaldatanet/aws-firewall-factory): Deploy, update, and stage your WAFs while managing them centrally via FMS.
* [aws-vault](https://github.com/99designs/aws-vault): A vault for securely storing and accessing AWS credentials in development environments.
* [awspx](https://github.com/FSecureLABS/awspx): A graph-based tool for visualizing effective access and resource relationships within AWS.
* [azucar](https://github.com/nccgroup/azucar): A security auditing tool for Azure environments
* [checkov](https://github.com/bridgecrewio/checkov): A static code analysis tool for infrastructure-as-code.
* [cloud-forensics-utils](https://github.com/google/cloud-forensics-utils): A python lib for DF & IR on the cloud.
* [Cloud-Katana](https://github.com/Azure/Cloud-Katana): Automate the execution of simulation steps in multi-cloud and hybrid cloud environments.
* [cloudlist](https://github.com/projectdiscovery/cloudlist): Listing Assets from multiple Cloud Providers.
* [Cloud Sniper](https://github.com/cloud-sniper/cloud-sniper): A platform designed to manage Cloud Security Operations.
* [Cloudmapper](https://github.com/duo-labs/cloudmapper): Analyze your AWS environments.
* [Cloudmarker](https://github.com/cloudmarker/cloudmarker): A cloud monitoring tool and framework.
* [Cloudsploit](https://github.com/aquasecurity/cloudsploit): Cloud security configuration checks.
* [CloudQuery](https://github.com/cloudquery/cloudquery): Open source cloud asset inventory with set of pre-baked SQL [policies](https://hub.cloudquery.io/policies) for security and compliance.
* [Cloud-custodian](https://github.com/cloud-custodian/cloud-custodian): Rules engine for cloud security, cost optimization, and governance.
* [consoleme](https://github.com/Netflix/consoleme): A Central Control Plane for AWS Permissions and Access
* [cs suite](https://github.com/SecurityFTW/cs-suite): Tool for auditing the security posture of AWS/GCP/Azure.
* [Deepfence ThreatMapper](https://github.com/deepfence/ThreatMapper): Apache v2, powerful runtime vulnerability scanner for kubernetes, virtual machines and serverless.
* [dftimewolf](https://github.com/log2timeline/dftimewolf): A multi-cloud framework for orchestrating forensic collection, processing and data export.
* [diffy](https://github.com/Netflix-Skunkworks/diffy): Diffy is a digital forensics and incident response (DFIR) tool developed by Netflix.
* [ElectricEye](https://github.com/jonrau1/ElectricEye): Continuously monitor AWS services for configurations.
* [Forseti security](https://github.com/forseti-security/forseti-security): GCP inventory monitoring and policy enforcement tool.
* [Hammer](https://github.com/dowjones/hammer): A multi-account cloud security tool for AWS. It identifies misconfigurations and insecure data exposures within most popular AWS resources.
* [kics](https://github.com/Checkmarx/kics): Find security vulnerabilities, compliance issues, and infrastructure misconfigurations early in the development cycle of your infrastructure-as-code.
* [Matano](https://github.com/matanolabs/matano): Open source serverless security lake platform on AWS that lets you ingest, store, and analyze data into an Apache Iceberg data lake and run realtime Python detections as code.
* [Metabadger](https://github.com/salesforce/metabadger): Prevent SSRF attacks on AWS EC2 via automated upgrades to the more secure Instance Metadata Service v2 (IMDSv2).
* [Open policy agent](https://www.openpolicyagent.org/): Policy-based control tool.
* [pacbot](https://github.com/tmobile/pacbot): Policy as Code Bot.
* [pacu](https://github.com/RhinoSecurityLabs/pacu): The AWS exploitation framework.
* [Prowler](https://github.com/toniblyx/prowler): Command line tool for AWS Security Best Practices Assessment, Auditing, Hardening and Forensics Readiness Tool.
* [ScoutSuite](https://github.com/nccgroup/ScoutSuite): Multi-cloud security auditing tool.
* [Security Monkey](https://github.com/Netflix/security\_monkey): Monitors AWS, GCP, OpenStack, and GitHub orgs for assets and their changes over time.
* [SkyWrapper](https://github.com/cyberark/SkyWrapper): Tool helps to discover suspicious creation forms and uses of temporary tokens in AWS.
* [Smogcloud](https://github.com/BishopFox/smogcloud): Find cloud assets that no one wants exposed.
* [Steampipe](https://github.com/turbot/steampipe): A Postgres FDW that maps APIs to SQL, plus suites of [API plugins](https://hub.steampipe.io/plugins) and [compliance mods](https://hub.steampipe.io/mods) for AWS/Azure/GCP and many others.
* [Terrascan](https://github.com/accurics/terrascan): Detect compliance and security violations across Infrastructure as Code to mitigate risk before provisioning cloud native infrastructure.
* [tfsec](https://github.com/liamg/tfsec): Static analysis powered security scanner for Terraform code.
* [Zeus](https://github.com/DenizParlak/Zeus): AWS Auditing & Hardening Tool.
* [AWS Security Benchmark](https://github.com/awslabs/aws-security-benchmark)
* [AWS Missing Tools by CloudAvail](https://github.com/cloudavail/aws-missing-tools)

#### Container

* [auditkube](https://github.com/opszero/auditkube): Audit for for EKS, AKS and GKE for HIPAA/PCI/SOC2 compliance and cloud security.
* [Falco](https://github.com/falcosecurity/falco): Container runtime security.
* [mkit](https://github.com/darkbitio/mkit): Managed kubernetes inspection tool.
* [Open policy agent](https://www.openpolicyagent.org/): Policy-based control tool.
* [Anchore Engine](https://github.com/anchore/anchore-engine)
* [Grype](https://github.com/anchore/grype)
* [Kai](https://github.com/anchore/kai)
* [Syft](https://github.com/anchore/syft)
* [Cloudsploit](https://github.com/aquasecurity/cloudsploit)
* [Kube-Bench](https://github.com/aquasecurity/kube-bench)
* [Kube-Hunter](https://github.com/aquasecurity/kube-hunter)
* [Kubectl-who-can](https://github.com/aquasecurity/kubectl-who-can)
* [Trivy](https://github.com/aquasecurity/trivy)
* [Docker - Docker Bench for Security](https://github.com/docker/docker-bench-security)
* [Elias - Dagda](https://github.com/eliasgranderubio/dagda/)
* [Falco Security - Falco](https://github.com/falcosecurity/falco)
* [Harbor - Harbor](https://github.com/goharbor/harbor)
* [Quay - Clair](https://github.com/quay/clair)
* [Snyk - Snyk](https://github.com/snyk/snyk)
* [vchinnipilli - Kubestriker](https://github.com/vchinnipilli/kubestriker)

#### SaaS

* [aws-allowlister](https://github.com/salesforce/aws-allowlister): Automatically compile an AWS Service Control Policy with your preferred compliance frameworks.
* [binaryalert](https://github.com/airbnb/binaryalert): Serverless S3 yara scanner.
* [cloudsplaining](https://github.com/salesforce/cloudsplaining): An AWS IAM Security Assessment tool that identifies violations of least privilege and generates a risk-prioritized report.
* [Cloud Guardrails](https://github.com/salesforce/cloud-guardrails): Rapidly cherry-pick cloud security guardrails by generating Terraform files that create Azure Policy Initiatives.
* [Function Shield](https://github.com/puresec/FunctionShield): Protection/destection lib of aws lambda and gcp function.
* [FestIN](https://github.com/cr0hn/festin): S3 bucket finder and content discover.
* [GCPBucketBrute](https://github.com/RhinoSecurityLabs/GCPBucketBrute): A script to enumerate Google Storage buckets.
* [IAM Zero](https://github.com/common-fate/iamzero): Detects identity and access management issues and automatically suggests least-privilege policies.
* [Lambda Guard](https://github.com/Skyscanner/LambdaGuard): AWS Lambda auditing tool.
* [Policy Sentry](https://github.com/salesforce/policy\_sentry): IAM Least Privilege Policy Generator.
* [S3 Inspector](https://github.com/kromtech/s3-inspector): Tool to check AWS S3 bucket permissions.
* [Serverless Goat](https://github.com/OWASP/Serverless-Goat): A serverless application demonstrating common serverless security flaws.
* [SkyArk](https://github.com/cyberark/SkyArk): Tool to helps to discover, assess and secure the most privileged entities in Azure and AWS.
* [Terraform for Policy Guru](https://github.com/salesforce/terraform-provider-policyguru)
* [Aardvark](https://github.com/Netflix-Skunkworks/aardvark)
* [PolicyUniverse](https://github.com/Netflix-Skunkworks/policyuniverse)
* [Repokid](https://github.com/Netflix/Repokid)
* [AWS IAM Generator](https://github.com/awslabs/aws-iam-generator)
* [Parliament](https://github.com/duo-labs/parliament)
* [CloudTracker](https://github.com/duo-labs/cloudtracker)

#### Native tools

* AWS:
  * [Artifact](https://aws.amazon.com/artifact/): Compliance report selfservice.
  * [Audit manager](https://aws.amazon.com/audit-manager/): Continuously audit for AWS usage.
  * [Certificate Manager](https://aws.amazon.com/certificate-manager/): Private CA and certificate management service.
  * [CloudTrail](https://aws.amazon.com/cloudtrail/): Record and log API call on AWS.
  * [Config](https://aws.amazon.com/config/): Configuration and resources relationship monitoring.
  * [Elastic Disaster Recovery](https://aws.amazon.com/disaster-recovery/): Application recovery service.
  * [Detective](https://aws.amazon.com/detective/): Analyze and visualize security data and help security investigations.
  * [Firewall Manager](https://aws.amazon.com/firewall-manager/): Firewall management service.
  * [GuardDuty](https://aws.amazon.com/guardduty/): IDS service
  * [CloudHSM](https://aws.amazon.com/cloudhsm/): HSM service.
  * [Inspector](https://aws.amazon.com/inspector/): Vulnerability discover and assessment service.
  * [KMS](https://aws.amazon.com/kms/): KMS service
  * [Macie](https://aws.amazon.com/macie/): Fully managed data security and data privacy service for S3.
  * [Network Firewall](https://aws.amazon.com/network-firewall/): Network firewall service.
  * [Secret Manager](https://aws.amazon.com/secrets-manager/): Credential management service.
  * [Security Hub](https://aws.amazon.com/security-hub/): Integration service for other AWS and third-party security service.
  * [Shield](https://aws.amazon.com/shield/): DDoS protection service.
  * [Single Sign-On](https://aws.amazon.com/single-sign-on/): Service of centrally manage access AWS or application.
  * [ThreatMapper](https://github.com/deepfence/ThreatMapper): Identify vulnerabilities in running containers, images, hosts and repositories.
  * [VPC Flowlog](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html): Log of network traffic.
  * [WAF](https://aws.amazon.com/waf/): Web application firewall service.
* Azure:
  * [Application Gateway](https://azure.microsoft.com/en-us/services/application-gateway/): L7 load balancer with optional WAF function.
  * [DDoS Protection](https://azure.microsoft.com/en-us/services/ddos-protection/): DDoS protection service.
  * [Dedicated HSM](https://azure.microsoft.com/en-us/services/azure-dedicated-hsm/): HSM service.
  * [Key Vault](https://azure.microsoft.com/en-us/services/key-vault/): KMS service
  * [Monitor](https://docs.microsoft.com/en-us/azure/azure-monitor/): API log and monitoring related service.
  * [Security Center](https://azure.microsoft.com/en-us/services/security-center/): Integration service for other Azure and third-party security service.
  * [Sentinel](https://azure.microsoft.com/zh-tw/services/azure-sentinel/): SIEM service.
* GCP:
  * [Access Transparency](https://cloud.google.com/access-transparency): Transparency log and control of GCP.
  * [Apigee Sense](https://cloud.google.com/apigee/api-management/apigee-sense): API security monitoring, detection, mitigation.
  * [Armor](https://cloud.google.com/armor): DDoS protection and WAF service
  * [Asset Inventory](https://cloud.google.com/asset-inventory): Asset monitoring service.
  * [Assured workloads](https://cloud.google.com/assured-workloads/): Secure and compliant workloads.
  * [Audit Logs](https://cloud.google.com/audit-logs): API logs.
  * [Binanry Authorization](https://cloud.google.com/binary-authorization/): Binary authorization service for containers and serverless.
  * [Cloud HSM](https://cloud.google.com/hsm): HSM service.
  * [Cloud IDS](https://cloud.google.com/intrusion-detection-system/): IDS service.
  * [Confidential VM](https://cloud.google.com/compute/confidential-vm/): Encrypt data in use with VM.
  * [Context-aware Access](https://cloud.google.com/context-aware-access): Enable zero trust access to applications and infrastructure.
  * [DLP](https://cloud.google.com/dlp): DLP service:
  * [EKM](https://cloud.google.com/ekm): External key management service
  * [Identity-Aware Proxy](https://cloud.google.com/iap): Identity-Aware Proxy for protect the internal service.
  * [KMS](https://cloud.google.com/kms): KMS service
  * [Policy Intelligence](https://cloud.google.com/policy-intelligence): Detect the policy related risk.
  * [Security Command Center](https://cloud.google.com/security-command-center): Integration service for other GCP security service.
  * [Security Scanner](https://cloud.google.com/security-scanner): Application security scanner for GAE, GCE, GKE.
  * [Shielded VM](https://cloud.google.com/compute/shielded-vm/): VM with secure boot and vTPM.
  * [Event Threat Detection](https://cloud.google.com/event-threat-detection): Threat dection service.
  * [VPC Service Controls](https://cloud.google.com/vpc-service-controls): GCP service security perimeter control.

#### Incident Response

* [AWS Incident Response Playbooks by AWS Samples](https://github.com/aws-samples/aws-incident-response-playbooks)
* [AWS Security Hub Automated Response and Remediation](https://github.com/awslabs/aws-security-hub-automated-response-and-remediation)
* [Dispatch by Netflix](https://github.com/Netflix/dispatch)
* [PagerDuty Automated Remediation Docs](https://github.com/PagerDuty/automated-remediation-docs)
* [PagerDuty Business Response Docs](https://github.com/PagerDuty/business-response-docs)
* [PagerDuty DevSecOps Docs](https://github.com/PagerDuty/devsecops-docs)
* [PagerDuty Full Case Ownership Docs](https://github.com/PagerDuty/full-case-ownership-docs)
* [PagerDuty Full Service Ownership Docs](https://github.com/PagerDuty/full-service-ownership-docs)
* [PagerDuty Going OnCall Docs](https://github.com/PagerDuty/goingoncall-docs)
* [PagerDuty Incident Response Docs](https://github.com/PagerDuty/incident-response-docs)
* [PagerDuty Operational Review Docs](https://github.com/PagerDuty/operational-review-docs)
* [PagerDuty PostMortem Docs](https://github.com/PagerDuty/postmortem-docs)
* [PagerDuty Retrospectives Docs](https://github.com/PagerDuty/retrospectives-docs)
* [PagerDuty Stakeholder Communication Docs](https://github.com/PagerDuty/stakeholder-comms-docs)
* [Velociraptor](https://github.com/Velocidex/velociraptor)

#### Examples

* Ex. Automated Security Assessment
  * [AWS Config Rules Repository](https://github.com/awslabs/aws-config-rules)
  * [AWS Inspector Agent Autodeploy](https://github.com/awslabs/amazon-inspector-agent-autodeploy)
  * [AWS Inspector Auto Remediation](https://github.com/awslabs/amazon-inspector-auto-remediate)
  * [AWS Inspector Lambda Finding Processor](https://github.com/awslabs/amazon-inspector-finding-forwarder)
* Ex. Identity and Access Management
  * [Amazon Cognito Streams connector for Amazon Redshift](https://github.com/awslabs/amazon-cognito-streams-sample)
* Ex. Logging
  * [AWS Centralized Logging](https://github.com/awslabs/aws-centralized-logging)
  * [AWS Config Snapshots to ElasticSearch](https://github.com/awslabs/aws-config-to-elasticsearch)
  * [AWS CloudWatch Events Monitor Security Groups](https://github.com/awslabs/cwe-monitor-secgrp)
* Ex. Web Application Firewall
  * [AWS WAF Sample](https://github.com/awslabs/aws-waf-sample)
  * [AWS WAF Security Automations](https://github.com/awslabs/aws-waf-security-automations)

#### Others

* [Git Secrets by AWS Labs](https://github.com/awslabs/git-secrets)
* [411 by Etsy](https://github.com/etsy/411)
* [ElastAlert by Yelp](https://github.com/Yelp/elastalert)
* [StreamAlert by Airbnb](https://github.com/airbnb/streamalert)
* [Knox](https://github.com/pinterest/knox)
* [Spring Cloud Security](https://github.com/dschadow/CloudSecurity)
* [ThreatModel for Amazon S3](https://github.com/trustoncloud/threatmodel-for-aws-s3)

### Reading

* AWS:
  * [Overiew of AWS Security](https://aws.amazon.com/security/)
  * [AWS-IAM-Privilege-Escalation by RhinoSecurityLabs](https://github.com/RhinoSecurityLabs/AWS-IAM-Privilege-Escalation): A centralized source of all AWS IAM privilege escalation methods.
  * [MITRE ATT\&CK Matrices of AWS](https://attack.mitre.org/matrices/enterprise/cloud/aws/)
  * [AWS security workshops](https://github.com/aws-samples/aws-security-workshops)
  * [ThreatModel for Amazon S3](https://github.com/trustoncloud/threatmodel-for-aws-s3): Library of all the attack scenarios on Amazon S3, and how to mitigate them following a risk-based approach
* Azure:
  * [Overiew of Azure Security](https://azure.microsoft.com/en-us/overview/security/)
  * [Azure security fundamentals](https://docs.microsoft.com/en-us/azure/security/fundamentals/)
  * [MicroBurst by NetSPI](https://github.com/NetSPI/MicroBurst): A collection of scripts for assessing Microsoft Azure security
  * [MITRE ATT\&CK Matrices of Azure](https://attack.mitre.org/matrices/enterprise/cloud/azure/)
  * [Azure security center workflow automation](https://github.com/Azure/Azure-Security-Center/tree/master/Workflow%20automation)
* GCP:
  * [Overiew of Azure Security](https://azure.microsoft.com/en-us/overview/security/)
  * [Azure security fundamentals](https://docs.microsoft.com/en-us/azure/security/fundamentals/)
  * [MicroBurst by NetSPI](https://github.com/NetSPI/MicroBurst): A collection of scripts for assessing Microsoft Azure security
  * [MITRE ATT\&CK Matrices of Azure](https://attack.mitre.org/matrices/enterprise/cloud/azure/)
  * [Azure security center workflow automation](https://github.com/Azure/Azure-Security-Center/tree/master/Workflow%20automation)
* Others:
  * [Cloud recent news | Dark Reading](https://www.darkreading.com/cloud)

### Podcasts

* [Azure DevOps Podcast](http://azuredevopspodcast.clear-measure.com/)
* [Security Now](https://twit.tv/shows/security-now)

### Testing & Learning

* Labs:
  * [AWS Workshops](https://workshops.aws/categories/Security)
    * [AWS Identity: Using Amazon Cognito for serverless consumer apps](https://serverless-idm.awssecworkshops.com/)
    * [AWS Network Firewall Workshop](https://networkfirewall.workshop.aws/)
    * [AWS Networking Workshop](https://networking.workshop.aws/)
    * [Access Delegation](https://identity-round-robin.awssecworkshops.com/delegation/)
    * [Amazon VPC Endpoint Workshop](https://www.vpcendpointworkshop.com/)
    * [Build a Vulnerability Management Program Using AWS for AWS](https://vul-mgmt-program.awssecworkshops.com/)
    * [Data Discovery and Classification with Amazon Macie](https://data-discovery-and-classification.workshop.aws/)
    * [Data Protection](https://data-protection.awssecworkshops.com/)
    * [DevSecOps - Integrating security into your pipeline](https://devops.awssecworkshops.com/)
    * [Disaster Recovery on AWS](https://disaster-recovery.workshop.aws/)
    * [Finding and addressing Network Misconfigurations on AWS](https://validating-network-reachability.awssecworkshops.com/)
    * [Firewall Manager Service - WAF Policy](https://introduction-firewall-manager.workshop.aws/)
    * [Getting Hands on with Amazon GuardDuty](https://hands-on-guardduty.awssecworkshops.com/)
    * [Hands on Network Firewall Workshop](https://hands-on-network-firewall.workshop.aws/)
    * [Implementing DDoS Resiliency](https://ddos-protection-best-practices.workshop.aws/)
    * [Infrastructure Identity on AWS](https://idm-infrastructure.awssecworkshops.com/)
    * [Integrating security into your container pipeline](https://container-devsecops.awssecworkshops.com/)
    * [Integration, Prioritization, and Response with AWS Security Hub](https://security-hub-workshop.awssecworkshops.com/)
    * [Introduction to WAF](https://introduction-to-waf.workshop.aws/)
    * [Permission boundaries: how to delegate permissions on AWS](https://identity-round-robin.awssecworkshops.com/permission-boundaries-advanced/)
    * [Protecting workloads on AWS from the instance to the edge](https://protecting-workloads.awssecworkshops.com/workshop/)
    * [Scaling threat detection and response on AWS](https://scaling-threat-detection.awssecworkshops.com/)
    * [Serverless Identity](https://identity-round-robin.awssecworkshops.com/serverless/)
  * [PagerDuty Training Lab](https://sudo.pagerduty.com/)
    * [PagerDuty Training GitHub](https://github.com/PagerDuty/security-training)
    * [PagerDuty Training for Engineers](https://sudo.pagerduty.com/for\_engineers/)
    * [PagerDuty Training for Everyone: Part 1](https://sudo.pagerduty.com/for\_everyone/)
    * [PagerDuty Training for Everyone: Part 2](https://sudo.pagerduty.com/for\_everyone\_part\_ii/)
* Courses:
  * [Oracle Cloud Security Administrator](https://learn.oracle.com/ols/learning-path/become-a-cloud-security-administrator/35644/38707)
  * Learning Paths (by [A Cloud Guru](https://www.pluralsight.com/cloud-guru)):
    * [AWS Security Path](https://learn.acloud.guru/learning-path/aws-security)
    * [Azure Security Path](https://learn.acloud.guru/learning-path/azure-security)
    * [GCP Security Path](https://learn.acloud.guru/learning-path/gcp-security)
* Others:
  * [ccat](https://github.com/RhinoSecurityLabs/ccat): Cloud Container Attack Tool.
  * [CloudBrute](https://github.com/0xsha/CloudBrute): A multiple cloud enumerator.
  * [cloudgoat](https://github.com/RhinoSecurityLabs/cloudgoat): "Vulnerable by Design" AWS deployment tool.
  * [Leonidas](https://github.com/FSecureLABS/leonidas): A framework for executing attacker actions in the cloud.
  * [Sadcloud](https://github.com/nccgroup/sadcloud): Tool for spinning up insecure AWS infrastructure with Terraform.
  * [TerraGoat](https://github.com/bridgecrewio/terragoat): Bridgecrew's "Vulnerable by Design" Terraform repository.
  * [WrongSecrets](https://github.com/commjoen/wrongsecrets): A vulnerable app which demonstrates how to not use secrets. With AWS/Azure/GCP support.
  * [ServerlessGoat by OWASP](https://github.com/OWASP/Serverless-Goat)

### Others

* [Cloud Security Research by RhinoSecurityLabs](https://github.com/RhinoSecurityLabs/Cloud-Security-Research)
* [CSA cloud security guidance v4](https://cloudsecurityalliance.org/artifacts/security-guidance-v4/)
* [Appsecco provides training](https://github.com/appsecco/breaking-and-pwning-apps-and-servers-aws-azure-training)
* [Cloud Risk Encyclopedia by Orca Security](https://orca.security/resources/cloud-risk-encyclopedia/): 900+ documented cloud security risks, with ability to filter by cloud vendor, compliance framework, risk category, and criticality.
* [Mapping of On-Premises Security Controls vs. Major Cloud Providers Services](https://www.eventid.net/docs/onprem\_to\_cloud.asp)
* AWS [Bucket search by grayhatwarfare](https://buckets.grayhatwarfare.com/)

## Sources

\[1]: [What Is Cloud-Native Security? - Palo Alto Networks](https://www.paloaltonetworks.com/cyberpedia/what-is-cloud-native-security)

\[2]: [OWASP Cloud-Native Application Security Top 10 | OWASP Foundation](https://owasp.org/www-project-cloud-native-application-security-top-10/)

\[3]: [4ndersonLin/awesome-cloud-security: 🛡️ Awesome Cloud Security Resources ⚔️ (github.com)](https://github.com/4ndersonLin/awesome-cloud-security#standards)

\[4]: [Funkmyster/awesome-cloud-security: Curated list of awesome cloud security blogs, podcasts, standards, projects, and examples. (github.com)](https://github.com/Funkmyster/awesome-cloud-security#public-cloud-governance)

\[5]: [teamssix/awesome-cloud-security: awesome cloud security 收集一些国内外不错的云安全资源，该项目主要面向国内的安全人员 (github.com)](https://github.com/teamssix/awesome-cloud-security)
