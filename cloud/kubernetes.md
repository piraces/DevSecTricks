---
description: Can you dig it?
---

# Kubernetes

## About

**What is Kubernetes Security?**&#x20;

Kubernetes Security is defined as the actions, processes and principles that should be followed to ensure security in your Kubernetes deployments. This includes – but is not limited to – securing containers, configuring workloads correctly, Kubernetes network security, and securing your infrastructure. \[1]

**Why is Kubernetes security important?**&#x20;

Kubernetes security is important due to the variety of threats facing clusters and pods, including:

* Malicious actors
* Malware running inside containers
* Broken container images
* Compromised or rogue users

Without proper controls, a malicious actor who breaches an application could attempt to take control of the host or the entire cluster. \[1]

## Best practices

Extracted from \[1].

Check out also about:

* [Key Kubernetes security issues](https://snyk.io/learn/kubernetes-security/#issues)
* [Kubernetes security challenges and solutions](https://snyk.io/learn/kubernetes-security/#challenges)
* [Securing Kubernetes hosts](https://snyk.io/learn/kubernetes-security/#hosts)
* [Kubernetes Security Observability](https://snyk.io/learn/kubernetes-security/#observability)

### By phase

**Development/Design phase:**

* [ ] Some Kubernetes environments may be more secure than others. Using a multi-cluster architecture or multiple namespaces with proper RBAC controls can help isolate workloads.

**Build phase:**

* [ ] Choose a minimal image from a vetted repository.
* [ ] Use container scanning tools to uncover any vulnerabilities or misconfigurations in containers.

**Deployment Phase:**

* [ ] Images should be scanned and validated prior to deployment.
  * [ ] An admission controller can be used to automate this validation so only vetted container images are deployed.

**Runtime Phase:**

* [ ] The Kubernetes API generates audit logs that should be monitored using a runtime security tool, such as Sysdig.
* [ ] Images and policy files should also be continuously scanned to prevent malware or misconfigurations in a runtime environment.

## Resources

* [aad-pod-identity](https://github.com/Azure/aad-pod-identity/): Assign Azure AD idenitites to pods in Kubernetes, in order to access Azure resources.
* [audit2rbac](https://github.com/liggitt/audit2rbac): Autogenerate RBAC policies based on Kubernetes audit logs.
* [Deepfence ThreatMapper](https://github.com/deepfence/ThreatMapper): Apache v2, powerful runtime vulnerability scanner for kubernetes, virtual machines and serverless.
* [cnspec](https://cnspec.io/): Scan Kubernetes clusters, containers, and manifest files for vulnerabilities and misconfigurations.
* [falco](https://github.com/falcosecurity/falco): Container Native Runtime Security.
* [kdigger](https://github.com/quarkslab/kdigger): Kubernetes focused container assessment and context discovery tool for penetration testing.
* [kiam](https://github.com/uswitch/kiam): Integrate AWS IAM with Kubernetes.
* [kube-bench](https://github.com/aquasecurity/kube-bench): Check whether Kubernetes is deployed according to security best practices.
* [kube-hunter](https://github.com/aquasecurity/kube-hunter): Hunt for security weaknesses in Kubernetes clusters.
* [kube-psp-advisor](https://github.com/sysdiglabs/kube-psp-advisor): Help building an adaptive and fine-grained pod security policy.
* [kube-scan](https://github.com/octarinesec/kube-scan): k8s cluster risk assessment tool.
* [Kubei](https://github.com/Portshift/kubei): Vulnerabilities scanner for Kubernetes clusters.
* [kube2iam](https://github.com/jtblin/kube2iam): Provide different AWS IAM roles for pods running on Kubernetes.
* [kubeaudit](https://github.com/Shopify/kubeaudit): Audit your Kubernetes clusters against common security controls.
* [kubectl-bindrole](https://github.com/Ladicle/kubectl-bindrole): Find Kubernetes roles bound to a specified ServiceAccount, Group or User.
* [kubectl-dig](https://github.com/sysdiglabs/kubectl-dig): Deep Kubernetes visibility from the kubectl.
* [kubectl-kubesec](https://github.com/stefanprodan/kubectl-kubesec): Scan Kubernetes pods, deployments, daemonsets and statefulsets with kubesec.io.
* [kubectl-who-can](https://github.com/aquasecurity/kubectl-who-can): Show who has permissions to \<verb> \<resource> in Kubernetes.
* [OWASP Top Ten for Kubernetes](https://owasp.org/www-project-kubernetes-top-ten/): The Top Ten is a prioritized list of these risks backed by data collected from organizations varying in maturity and complexity.
* [terrascan](https://github.com/accurics/terrascan): Detect compliance and security violations across Infrastructure as Code to mitigate risk before provisioning cloud native infrastructure.
* [kyverno](https://github.com/nirmata/kyverno): Kubernetes Native Policy Management.
* [rakkess](https://github.com/corneliusweig/rakkess): Review access matrix for Kubernetes server resources.
* [rback](https://github.com/team-soteria/rback): RBAC in Kubernetes visualizer.
* [steampipe](https://github.com/turbot/steampipe): Use SQL to query your cloud services (AWS, Azure, GCP and more) running Kubernetes.
* [steampipe-kubernetes](https://github.com/turbot/steampipe-plugin-kubernetes): Use SQL to query your Kubernetes resources.
* [steampipe-kubernetes-compliance](https://github.com/turbot/steampipe-mod-kubernetes-compliance): Kubernetes compliance scanning tool for CIS, NSA & CISA Cybersecurity technical report for Kubernetes hardening.
* [trivy](https://github.com/aquasecurity/trivy): A Simple and Comprehensive Vulnerability Scanner for Containers, Suitable for CI.
* [trivy-operator](https://github.com/aquasecurity/trivy-operator): Kubernetes-native security (Vulnerabilities,IaC MisConfig,Exposed Secrets,RBAC Assessment,Compliance and more) toolkit for kubernetes.
* [kubernetes-rbac-audit](https://github.com/cyberark/kubernetes-rbac-audit): Tool for auditing RBACs in Kubernetes.
* [kubernetes-external-secrets](https://github.com/external-secrets/kubernetes-external-secrets): Tool to get External Secrets from Hashicorp Vault and AWS SSM.
* [vault-secrets-operator](https://github.com/ricoberger/vault-secrets-operator): An operator to create Kubernetes secrets from Vault for a secure GitOps based workflow.

#### Others

* [Kubernetes Security and Disclosure Information](https://kubernetes.io/docs/reference/issues-security/security/)
* [Kubernetes Security](https://kubernetes-security.info/)
* [GKE Security Bulletins](https://cloud.google.com/kubernetes-engine/docs/security-bulletins)
* [CKS Certified Kubernetes Security Specialist resources repo](https://github.com/walidshaari/Certified-Kubernetes-Security-Specialist)
* [Kubernetes Security Checklist and Requirements](https://github.com/Vinum-Security/kubernetes-security-checklist)
* [OWASP Kubernetes Security Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes\_Security\_Cheat\_Sheet.html)
* [Securing Kubernetes Clusters](https://www.cyberark.com/resources/threat-research-blog/securing-kubernetes-clusters-by-eliminating-risky-permissions)
* [Kubernetes Security : 6 Best Practices for 4C Security Model](https://spacelift.io/blog/kubernetes-security)

## Sources

\[1]: [Kubernetes Security: Common Issues and Best Practices | Snyk](https://snyk.io/learn/kubernetes-security/)

\[2]: [ksoclabs/awesome-kubernetes-security: A curated list of awesome Kubernetes security resources (github.com)](https://github.com/ksoclabs/awesome-kubernetes-security)
