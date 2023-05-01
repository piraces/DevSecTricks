---
description: Perform static analysis on your code with these awesome tools
---

# Static Analysis

### About

Static code analysis addresses weakness in source code, vulnerabilities and others by using a tool (or set of tools) which performs an analysis of a set of source code against a set of coding rules (or advisories, known vulnerabilities...).

### GitHub

GitHub includes several features/products/solutions regarding static analysis of your projects and others related to security.

#### Pricing

* Free plan for OSS projects or public projects (on GitHub.com).
* Other paid plans for teams and enterprise (extra security features under an Advanced Security license).

More info: [https://docs.github.com/en/billing](https://docs.github.com/en/billing)

#### Solutions/Products

* **GitHub Advanced Security:** GitHub makes extra security features available to customers under an Advanced Security license [\[source\]](https://docs.github.com/en/get-started/learning-about-github/about-github-advanced-security):
  * Code scanning for private repository
  * Secret scanning for private repository
  * Dependency review for private repository
* **Code security:** build security into your GitHub workflow with features to keep secrets and vulnerabilities out of your codebase, and to maintain your software supply chain [\[source\]](https://docs.github.com/en/code-security).
* **Supply chain security:** visualize, maintain, and secure the dependencies in your software supply chain [\[source\]](https://docs.github.com/en/code-security/supply-chain-security).
* **Security advisories:** improving collaboration between repository maintainers and security researchers [\[source\]](https://docs.github.com/en/code-security/security-advisories).
* **Dependabot:** monitor vulnerabilities in dependencies used in your project and keep your dependencies up-to-date with Dependabot [\[source\]](https://docs.github.com/en/code-security/dependabot).
* **Code scanning:** using code scanning to identify and fix potential security vulnerabilities and other errors in your code [\[source\]](https://docs.github.com/en/code-security/code-scanning).
* **Secret scanning:** ensuring that tokens, private keys, and other code secrets are not exposed in your repository [\[source\]](https://docs.github.com/en/code-security/secret-scanning).

**Official page:** [https://snyk.io/](https://snyk.io/)

### Snyk

Snyk is a well-known "developer security company" that provides lots of solutions. They define Snyk as a developer security platform.

#### Pricing

* Free **limited** plan
* Other paid plans for teams and enterprise

More info: [https://snyk.io/plans/](https://snyk.io/plans/)

#### Solutions/Products

* **Snyk Code (SAST):** static application security testing (vulnerabilites, advices...).
* **Snyk Open Source (SCA):** open source risk management (vulnerabilities, license complience, reporting and others).
* **Snyk Container:** container and Kubernetes security (vulnerabilities, dependencies and others).
* **Snyk Infrastructure as Code:** secure IaC configurations, rules, custom policies, surfacing of unmanaged and drifted resources.
* **Snyk Cloud:** secure operations in the cloud at every stage of the lifecycle.

**Official page:** [https://snyk.io/](https://snyk.io/)

### Sonar (SonarSource)

Automatic code review, which includes security management. The tool is capable of identifying multiple security hotspots, make security-related rules and others.

#### Pricing

* Free plan for coding ("Free sonar"), analyze  your code in real time with IDE integration
* Other paid plans for developer, teams and enterprise (self-managed and as a service)

More info: [https://www.sonarsource.com/plans-and-pricing/](https://www.sonarsource.com/plans-and-pricing/#sonarqube)

#### Solutions/Products

* **SonarLint:** IDE code analysis integrations.
* **SonarQube:** self-hosted, self-managed code analysis.
* **SonarCloud:** "as a service" cloud-based code analysis.

{% hint style="info" %}
You can deploy a self-hosted sonarqube instance in your own machine with its [official container image](https://hub.docker.com/\_/sonarqube/) in minutes and scan your code
{% endhint %}

**Official page:** [https://www.sonarsource.com/](https://www.sonarsource.com/)

### Trivy

Open source security scanner. Finds vulnerabilities & IaC misconfigurations, SBOM discovery, cloud scannning, k8s security risks and more.

#### Pricing:

* Free

#### Solutions/Products

**AIO tool with multiple scanners:**

* OS packages and software dependencies in use (SBOM)
* Known vulnerabilities (CVEs)
* IaC issues and misconfigurations
* Sensitive information and secrets
* Software licenses

**Targets:**

* Container image
* Filesystem
* Git remotes repository
* Virtual Machine Image
* K8s
* AWS

{% hint style="info" %}
Getting started is easy with this one! [See "Quick Start" documentation](https://aquasecurity.github.io/trivy/) for getting the software and running it.
{% endhint %}

**Official page:** [https://trivy.dev/](https://trivy.dev/)



