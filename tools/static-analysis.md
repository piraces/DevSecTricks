---
description: Perform static analysis on your code with these awesome tools
---

# Static Analysis

## About

Static code analysis addresses weakness in source code, vulnerabilities and others by using a tool (or set of tools) which performs an analysis of a set of source code against a set of coding rules (or advisories, known vulnerabilities...).

## Popular products and solutions

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

## Other Tools / Solutions / Products

### Generic

* [osquery](https://github.com/osquery/osquery) ([web](https://osquery.io/)): SQL powered operating system instrumentation, monitoring, and analytics.
* [DefectDojo ](https://github.com/DefectDojo/django-DefectDojo)([web](https://www.defectdojo.com/)): a DevSecOps and vulnerability management tool.
* [StreamAlert](https://github.com/airbnb/streamalert) ([web](https://streamalert.io/)): a serverless, real-time data analysis framework which empowers you to ingest, analyze, and alert on data from any environment, using data sources and alerting logic you define.
* [graudit](https://github.com/wireghoul/graudit): grep rough audit - source code auditing tool.
* [Sobelow](https://github.com/nccgroup/sobelow): security-focused static analysis for the Phoenix Framework.
* [gau (getallurls)](https://github.com/lc/gau): fetch known URLs from AlienVault's Open Threat Exchange, the Wayback Machine, and Common Crawl.
* Google [OSS-Fuzz](https://github.com/google/oss-fuzz) ([web](https://google.github.io/oss-fuzz)): continuous fuzzing for open source software.
* Greenbone [OpenVAS](https://www.openvas.org/): a full-featured vulnerability scanner.
  * [Community edition](https://github.com/greenbone/openvas-scanner) ([web](https://greenbone.github.io/docs/latest/))
* [Security-bugtracker](https://github.com/designsecurity/security-bugtracker): a tool to run security tools and track security bugs easily.
* [PMD - source code analyzer](https://github.com/pmd/pmd) ([web](https://pmd.github.io/)): an extensible multilanguage static code analyzer.
* [Semgrep](https://github.com/returntocorp/semgrep) ([web](https://semgrep.dev/)): lightweight static analysis for many languages. Find bug variants with patterns that look like source code.

#### Web

* [OWASP ZAP (Zed Attack Proxy)](https://www.zaproxy.org/): The world’s most widely used web app scanner. Free and open source.
* [Dalfox ](https://github.com/hahwul/dalfox)([web](https://dalfox.hahwul.com/)): a powerful open-source XSS scanner and utility focused on automation.
* [bunkerweb](https://github.com/bunkerity/bunkerweb) ([web](https://docs.bunkerweb.io/)): a web server based on the notorious NGINX and focused on security.
* [CSP Evaluator](https://csp-evaluator.withgoogle.com/): CSP Evaluator allows developers and security experts to check if a Content Security Policy (CSP) serves as a strong mitigation against cross-site scripting attacks.
  * [Chrome extension](https://chrome.google.com/webstore/detail/csp-evaluator/fjohamlofnakbnbfjkohkbdigoodcejf)
* [Vulmap](https://github.com/zhzyker/vulmap/blob/main/readme.us-en.md) (English/Chinese): Web vulnerability scanning and verification tools.
* TruffleSecurity [XSSHunter](https://github.com/trufflesecurity/xsshunter) ([web](https://xsshunter.trufflesecurity.com/https://xsshunter.trufflesecurity.com/)): the fastest way to set up XSS Hunter to test and find blind cross-site scripting vulnerabilities.
* [Arachni](https://github.com/Arachni/arachni) ([web](https://www.arachni-scanner.com/)) (⚠️): web application security scanner framework.
* [ecsypno SCNR](https://ecsypno.com/): web application security scanner framework (Arachni successor).

#### API

* [Astra](https://github.com/flipkart-incubator/Astra): automated Security Testing For REST API's.

#### C/C++

* [Flawfinder](https://github.com/david-a-wheeler/flawfinder) ([web](http://dwheeler.com/flawfinder)): a simple program that scans C/C++ source code and reports potential security flaws.

#### JVM based

* [OWASP Find Security Bugs](https://github.com/find-sec-bugs/find-sec-bugs) ([web](https://find-sec-bugs.github.io/)): the SpotBugs plugin for security audits of Java web applications and Android applications. (Also work with Kotlin, Groovy and Scala projects).
* [SpotBugs ](https://github.com/spotbugs/spotbugs)([web](https://spotbugs.github.io/)): SpotBugs is FindBugs' successor. A tool for static analysis to look for bugs in Java code.

#### JavaScript

* [JSHint](https://github.com/jshint/jshint) ([web](http://jshint.com/)): a tool that helps to detect errors and potential problems in your JavaScript code.

#### Node.js

* [nodejsscan](https://github.com/ajinabraham/nodejsscan): a static security code scanner for Node.js applications.
* [Helmet](https://github.com/helmetjs/helmet) ([web](https://helmetjs.github.io/)): help secure Express apps with various HTTP headers.

#### Golang

* [gosec](https://github.com/securego/gosec) ([web](https://securego.io/)): Golang security checker.
* [Staticcheck](https://github.com/dominikh/go-tools) ([web](https://staticcheck.io/)): a state of the art linter for the Go programming language. Using static analysis, it finds bugs and performance issues, offers simplifications, and enforces style rules.
* [GoKart](https://github.com/praetorian-inc/gokart): a static analysis tool for securing Go code.

#### Python

* Facebook (Meta) [Pyre](https://github.com/facebook/pyre-check) (aka pyre-check) ([web](https://pyre-check.org/)): a performant type checker for Python.
* [Bandit](https://github.com/PyCQA/bandit) ([web](https://bandit.readthedocs.io/)): a tool designed to find common security issues in Python code.

#### Ruby

* [Brakeman](https://github.com/presidentbeef/brakeman) ([web](https://brakemanscanner.org/)): a static analysis security vulnerability scanner for Ruby on Rails applications.

#### PHP

* [progpilot](https://github.com/designsecurity/progpilot): a static application security testing (SAST) for PHP.
* [iniscan](https://github.com/psecio/iniscan) (⚠️): php.ini scanner for best security practices.

#### Kubernetes (k8s)

* Aqua [kube-bench](https://github.com/aquasecurity/kube-bench): kube-bench is a tool that checks whether Kubernetes is deployed securely by running the checks documented in the CIS Kubernetes Benchmark.
* Armo [Kubescape](https://github.com/kubescape/kubescape): an open-source Kubernetes security platform for your IDE, CI/CD pipelines, and clusters.
* [Kube-score](https://github.com/zegl/kube-score) ([web](https://kube-score.com/)): Kubernetes object analysis with recommendations for improved reliability and security.
* Cilium [Tetragon](https://github.com/cilium/tetragon): eBPF-based Security Observability and Runtime Enforcement.
* Cilium [Hubble](https://github.com/cilium/hubble): Network, Service & Security Observability for Kubernetes using eBPF.
* [Falco](https://github.com/falcosecurity/falco) ([web](https://falco.org/)): Cloud Native Runtime Security.
* [Datree](https://github.com/datreeio/datree) ([web](https://datree.io/)): provides an E2E policy enforcement solution to run automatic checks for rule violations.

#### Windows

* [LogonTracer](https://github.com/JPCERTCC/LogonTracer): investigate malicious Windows logon by visualizing and analyzing Windows event log.
* [Hardentools](https://github.com/securitywithoutborders/hardentools): reduces the attack surface on Microsoft Windows computers by disabling low-hanging fruit risky features.

#### Web3 (Ethereum | EVM)

* Consensys [MythX](https://mythx.io/): Smart contract security service for Ethereum.
* Consensys [Mythril](https://github.com/ConsenSys/mythril) ([web](https://mythx.io/)): Security analysis tool for EVM bytecode.
* [Echidna](https://github.com/crytic/echidna): a Fast Smart Contract Fuzzer.

#### WAF

* [Coreruleset ](https://github.com/coreruleset/coreruleset)([web](https://coreruleset.org/)): OWASP ModSecurity Core Rule Set.

#### Security policy

* [content](https://github.com/ComplianceAsCode/content) ([web](https://www.open-scap.org/security-policies/scap-security-guide)): security automation content in SCAP, Bash, Ansible, and other formats.

#### Cryptography

* Google [Tink Cryptographic Library](https://developers.google.com/tink/): an open-source cryptography library written by cryptographers and security engineers at Google.
* [Smallstep CLI](https://github.com/smallstep/cli) ([web](https://smallstep.com/cli)): zero trust swiss army knife for working with X509, OAuth, JWT, OATH OTP, etc.

#### SSL/TLS

* Qualys [SSL Labs (Server test)](https://www.ssllabs.com/ssltest/): free online service performs a deep analysis of the configuration of any SSL web server on the public Internet.
  * [Other tests](https://www.ssllabs.com/)
* [testssl.sh](https://testssl.sh/): a free command line tool which checks a server's service on any port for the support of TLS/SSL ciphers, protocols as well as recent cryptographic flaws and more.
* [sslscan](https://github.com/rbsec/sslscan): tests SSL/TLS enabled services to discover supported cipher suites.
* [sslyze](https://github.com/nabla-c0d3/sslyze): fast and powerful SSL/TLS scanning library.

#### OOB (Out-of-band)

* [interact.sh](https://github.com/projectdiscovery/interactsh) ([web](https://app.interactsh.com/)): an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions.

### Rule / Analysis engines

* GitHub [CodeQL](https://github.com/github/codeql) ([web](https://codeql.github.com/)): discover vulnerabilities across a codebase with CodeQL, our industry-leading semantic code analysis engine.
  * [CLI](https://codeql.github.com/docs/codeql-cli/)
  * [Visual Studio Code extension](https://codeql.github.com/docs/codeql-for-visual-studio-code/)
  * [Documentation](https://codeql.github.com/docs/)
* [YARA](https://github.com/virustotal/yara) ([web](https://virustotal.github.io/yara/)): YARA is a tool aimed at (but not limited to) helping malware researchers to identify and classify malware samples.

### Multi-purpose

* [ggshield ](https://github.com/GitGuardian/ggshield)([GitGuardian](https://www.gitguardian.com/)): find and fix hardcoded secrets and infrastructure-as-code misconfigurations.

### Containers

* [Dockle ](https://github.com/goodwithtech/dockle)([web](https://containers.goodwith.tech/)): container Image Linter for Security, Helping build the Best-Practice Docker Image, Easy to start.

### Cloud

#### Generic

* [Aqua CloudSploit](https://github.com/aquasecurity/cloudsploit) ([web](https://www.aquasec.com/products/cspm/)): Cloud Security Scans.
* Deepfence [ThreatMapper](https://github.com/deepfence/ThreatMapper): Open source cloud native security observability platform. Linux, K8s, AWS Fargate and more.
* [CloudQuery](https://github.com/cloudquery/cloudquery) ([web](https://www.cloudquery.io/)): an open source high performance data integration platform built for developers.
* [Steampipe](https://github.com/turbot/steampipe) ([web](https://steampipe.io/)): use SQL to instantly query your cloud services (AWS, Azure, GCP and more). Open source CLI. No DB required.
* NCC Group [ScoutSuite](https://github.com/nccgroup/ScoutSuite): Multi-Cloud Security Auditing Tool.
* [Prowler](https://github.com/prowler-cloud/prowler) ([web](https://www.prowler.pro/)): an Open Source Security tool for AWS, Azure and GCP to perform Cloud Security best practices assessments, audits, incident response, compliance, continuous monitoring, hardening and forensics readiness.

#### AWS (Amazon Web Services)

* [Cloudsplaining](https://github.com/salesforce/cloudsplaining) ([web](https://cloudsplaining.readthedocs.io/)): an AWS IAM Security Assessment tool that identifies violations of least privilege and generates a risk-prioritized report.
* Cisco Duo [CloudMapper](https://github.com/duo-labs/cloudmapper): helps you analyze your Amazon Web Services (AWS) environments.
