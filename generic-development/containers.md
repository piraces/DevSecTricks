---
description: Containers are great... but you must secure them!
---

# Containers

## About

Containers have revolutionized the way applications are developed, deployed, and managed. They provide a lightweight, standalone, executable package that includes everything needed to run a piece of software, including the code, a runtime, system tools, system libraries, and settings. Containers are portable across different platforms and they offer a consistent environment, which is a major advantage for developers and system administrators.

**Nevertheless, a container is not "secure by itself"... a container include code binaries, configuration files, dependencies, the host environment, network configurations...** **Each of these can cause an attack surface \[1].**

Container security involves defining and adhering to build, deployment, and runtime practices that protect a Linux container—from the applications they support to the infrastructure they rely on \[2].

## Best practices

Here are some Container security best practices \[1]\[2]\[3]\[4]\[5]:

* [ ] Do NOT run as root (and don't use 'sudo', 'doas' or others...)
* [ ] Use trusted base images (as minimal as possible)
* [ ] Sign your container images
* [ ] Update your environment & base images
* [ ] Close unused ports
* [ ] Do NOT use hardcoded credentials
* [ ] Do NOT store secrets in environment variables
* [ ] Be cautious when using the 'latest' tag for the base image... (it may introduce a new vulnerability)
* [ ] Avoid curl bashing (pulling scripts from internet and piping into the shell)
* [ ] Do NOT upgrade your system packages (it amplifies the unpredictability of your dependencies tree, pin your software dependencies)
* [ ] Do NOT use ADD if possible (use COPY). If you really have to use COPY use trusted sources over secure connections
* [ ] Scan your container environments regularly (checkout the tools below)
* [ ] Secure your code and its dependencies (checkout the [Static Analysis](../tools/static-analysis.md) section)
* [ ] Manage all layers in between the base image and your code
* [ ] Use access management (following the [principle of least privilege](https://www.crowdstrike.com/cybersecurity-101/principle-of-least-privilege-polp/))
* [ ] Follow the [OWASP Docker Top 10 project](https://owasp.org/www-project-docker-top-10/https://owasp.org/www-project-docker-top-10/) points ([overview](https://github.com/OWASP/Docker-Security/blob/main/D00%20-%20Overview.md)):
  * [ ] [D01 - Secure User Mapping](https://github.com/OWASP/Docker-Security/blob/main/D01%20-%20Secure%20User%20Mapping.md)
  * [ ] [D02 - Patch Management Strategy](https://github.com/OWASP/Docker-Security/blob/main/D02%20-%20Patch%20Management%20Strategy.md)
  * [ ] [D03 - Network Segmentation and Firewalling](https://github.com/OWASP/Docker-Security/blob/main/D03%20-%20Network%20Segmentation%20and%20Firewalling.md)
  * [ ] [D04 - Secure Defaults and Hardening](https://github.com/OWASP/Docker-Security/blob/main/D04%20-%20Secure%20Defaults%20and%20Hardening.md)
  * [ ] [D05 - Mantain Security Contexts](https://github.com/OWASP/Docker-Security/blob/main/D05%20-%20Maintain%20Security%20Contexts.md)
  * [ ] [D06 - Protect Secrets](https://github.com/OWASP/Docker-Security/blob/main/D06%20-%20Protect%20Secrets.md)
  * [ ] [D07 - Resource Protection](https://github.com/OWASP/Docker-Security/blob/main/D07%20-%20Resource%20Protection.md)
  * [ ] [D08 - Container Image Integrity and Origin](https://github.com/OWASP/Docker-Security/blob/main/D08%20-%20Container%20Image%20Integrity%20and%20Origin.md)
  * [ ] [D09 - Follow Immutable Paradigm](https://github.com/OWASP/Docker-Security/blob/main/D09%20-%20Follow%20Immutable%20Paradigm.md)
  * [ ] [D10 - Logging](https://github.com/OWASP/Docker-Security/blob/main/D10%20-%20Logging.md)
* [ ] Checkout the [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker\_Security\_Cheat\_Sheet.html)

## Cloud / Registries

Some cloud offerings, related to container image registries and registries services offers vulnerability scanning and assessment:

* [AWS Elastic Container Registry (ECR)](https://aws.amazon.com/ecr/): AWS ECR offers scanning and managing software vulnerabilities to meet security requirements.
* [Azure Container Registry (ACR)](https://azure.microsoft.com/en-us/products/container-registry/): Azure offers [Microsoft Defender for Containers](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-containers-introduction), which will scan images for vulnerabilities.
* [Google Cloud (GCP) Artifact Registry](https://cloud.google.com/artifact-registry): it offers [Container Analysis](https://cloud.google.com/container-analysis/docs) integration to provide vulnerability scanning and metadata storage for containers on Google Cloud.
* [Docker Hub](https://hub.docker.com/): supports an automatic [vulnerability scanning](https://docs.docker.com/docker-hub/vulnerability-scanning/) feature, which when enabled, automatically scans images when you push them to a Docker Hub repository. Requires a [Docker subscription](https://docs.docker.com/subscription/).

## Tools

Some are from the [Static Analysis section](../tools/static-analysis.md), these tools covers "Containers":

* [Snyk Container](https://snyk.io/product/container-vulnerability-management/): Container and Kubernetes security that helps developers and DevOps find and fix vulnerabilities throughout the SDLC — _before_ workloads hit production.
* [Docker Scout](https://www.docker.com/products/docker-scout/) (included in [Docker Desktop](https://www.docker.com/products/docker-desktop/)): a collection of software supply chain features that appear throughout Docker user interfaces and the command line interface (CLI). These features provide detailed insights into the composition and security of container images.
* [Qualys Container Security (CS)](https://www.qualys.com/apps/container-security/): Qualys Container Security allows you to discover, track and continuously secure containers – from build to runtime. It provides deep visibility across on-premise container environments and managed containers across multiple cloud providers.
* Aqua Security - [Trivy](https://aquasecurity.github.io/trivy):  a comprehensive and versatile security scanner. Trivy has _scanners_ that look for security issues, and _targets_ where it can find those issues. One of these targets is container images.
* Chef [Inspec](https://github.com/inspec/inspec) ([web](https://community.chef.io/tools/chef-inspec)): an open-source testing framework for infrastructure with a human- and machine-readable language for specifying compliance, security and policy requirements.

{% hint style="info" %}
For example you can use Inspec with the [dev-sec/linux-baseline project](https://github.com/dev-sec/linux-baseline) to asses some Linux common issues:

```bash
inspec exec https://github.com/dev-sec/linux-baseline -t docker://<docker_id>
```

Or the dev-sec/docker-baseline project:

```bash
inspec exec https://github.com/dev-sec/cis-docker-benchmark -t docker://<docker_id>
```

\
Checkout the [dev-sec page](https://dev-sec.io/) and [GitHub](https://github.com/dev-sec) for more.
{% endhint %}

* [Docker Bench for Security](https://github.com/docker/docker-bench-security): a script that checks for dozens of common best-practices around deploying Docker containers in production.&#x20;
* Anchore [grype](https://github.com/anchore/grype): vulnerability scanner for container images and filesystems.
* [Haskell Dockerfile Linter](https://github.com/hadolint/hadolint): a smarter Dockerfile linter that helps you build best practice Docker images.
* [Dockle ](https://github.com/goodwithtech/dockle) ([web](https://containers.goodwith.tech/)): container Image Linter for Security, Helping build the Best-Practice Docker Image, Easy to start.
* Quay [Clair](https://github.com/quay/clair) ([web](https://quay.io/)): is an open source project for the static analysis of vulnerabilities in application containers (currently including OCI and docker).
* [Dive](https://github.com/wagoodman/dive) (⚠️): not a scanner itself (but could help), it's a tool for exploring a docker image, layer contents, and discovering ways to shrink the size of your Docker/OCI image.
* [Dagda](https://github.com/eliasgranderubio/dagda/) (⚠️): a tool to perform static analysis of known vulnerabilities, trojans, viruses, malware & other malicious threats in docker images/containers and to monitor the docker daemon and running docker containers for detecting anomalous activities.

## Sources

\[1]: [How to Secure Your Docker Containers: Tips and Challenges - PurpleBox (prplbx.com)](https://www.prplbx.com/resources/blog/docker-part1/)

\[2]: [What is container security? (redhat.com)](https://www.redhat.com/en/topics/security/container-security)

\[3]: [What is container security? | Container Security | Snyk](https://snyk.io/learn/container-security/)

\[4]: [Docker Security Best Practices from the Dockerfile (cloudberry.engineering)](https://cloudberry.engineering/article/dockerfile-security-best-practices/)

\[5]: [Security best practices | Docker Documentation](https://docs.docker.com/develop/security-best-practices/)
