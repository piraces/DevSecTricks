---
description: Ensuring the dependencies of your codebase are secure
---

# Dependency Management

From the [Static Analysis section](static-analysis.md), these tools covers "Dependency management":

* **GitHub:**
  * Dependabot
  * GitHub Advanced Security (for orgs, enterprises or private repos)
* **Snyk:**
  * Snyk Open Source (SCA)
  * Snyk Container
* **Trivy**

## Other Tools / Solutions / Products

### Generic

* OWASP [Dependency-Track](https://github.com/DependencyTrack/dependency-track) ([web](https://dependencytrack.org/)): an intelligent Component Analysis platform that allows organizations to identify and reduce risk in the software supply chain.
* OWASP [Dependency-Check](https://github.com/jeremylong/DependencyCheck) ([web](https://owasp.org/www-project-dependency-check/)): a software composition analysis utility that detects publicly disclosed vulnerabilities in application dependencies.
* Mend [Renovate](https://github.com/renovatebot/renovate) ([web](https://www.mend.io/renovate/)): Universal dependency update tool that fits into your workflows.
* [Confused](https://github.com/visma-prodsec/confused): a tool to check for dependency confusion vulnerabilities in multiple package management systems.

### npm/js ecosystems

* [npm audit](https://docs.npmjs.com/cli/audit): vulnerable package auditing for packages built into the npm CLI.
* [Bundlephobia](https://bundlephobia.com/): find the cost of adding a npm package to your bundle.
* [is website vulnerable](https://github.com/lirantal/is-website-vulnerable): finds publicly known security vulnerabilities in a website's frontend JavaScript libraries.
* [retire.js](https://github.com/RetireJS/retire.js) ([web](https://retirejs.github.io/retire.js/)): scanner detecting the use of JavaScript libraries with known vulnerabilities. Can also generate an SBOM of the libraries it finds.

### Python ecosystem

* [pyupio safety](https://github.com/pyupio/safety): safety checks Python dependencies for known security vulnerabilities and suggests the proper remediations for vulnerabilities detected.

### Ruby ecosystem

* [bundler-audit](https://github.com/rubysec/bundler-audit): patch-level verification for Bundler.

### dotnet ecosystem

* [ConfusedDotnet](https://github.com/visma-prodsec/ConfusedDotnet): a tool for checking for lingering free namespaces for private package names referenced in dependency configuration for Nuget (nuget) packages.config or the new PackageReference style.
