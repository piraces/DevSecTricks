---
description: Ensuring you don't leak secrets and bad actors use them
---

# Secrets Scanning

## About

Source control is not a secure place to store secrets such as credentials, API keys or tokens, even if the repo is private. Secrets scanning tools can scan and monitor git repositories and pull-requests for secrets, and can be used to prevent secrets from being committed, or to find and remove secrets that have already been committed to source control. \[1]

## Tools / Solutions / Products

* TruffleSecurity [Trufflehog](https://github.com/trufflesecurity/trufflehog) ([web](https://trufflesecurity.com/trufflehog/)): find and verify credentials.
  * [Chrome extension](https://chrome.google.com/webstore/detail/trufflehog/bafhdnhjnlcdbjcdcnafhdcphhnfnhjc)
* [gitleaks](https://github.com/gitleaks/gitleaks) ([web](https://gitleaks.io/)): a fast, light-weight, portable, and open-source secret scanner for git repositories, files, and directories.
* Deepfence [SecretScanner](https://github.com/deepfence/SecretScanner): find secrets and passwords in container images and file systems.
* TruffleSecurity [Driftwood](https://github.com/trufflesecurity/driftwood): a tool that can enable you to lookup whether a private key is used for things like TLS or as a GitHub SSH key for a user.
* [stacs](https://github.com/stacscan/stacs): a YARA powered static credential scanner which suports binary file formats, analysis of nested archives, composable rulesets and ignore lists, and SARIF reporting.
* [git-hound](https://github.com/tillson/git-hound): Reconnaissance tool for GitHub code search. Scans for exposed API keys across all of GitHub, not just known repos.
* AWS Labs [git-secrets](https://github.com/awslabs/git-secrets): Prevents you from committing secrets and credentials into git repositories
* GoDaddy [Tartufo](https://github.com/godaddy/tartufo) ([web](https://tartufo.readthedocs.io/en/stable/)): searches through git repositories for high entropy strings and secrets, digging deep into commit history
* Yelp [detect-secrets](https://github.com/Yelp/detect-secrets): An enterprise friendly way of detecting and preventing secrets in code.
* Auth0 [Repo-supervisor](https://github.com/auth0/repo-supervisor): a tool that helps you to detect secrets and passwords in your code.
* [GitGuardian](https://www.gitguardian.com/v): secure your software development lifecycle with enterprise-grade secrets detection. Eliminate blind spots with our automated, battle-tested detection engine.
* [Nightfall](https://www.nightfall.ai/): discover, classify, and remove secrets and keys to protect your organization and maintain compliance.
* [Spectral](https://spectralops.io/): monitor, classify, and protect your code, assets, and infrastructure for exposed API keys, tokens, credentials, and high-risk security misconfigurations in a simple way, without noise.

## Sources

* \[1]: [https://github.com/TaptuIT/awesome-devsecops#secrets-scanning](https://github.com/TaptuIT/awesome-devsecops#secrets-scanning)
