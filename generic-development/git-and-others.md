---
description: Is Git Secure by default? Are VCS secure by default? Nope…
---

# Git & other VCS

## About

Nearly every developer uses Git development at some point or another. It’s the default at most universities. It’s open source and widely available for anyone to use. And there’s a lot that Git is great for, especially if you’re working on a small project. \[1]

But, Git has its drawbacks. Especially when it comes to security. \[1]

Native Git is not secure. \[1]

> There are no authentication or verification measures. You can only control Git with server access. And developers can easily rewrite your change history. Since Git is distributed, everyone winds up with a copy of the repository on their laptop. And they can do whatever they want with it. \[1]

## Best practices

Here are some best practices to follow when working with Git \[1]\[2]\[3]:

* [ ] Subscribe to [Git Vulnerabilities](https://www.cvedetails.com/vulnerability-list/vendor\_id-15815/product\_id-33590/Git-scm-GIT.html) and update frequently (there are alternatives, such as [HelixCore](https://www.perforce.com/products/helix-core) to improve security)
* [ ] Never use shared, or system accounts for committing changes
* [ ] Never use a privileged account to develop code and commit
* [ ] Do NOT assume identity-based on username/email
* [ ] Enforce signed commits (all committers must sign):
  * [ ] Do NOT use short keys for PGP/GPG
  * [ ] Do NOT trust a PGP/GPG key by default
  * [ ] Protect your private key. If it gets compromised, revoke the key immediately from key servers
  * [ ] Do NOT generate PGP/GPG keys with infinite validity period
  * [ ] Assign strong passwords to protect private keys
* [ ] Always have at least one copy of your repositories you can trust and treat as secure
* [ ] Protect main/relevant branches (to avoid history modification)
* [ ] Make sure you DO NOT expose insecure directories (ex. '.git/config')
* [ ] For Self-Hosted Git Servers: secure your Git server and grant user permissions properly)
* [ ] Sensitive data: NEVER store credentials as code/config in git
  * [ ] Block sensitive data from being pushed to the repositories by using tools such as [git-secrets](https://github.com/awslabs/git-secrets) or a [git pre-commt hook](https://githooks.com/)
  * [ ] Break builds if sensitive data is present
  * [ ] Audit repositories from secrets with tools such as [Trufflehog](https://github.com/trufflesecurity/truffleHoghttps:/github.com/trufflesecurity/truffleHog)
  * [ ] If Sensitive data reached the repo:
    * [ ] Invalidate tokens and passwords
    * [ ] Remove the info and clear the Git history (checkout [BFG Repo-Cleaner](https://rtyley.github.io/bfg-repo-cleaner/), [git filter-repo](https://github.com/newren/git-filter-repo) or the standard [git filter-branch](https://git-scm.com/docs/git-filter-branch), and also[ this document from GitHub](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository))
    * [ ] Assess the impact of leaked private info
* [ ] Tight your control access
  * [ ] Require two factor if available
  * [ ] Do NOT let users share accounts/passwords
  * [ ] Be sure any laptops/devices with access to source code and remote repository are secured
  * [ ] Immediately revoke access from users who are no longer working in the project
  * [ ] Give contributors only access to what they need to do their work
* [ ] In GitHub or other platforms:
  * [ ] Add a [SECURITY.md file](https://docs.github.com/en/code-security/getting-started/adding-a-security-policy-to-your-repository#about-security-policies): this should contain a "Disclosure Policy", "Security Update policy", "Security related configuration" and "Known security gaps & future enhancements".
  * [ ] If you have Apps that interact with your repositories:
    * [ ] Give and validate the correct and minimum app access rights
    * [ ] Assess the author/organization credibility
    * [ ] Assess how good is the app's security posture (a breach/vulnerability in the app cloud affect you)
    * [ ] Monitor changes in apps and consider application access restrictions
  * [ ] &#x20;Add security testing to Pull Requests (see [Static Analysis](../tools/static-analysis.md))
  * [ ] Rotate SSH Keys, Personal Access Tokens and other kind of tokens (also passwords)
  * [ ] Create new projects with security in mind
  * [ ] When importing projects, audit the history for sensitive data and remove it before the import
* [ ] Use SSH key authentication where possible and applicable (SSHv2 preferible)
* [ ] Use only HTTPS or SSH to access Git repositories
* [ ] Integrity: enforce checks on all incoming objects by setting `transfer.fsckObjects`, `fetch.fsckObjects` and `receive.fsckObjects` to true in your git config (you can run an integrity check at any type by executing `git fsck`)
* [ ] Enforce usage of `.gitignore` files and periodically review them

## Tools

**From the** [**Secrets Scanning**](../tools/secrets/secrets-scanning.md) **section:**

* TruffleSecurity [Trufflehog](https://github.com/trufflesecurity/trufflehog) ([web](https://trufflesecurity.com/trufflehog/)): find and verify credentials.
  * [Chrome extension](https://chrome.google.com/webstore/detail/trufflehog/bafhdnhjnlcdbjcdcnafhdcphhnfnhjc)
* [gitleaks](https://github.com/gitleaks/gitleaks) ([web](https://gitleaks.io/)): a fast, light-weight, portable, and open-source secret scanner for git repositories, files, and directories.
* Deepfence [SecretScanner](https://github.com/deepfence/SecretScanner): find secrets and passwords in container images and file systems.
* TruffleSecurity [Driftwood](https://github.com/trufflesecurity/driftwood): a tool that can enable you to lookup whether a private key is used for things like TLS or as a GitHub SSH key for a user.
* [stacs](https://github.com/stacscan/stacs): a YARA powered static credential scanner which suports binary file formats, analysis of nested archives, composable rulesets and ignore lists, and SARIF reporting.
* [git-hound](https://github.com/tillson/git-hound): Reconnaissance tool for GitHub code search. Scans for exposed API keys across all of GitHub, not just known repos.
* AWS Labs [git-secrets](https://github.com/awslabs/git-secrets): Prevents you from committing secrets and credentials into git repositories
* Yelp [detect-secrets](https://github.com/Yelp/detect-secrets): An enterprise friendly way of detecting and preventing secrets in code.
* Auth0 [Repo-supervisor](https://github.com/auth0/repo-supervisor): a tool that helps you to detect secrets and passwords in your code.
* [GitGuardian](https://www.gitguardian.com/v): secure your software development lifecycle with enterprise-grade secrets detection. Eliminate blind spots with our automated, battle-tested detection engine.
* [Nightfall](https://www.nightfall.ai/): discover, classify, and remove secrets and keys to protect your organization and maintain compliance.
* [Spectral](https://spectralops.io/): monitor, classify, and protect your code, assets, and infrastructure for exposed API keys, tokens, credentials, and high-risk security misconfigurations in a simple way, without noise.

**From the** [**Secrets Management**](../tools/secrets/secrets-management.md) **section:**

* [Azure Key Vault](https://azure.microsoft.com/en-us/products/key-vault/): safeguard cryptographic keys and other secrets used by cloud apps and services.
* [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/): helps you manage, retrieve, and rotate database credentials, API keys, and other secrets throughout their lifecycles.
* [AWS Key Management Service (KMS)](https://aws.amazon.com/kms/): create and control keys used to encrypt or digitally sign your data.
* [Google Cloud Secret Manager](https://cloud.google.com/secret-manager): a secure and convenient storage system for API keys, passwords, certificates, and other sensitive data.
* [Google Cloud Key Management](https://cloud.google.com/security-key-management): manage encryption keys on Google Cloud.
* [HashiCorp Vault](https://www.hashicorp.com/products/vault): manage access to secrets and protect sensitive data.
* [StackExchange Blackbox](https://github.com/StackExchange/blackbox): Safely store secrets in a VCS repo (i.e. Git, Mercurial, Subversion or Perforce).
* [Akeyless Vault Platform](https://www.akeyless.io/secrets-management/secrets-store/): enable developers with a secure vault for credentials, certificates and keys.
* [Doppler](https://www.doppler.com/): the uncomplicated way to sync, manage, orchestrate, and rotate secrets across any environment or app config with easy to use tools.
* Mozilla [SOPS](https://github.com/mozilla/sops) (Secrets OPerationS): simple and flexible tool for managing secrets.
* [Teller](https://github.com/tellerops/teller) ([web](https://tlr.dev/)): a productivity secret manager for developers supporting cloud-native apps and multiple cloud providers. Mix and match all vaults and other key stores and safely use secrets as you code, test, and build applications.
* [CyberArk Conjur](https://github.com/cyberark/conjur) ([web](https://www.conjur.org/)): automatically secures secrets used by privileged users and machine identities.
* [GoPass](https://github.com/gopasspw/gopass) ([web](https://www.gopass.pw/)): the slightly more awesome standard UNIX password manager for teams.
* [Spectral Keyscope](https://github.com/SpectralOps/keyscope): a key and secret workflow (validation, invalidation, etc.) tool built in Rust.
* [Pinterest Knox](https://github.com/pinterest/knox): a service for storing and rotation of secrets, keys, and passwords used by other services.
* [Git-tresor](https://github.com/thebitrebels/git-tresor): Encrypt and decrypt files to store them inside a git repository. git-tresor uses AES-256 encryption. Every file or directory has it's own password. This enables you to commit encrypted files either in a separate git repository or inside the same repository where your secret files are needed (f.e. Android-Keystores or Signing-Certificates for Apple).
* [Ansible Vault](https://docs.ansible.com/ansible/latest/cli/ansible-vault.html): encryption/decryption utility for Ansible data files.
* [Chef Vault](https://github.com/chef/chef-vault): securely manage passwords, certs, and other secrets in Chef.
* [CredStash](https://github.com/fugue/credstash) (⚠️): a very simple, easy to use credential management and distribution system that uses AWS Key Management Service (KMS) for key wrapping and master-key storage, and DynamoDB for credential storage and sharing.

**Other utilities:**

* For cleaning sensitive data from repositories:
  * [BFG Repo-Cleaner](https://rtyley.github.io/bfg-repo-cleaner/): removes large or troublesome blobs like git-filter-branch does, but faster.
  * [git filter-repo](https://github.com/newren/git-filter-repo): a versatile tool for rewriting history.
  * [git filter-branch](https://git-scm.com/docs/git-filter-branch): lets you rewrite Git revision history by rewriting the branches.

## Sources

\[1]: [Git Security | Secure Git with Best Practices | Perforce](https://www.perforce.com/blog/vcs/git-secure)

\[2]: [10 GitHub Security Best Practices | Snyk](https://snyk.io/blog/ten-git-hub-security-best-practices/)

\[3]: [Security best practices for git users | Infosec Resources (infosecinstitute.com)](https://resources.infosecinstitute.com/topic/security-best-practices-for-git-users/)
