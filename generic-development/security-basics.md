---
description: Let's start from the beginning...
---

# Security Basics

## About

This page is meant to be as an starting point for security in development, for developers with little or no experience at all with secure development and good security practices in development.

## Awareness

Every year vulnerabilities tend to grow in numbers ([as you can see in CVE Details](https://www.cvedetails.com/browse-by-date.php)) as well as weakness in code ([view CWE from Mitre](https://cwe.mitre.org/data/index.html)).

Lots of enterprises are more aware about security in their software, ransomware groups and attacks are pretty common every single day, automated scannners for common vulnerabilities run by bad actors...

The are lots of reasons to take security seriously as a developer. Just take a Raspberry Pi (or other similar device) or spin up a VM in a cloud service, and open SSH port on port 22 publicly... You will be shocked with the number of attempts to login to your device...

Then have a look to some of this visualization tools:

* [Cloudflare](https://www.cloudflare.com/) offers ["Cloudflare Radar"](https://radar.cloudflare.com/) where you can see an instant overview of internet insights (some regarding security and attacks).
* The [NIST (National Instutute of Standards and Technology)](https://www.nist.gov/) provides [multiple visualizations of it's vulnerability database.](https://nvd.nist.gov/general/visualizations)
* [CheckPoint ](https://www.checkpoint.com/)offers [ThreatMap](https://threatmap.checkpoint.com/) where you can see attacks in real time, as well as attacks on the day of visit (tends to grow to millions a day).
* [Kaspersky](https://www.kaspersky.com/) offers [Cybermap](https://cybermap.kaspersky.com/), a realtime CyberTheat map.
* [Radware](https://radware.com) offers [another live threat map](https://livethreatmap.radware.com/) worth to check out.
* [NetScout](https://www.netscout.com/) offers [Horizon](https://horizon.netscout.com/), its own cyber threat real-time map.
* [Imperva](https://www.imperva.com/) also offers [its own cyber threat attack map](https://www.imperva.com/cyber-threat-attack-map/).
* And lots of other tools:
  * [Digital Attack Map (DDoS attacks)](https://www.digitalattackmap.com/)
  * [Akamai Internet Station (Cyber attacks)](https://www.akamai.com/internet-station/cyber-attacks)
  * [Threatbutt Internet Hacking Attack Attribution Map](https://threatbutt.com/map/)
  * [Fortiguard (Fortinet) threat map](https://threatmap.fortiguard.com/)
  * [Bitdefender Cyberthreat real time map](https://threatmap.bitdefender.com/)
  * [Talos Cyber attack map (Spam & Malware)](https://talosintelligence.com/fullpage\_maps/pulse)
  * [SonicWall live attack map](https://attackmap.sonicwall.com/live-attack-map/)

Search news for data breaches, security incidents, ransomware attacks.

Are you more concerned now?

Great. Let's improve this situation...

**A good starting point is to look at [OWASP Top Ten](https://owasp.org/www-project-top-ten/), these are the main application security risks that are most important nowadays. The goal is to minimise these risks.**

## Secure Coding Practices

A very good starting point to ensure whatever you are developing, you meet with [this OWASP checklist](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/stable-en/02-checklist/05-checklist).

[This SecureCoding blog post](https://www.securecoding.com/blog/owasp-secure-coding-checklist/) about it, it's also very useful.

This checklist covers the following points:

* [Input Validation](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/stable-en/02-checklist/05-checklist#input-validation)
* [Output Encoding](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/stable-en/02-checklist/05-checklist#output-encoding)
* [Authentication & Password Management](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/stable-en/02-checklist/05-checklist#authentication-and-password-management)
* [Session Management](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/stable-en/02-checklist/05-checklist#session-management)
* [Access Control](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/stable-en/02-checklist/05-checklist#access-control)
* [Cryptographic Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/stable-en/02-checklist/05-checklist#cryptographic-practices)
* [Error Handling & Logging](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/stable-en/02-checklist/05-checklist#error-handling-and-logging)
* [Data Protection](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/stable-en/02-checklist/05-checklist#data-protection)
* [Communication Security](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/stable-en/02-checklist/05-checklist#communication-security)
* [System Configuration](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/stable-en/02-checklist/05-checklist#system-configuration)
* [Database Security](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/stable-en/02-checklist/05-checklist#database-security)
* [File Management](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/stable-en/02-checklist/05-checklist#file-management)
* [Memory Management](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/stable-en/02-checklist/05-checklist#memory-management)
* [**General coding practices**](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/stable-en/02-checklist/05-checklist#general-coding-practices) **(this last point is very important)**

From the last bullet point, make sure you are following this coding practices:

* [ ] **Use tested and approved managed code** rather than creating new unmanaged code for common tasks.
* [ ] Utilize task specific built-in APIs to conduct operating system tasks. **Do not allow the application to issue commands directly to the Operating System, especially through the use of application initiated command shells**.
* [ ] **Use [checksums](https://en.wikipedia.org/wiki/Checksum) or hashes to verify the integrity** of interpreted code, libraries, executables, and configuration files.
* [ ] Utilize locking to prevent multiple simultaneous requests or use a synchronization mechanism to **prevent race conditions**.
* [ ] **Protect shared variables and resources** from inappropriate concurrent access.
* [ ] **Explicitly initialize all your variables and other data stores**, either during declaration or just before the first usage.
* [ ] In cases where the application must run with elevated privileges, **raise privileges as late as possible, and drop them as soon as possible**.
* [ ] Avoid calculation errors by **understanding your programming language's underlying representation.**
* [ ] **Do not pass user supplied data to any dynamic execution function.**
* [ ] **Restrict users from generating new code or altering existing code.**
* [ ] **Review all secondary applications, third party code and libraries** to determine business necessity and validate safe functionality.
* [ ] Implement **safe updating using encrypted channels.**

## Getting some help

You don't have to do all of this without help!

Look for professionals, professional enterprise ready tools and solutions. awesome OSS projects and others in other sections of this page:

* [Broken link](broken-reference "mention")
* [Broken link](broken-reference "mention")

