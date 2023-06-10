---
description: Cryptography is hard, difficult, but we must know about its importance
---

# Cryptography

## About

Cryptography is the process of hiding or coding information so that only the person a message was intended for can read it. Cryptography remains important to protecting data and users, ensuring confidentiality, and preventing cyber criminals from intercepting sensitive corporate information. \[2]

Cryptographic keys are a foundational element of modern cybersecurity. They serve to keep data safely encrypted and help maintain secure networks for client-server communication. Unfortunately, this makes them a prime target for hackers. A single compromised key can give access to a goldmine of personal data and valuable IP, as well as enable other malicious actions such as unauthorized system access or signing digital certificates. Yet, despite its importance, many software developers still do not prioritize cryptographic key protection. \[3]

## Best practices

Here are some best practices to follow regarding Cryptography and Cryptographic keys \[1]\[2]\[3]\[4]:

* [ ] **NEVER use custom algorithms...**
* [ ] Encrypt all data in transit with secure protocols such as TLS with forward secrecy (FS) ciphers, cipher prioritization by the server, and secure parameters
* [ ] Enforce encryption using directives like HTTP Strict Transport Security (HSTS)
* [ ] Encrypt data at rest
* [ ] Disable caching for response that contain sensitive data
* [ ] Do NOT use legacy protocols for transporting sensitive data
* [ ] Store passwords using strong adaptive and salted hashing functions with a work factor (delay factor), such as [Argon2](https://en.wikipedia.org/wiki/Argon2), [scrypt](https://en.wikipedia.org/wiki/Scrypt), [bcrypt ](https://en.wikipedia.org/wiki/Bcrypt)or [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2)
* [ ] Always use authenticated encryption instead of just encryption
* [ ] Perform encryption in the correct layer ([more info](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic\_Storage\_Cheat\_Sheet.html#where-to-perform-encryption))
* [ ] Verify independently the effectiveness of configuration and settings
* [ ] Use approved and appropriate cryptographic algorithms ([source](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program)) ([more info](https://cheatsheetseries.owasp.org/cheatsheets/Key\_Management\_Cheat\_Sheet.html#key-selection))
  * [ ] Avoid deprecated cryptographic functions and padding schemes, such as [MD5](https://en.wikipedia.org/wiki/MD5), [SHA1](https://en.wikipedia.org/wiki/SHA-1), [PKCS number 1 ](https://en.wikipedia.org/wiki/PKCS\_1)v1.5
  * [ ] Take into account Cipher modes ([more info](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic\_Storage\_Cheat\_Sheet.html#cipher-modes)) and Random padding ([more info](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic\_Storage\_Cheat\_Sheet.html#random-padding))
* [ ] Never hard-code keys in your software
* [ ] Minimise the storage of sensitive information
* [ ] Use secure random number generation ([more info](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic\_Storage\_Cheat\_Sheet.html#secure-random-number-generation)) and be aware of UUIDs and GUIDs generation ([more info](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic\_Storage\_Cheat\_Sheet.html#uuids-and-guids))
* [ ] Limit keys to a single, specific purpose
* [ ] Use hardware-backed security when posible
* [ ] Separate Keys from data ([more info](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic\_Storage\_Cheat\_Sheet.html#separation-of-keys-and-data))
* [ ] Encrypt Stored Keys ([more info](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic\_Storage\_Cheat\_Sheet.html#encrypting-stored-keys))
* [ ] Put robust [key management](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic\_Storage\_Cheat\_Sheet.html#key-management) in place (see [Secrets management](../tools/secrets/secrets-management.md) section, the ones related with keys)
  * [ ] Key generation ([more info](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic\_Storage\_Cheat\_Sheet.html#key-generation))
  * [ ] Key lifetimes and rotation ([more info](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic\_Storage\_Cheat\_Sheet.html#key-lifetimes-and-rotation))
  * [ ] Key lifecycle ([more info](https://cheatsheetseries.owasp.org/cheatsheets/Key\_Management\_Cheat\_Sheet.html#key-selection))
  * [ ] Key storage ([more info](https://cheatsheetseries.owasp.org/cheatsheets/Key\_Management\_Cheat\_Sheet.html#trust-stores)) and backup ([more info](https://cheatsheetseries.owasp.org/cheatsheets/Key\_Management\_Cheat\_Sheet.html#escrow-and-backup))
  * [ ] Access protections and restrictions ([more info](https://cheatsheetseries.owasp.org/cheatsheets/Key\_Management\_Cheat\_Sheet.html#accountability-and-audit))
* [ ] Take advantage of [white-box cryptography](https://cpl.thalesgroup.com/software-monetization/white-box-cryptography) for key protection gaps

## Resources

* [A02 Cryptographic Failures - OWASP Top 10:2021](https://owasp.org/Top10/A02\_2021-Cryptographic\_Failures/)
* [OWASP Proactive Controls: Protect Data Everywhere](https://owasp.org/www-project-proactive-controls/v3/en/c8-protect-data-everywhere)
* [OWASP Application Security Verification Standard (V7, 9, 10)](https://owasp.org/www-project-application-security-verification-standard)
* [OWASP Cheat Sheet: Transport Layer Protection](https://cheatsheetseries.owasp.org/cheatsheets/Transport\_Layer\_Protection\_Cheat\_Sheet.html)
* [OWASP Cheat Sheet: User Privacy Protection](https://cheatsheetseries.owasp.org/cheatsheets/User\_Privacy\_Protection\_Cheat\_Sheet.html)
* [OWASP Cheat Sheet: Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password\_Storage\_Cheat\_Sheet.html)
* [OWASP Cheat Sheet: Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic\_Storage\_Cheat\_Sheet.html)
* [OWASP Cheat Sheet: Key management](https://cheatsheetseries.owasp.org/cheatsheets/Key\_Management\_Cheat\_Sheet.html)
* [OWASP Cheat Sheet: HSTS](https://cheatsheetseries.owasp.org/cheatsheets/HTTP\_Strict\_Transport\_Security\_Cheat\_Sheet.html)
* [OWASP Testing Guide: Testing for weak cryptography](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web\_Application\_Security\_Testing/09-Testing\_for\_Weak\_Cryptography/README)
* [The Definitive Guide to Encryption Key Management Fundamentals (townsendsecurity.com)](https://info.townsendsecurity.com/definitive-guide-to-encryption-key-management-fundamentals)
* [Practical Cryptography for Developers (nakov.com)](https://cryptobook.nakov.com/)

## Tools

[OWASP Testing Guide: Testing for weak cryptography](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web\_Application\_Security\_Testing/09-Testing\_for\_Weak\_Cryptography/README)

## Sources

\[1]: [Cryptography | NIST](https://www.nist.gov/cryptography)

\[2]: [What is Cryptography? Definition, Importance, Types | Fortinet](https://www.fortinet.com/resources/cyberglossary/what-is-cryptography)

\[3]: [Five cryptographic key protection best practices - Security Boulevard](https://securityboulevard.com/2021/01/five-cryptographic-key-protection-best-practices/)

\[4]: [Key Management - OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/cheatsheets/Key\_Management\_Cheat\_Sheet.html)
