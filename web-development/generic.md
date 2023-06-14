---
description: Here resides some generic good security practices regarding web development
---

# Generic

## About

Needless to say, most websites suffer from various types of bugs which may eventually lead to vulnerabilities. Why would this happen so often? There can be many factors involved including misconfiguration, shortage of engineers' security skills, etc. \[1] We are here to combat this…

## Best practices

Here is a list of common attacks to cover ourselves from:

* [ ] XSS (Cross-Site Scripting)
  * [ ] Use [CSP to defend against some XSS](https://cheatsheetseries.owasp.org/cheatsheets/Content\_Security\_Policy\_Cheat\_Sheet.html#defense-against-xss) attacks (inline scripts, remote scripts, unsafe JavaScript, form submissions, objects...)
  * [ ] Understand your [Framework Security](https://cheatsheetseries.owasp.org/cheatsheets/Cross\_Site\_Scripting\_Prevention\_Cheat\_Sheet.html#framework-security). We have to be aware about how our framework prevents XSS and where it has gaps
  * [ ] Ensure all variables go through validation and then escaped or sanitized correctly
  * [ ] Use [Output Encoding](https://cheatsheetseries.owasp.org/cheatsheets/Cross\_Site\_Scripting\_Prevention\_Cheat\_Sheet.html#output-encoding). Safely display data exactly as a user typed it in. Variables should not be interpreted as code instead of text. This applies to HTML, JS, CSS, URLs...
  * [ ] Perform [HTML Sanitization](https://cheatsheetseries.owasp.org/cheatsheets/Cross\_Site\_Scripting\_Prevention\_Cheat\_Sheet.html#html-sanitization)
  * [ ] Use [Safe Sinks](https://cheatsheetseries.owasp.org/cheatsheets/Cross\_Site\_Scripting\_Prevention\_Cheat\_Sheet.html#safe-sinks)
  * [ ] Use Cookie attributes to change how JavaScript and browsers can interact with cookies
  * [ ] The use of Web Application Firewalls (WAF) can block some known attack strings
* [ ] CSV Injection
  * [ ] Ensure that no cells begins with these characters: "=", "+", "-", "@", tab "0x09", carriage return "0x0D"
  * [ ] We need to ensure content will be read as text by the spreadsheet editor
  * [ ] Take care of field separators and quotes
    * [ ] Wrap each cell field in double quotes
    * [ ] Prepend each cell field with a single quote
    * [ ] Escape every double quote using an additional double quote
* [ ] SQL Injection
  * [ ] If using an [ORM](https://en.wikipedia.org/wiki/Object%E2%80%93relational\_mapping), check about its SQLi defenses
  * [ ] Use [Prepared Statements (with Parametrized Queries)](https://cheatsheetseries.owasp.org/cheatsheets/SQL\_Injection\_Prevention\_Cheat\_Sheet.html#defense-option-1-prepared-statements-with-parameterized-queries)
  * [ ] Use of [properly constructed Stored Procedures](https://cheatsheetseries.owasp.org/cheatsheets/SQL\_Injection\_Prevention\_Cheat\_Sheet.html#defense-option-2-stored-procedures)
  * [ ] [Allow-list Input Validation](https://cheatsheetseries.owasp.org/cheatsheets/SQL\_Injection\_Prevention\_Cheat\_Sheet.html#defense-option-3-allow-list-input-validation)
  * [ ] [Escape all User-Supplied Input](https://cheatsheetseries.owasp.org/cheatsheets/SQL\_Injection\_Prevention\_Cheat\_Sheet.html#defense-option-4-escaping-all-user-supplied-input)
  * [ ] Enforce [Least privilege](https://cheatsheetseries.owasp.org/cheatsheets/SQL\_Injection\_Prevention\_Cheat\_Sheet.html#least-privilege)
* [ ] NoSQL injection
  * [ ] [Test for NoSQL injection vulnerabilities](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web\_Application\_Security\_Testing/07-Input\_Validation\_Testing/05.6-Testing\_for\_NoSQL\_Injection)
  * [ ] Avoid unsanitized user inputs in application code
  * [ ] Some DBs has built-in features for secure query building... check them out
  * [ ] Apply the rule of Least Privilege
  * [ ] Know your language to avoid using vulnerable constructs
* [ ] XXE - XML eXternal Entity
  * [ ] The safest way is to disable DTDs completely
  * [ ] For detailed XXE prevention guidance, check the [OWASP Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/XML\_External\_Entity\_Prevention\_Cheat\_Sheet.html)
* [ ] CSRF - Cross-Site Request forgery
  * [ ] Check if your framework has [built-in CSRF protection](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site\_Request\_Forgery\_Prevention\_Cheat\_Sheet.html#use-built-in-or-existing-csrf-implementations-for-csrf-protection) and use it
    * [ ] If not, add [CSRF tokens](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site\_Request\_Forgery\_Prevention\_Cheat\_Sheet.html#token-based-mitigation) to all state changing requests and validate them on the backend
  * [ ] For stateful software use the [synchronizer token pattern](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site\_Request\_Forgery\_Prevention\_Cheat\_Sheet.html#synchronizer-token-pattern)
  * [ ] For stateless software use [double submit cookies](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site\_Request\_Forgery\_Prevention\_Cheat\_Sheet.html#double-submit-cookie)
  * [ ] For API-driven sites that don't use `<form>` tags, use [custom request headers](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site\_Request\_Forgery\_Prevention\_Cheat\_Sheet.html#custom-request-headers)
  * [ ] Consider using [SameSite Cookie Attribute](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site\_Request\_Forgery\_Prevention\_Cheat\_Sheet.html#samesite-cookie-attribute)
  * [ ] Consider implementing [user interaction based protection](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site\_Request\_Forgery\_Prevention\_Cheat\_Sheet.html#user-interaction-based-csrf-defense) for highly sensitive operations
  * [ ] [Verify the origin with standard headers](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site\_Request\_Forgery\_Prevention\_Cheat\_Sheet.html#verifying-origin-with-standard-headers)
  * [ ] Do NOT use GET requests for state changing operations
    * [ ] If you need to do that, protect those resources against CSRF
* [ ] Clickjacking ([OWASP Clickjacking Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking\_Defense\_Cheat\_Sheet.html))
  * [ ] Prevent the browser from loading the page in an iframe by using [X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options) or [CSP headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy) (specially ["frame-ancestors"](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors))
  * [ ] Prevent sesion cookies from being included when the page is loaded in a frame using the [SameSite](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite) cookie attribute
  * [ ] Implement JavaScript code in the page to attempt to prevent it being loaded in a frame (["frame-buster" technique](https://en.wikipedia.org/wiki/Framekiller))
* [ ] SSRF - Server-Side Request forgery
  * [ ] Check where the application can send request only to identified and trusted applications
    * [ ] Use [Input validation](https://cheatsheetseries.owasp.org/cheatsheets/Input\_Validation\_Cheat\_Sheet.html) in all application layers
    * [ ] Disable the support for the following of [redirections ](https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections)to prevent the bypass of the input validation
    * [ ] Apply [the allow list approach](https://cheatsheetseries.owasp.org/cheatsheets/Input\_Validation\_Cheat\_Sheet.html#allow-list-vs-block-list)
  * [ ] Check where the application can send request to ANY external IP address or domain name
    * [ ] Check [available protections in this case](https://cheatsheetseries.owasp.org/cheatsheets/Server\_Side\_Request\_Forgery\_Prevention\_Cheat\_Sheet.html#available-protections\_1)
* [ ] Open Redirects
  * [ ] Never allow open redirects as a default (if possible)
  * [ ] Do not allow the URL as user input for destination (if possible)
    * [ ] If user input can't be avoided
      * [ ] Ensure it's valid
      * [ ] Sanitize the input
      * [ ] Ensure it's authorized
      * [ ] Force redirects to go through a page notifying users they are going to another site and make them confirm
  * [ ] Follow an allow-list approach, rather than a block list
  * [ ] Map the URL provided by the user to a short name (not enumerable) or hash to avoid tampering and reduce enumeration vulnerabilities
* [ ] File Uploads
  * [ ] List allowed extensions, only allow safe and critical extensions for business functionallity
    * [ ] Use [input validation](https://cheatsheetseries.owasp.org/cheatsheets/Input\_Validation\_Cheat\_Sheet.html#file-upload-validation) before validation the extensions
  * [ ] Validate the file type, do NOT trust the [Content-Type header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Type) (it can be spoofed)
  * [ ] Change the filename to something generated by the application
  * [ ] Set a filename length limit
  * [ ] Restrict allowed characters in the filename
  * [ ] Set a file size limit
  * [ ] Only allow authorized users to upload files
  * [ ] Store files on a different server or outside the webroot
    * [ ] If you have to provide public access to these files use a handler to map filenames inside the application
  * [ ] Run the file through an antivirus (such as [VirusTotal](https://www.virustotal.com/)) or in a sandbox, to validate it doesn't contain malicious data
  * [ ] Ensure that used libraries for this purpose are securely configured and up to date
  * [ ] Protect against [CSRF ](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site\_Request\_Forgery\_Prevention\_Cheat\_Sheet.html)attacks
* [ ] CSP (Content Security Policies)
  * [ ] Ensure to have a strong/strict CSP headers. Only allow what needed for your web to load
    * [ ] Use [hashes](https://cheatsheetseries.owasp.org/cheatsheets/Content\_Security\_Policy\_Cheat\_Sheet.html#hashes) or [nonces](https://cheatsheetseries.owasp.org/cheatsheets/Content\_Security\_Policy\_Cheat\_Sheet.html#nonces)
    * [ ] [Upgrade insecure requests](https://cheatsheetseries.owasp.org/cheatsheets/Content\_Security\_Policy\_Cheat\_Sheet.html#upgrading-insecure-requests) (or only serve via HTTPS)
  * [ ] Enable a [report directive](https://cheatsheetseries.owasp.org/cheatsheets/Content\_Security\_Policy\_Cheat\_Sheet.html#reporting-directives) to receive violations of prevented behaviours to specified locations
  * [ ] Use tools to evaluate your CSP policy (such as [CSP evaluator](https://csp-evaluator.withgoogle.com/))
* [ ] Use [HSTS (HTTP Strict Transport Security)](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security)
  * [ ] See [related problems](https://cheatsheetseries.owasp.org/cheatsheets/HTTP\_Strict\_Transport\_Security\_Cheat\_Sheet.html#problems) nevertheless
* [ ] Cryptography
  * [ ] See [cryptography.md](../generic-development/cryptography.md "mention")
* [ ] JWT (JSON Web Tokens)
  * [ ] Do NOT include secrets in the payload
  * [ ] Do NOT allow 'none' algorithm for signing ([more info](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/#Meet-the%E2%80%94None%E2%80%94Algorithm))
  * [ ] Always verify the token (issuer, signature, retrieve actual public keys...)
  * [ ] Avoid sensitive data exposure by not inserting a whole object into the JWT (break into parts, has to be lightweight)
  * [ ] Use strong/recommended algorithms for signing
* [ ] Authentication
  * [ ] UserIds
    * [ ] Make sure they are case-insensitive and unique
    * [ ] You can avoid username enumeration by mapping each username with an incremental ID internally and use a mapped hash (ex. using Hashids) to avoid enumeration
    * [ ] If using email as user id, perform input validation
  * [ ] Do NOT allow login with sensitive accounts (that can be used internally)
  * [ ] Do NOT use same authentication solution for internal resources and for public access
  * [ ] Implement proper password strength controls (see [OWASP Password Storage Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Password\_Storage\_Cheat\_Sheet.html#maximum-password-lengths))
  * [ ] Implement a proper "forgot password" mechanism (see [OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot\_Password\_Cheat\_Sheet.html))
  * [ ] Store password securely (see [OWASP Password Storage Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Password\_Storage\_Cheat\_Sheet.html#maximum-password-lengths))
  * [ ] Always compare password hashes using safe functions
  * [ ] Only allow authentication via HTTPs or other encrypted and strong transport
  * [ ] Require re-authentication or 2FA/MFA for sensitive features
  * [ ] Do NOT give hints in error messages to avoid enumeration attacks (be generic with error messages)
  * [ ] Protect against [automated attacks](https://cheatsheetseries.owasp.org/cheatsheets/Authentication\_Cheat\_Sheet.html#protect-against-automated-attacks) (see also [OWASP Credential Stuffing Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Credential\_Stuffing\_Prevention\_Cheat\_Sheet.html))
  * [ ] Log and monitor your authentication mechanism
  * [ ] Use authentication protocos that follow standards if possible ([OAuth](https://oauth.net/), [OpenID](https://openid.net/), [SAML](https://auth0.com/intro-to-iam/what-is-saml), [FIDO](https://fidoalliance.org/), [Passkeys](https://www.passkeys.com/) ...)
    * [ ] [SAML Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SAML\_Security\_Cheat\_Sheet.html)
  * [ ] Set `spellcheck="false"` in the HTML password field to avoid filtering the password (Spell-jacking)
  * [ ] Set `autocomplete="off"` if possible in the HTML password field
  * [ ] Let know the users about the benefits of using a password manager
* [ ] Cookies
  * [ ] Always limit their access as possible
  * [ ] Always set all Cookies with the "Secure" flag
  * [ ] Avoid access to the cookie via JS by setting "HttpOnly"
  * [ ] Set the expiration time ("Expires" & "Max-Age" directives) as soon as is necessary
  * [ ] Set the "Domain" directive as restrictive as possible
  * [ ] Set the "Path" directive as restrictive as possible
  * [ ] Set the "SameSite" directive accordingly to your needs and the more restrictive possible ("Strict" always recommended)
* [ ] Consider enabling [HTTP Public Key Pinning (HPKP)](https://infosec.mozilla.org/guidelines/web\_security#http-public-key-pinning)
* [ ] Set a [Referrer Policy](https://infosec.mozilla.org/guidelines/web\_security#referrer-policy) and consider never redirect a user to an external page with the referrer header (to be secretive)
* [ ] Create a restrictive ["robots.txt"](https://infosec.mozilla.org/guidelines/web\_security#robotstxt) file to avoid robots crawl and disclose private information or portions of a website
* [ ] Try to load external data from CDNs or others by specifying the "integrity" and "crossorigin" attributes to enable "[Subresource Integrity](https://infosec.mozilla.org/guidelines/web\_security#subresource-integrity)"&#x20;
* [ ] Consider setting the header "[X-Content-Type-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options)" to avoid the client to guess the MIME type of the response ([MIME type sniffing](https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics\_of\_HTTP/MIME\_types#mime\_sniffing))
* [ ] Add a "[security.txt](https://en.wikipedia.org/wiki/Security.txt)" file in the root of your page to tell security researchers how to disclose vulnerabilities

## Another things to take care about

Here is another check list of things to know about and protect (**this does not mean they are less important!**):

* [ ] Prototype Pollution
* [ ] HTTP Parameter Pollution
* [ ] Command Injection
* [ ] Deserialization attacks
* [ ] ORM Injection
* [ ] FTP Injection
* [ ] Web Cache Poisoning
* [ ] Relative Path Overwrite
* [ ] Remote Code Execution
* [ ] Header injection
* [ ] [URLs problems](https://github.com/qazbnm456/awesome-web-security/#url)
* [ ] [Leaking](https://github.com/qazbnm456/awesome-web-security/#leaking)
* [ ] Browser Exploitation
* [ ] ModSecurity (see [OWASP ModSecurity Core Rule Set](https://owasp.org/www-project-modsecurity-core-rule-set/))
* [ ] SSL/TLS
* [ ] NFS
* [ ] Fingerprint
* [ ] [Sub Domain Enumeration](https://github.com/qazbnm456/awesome-web-security/#sub-domain-enumeration-1)
* [ ] DNS Rebinding
* [ ] WAF (Web Application Firewalls)

## Resources

* [So you want to be a web security researcher? | PortSwigger Research](https://portswigger.net/research/so-you-want-to-be-a-web-security-researcher)
* [OWASP Web Security Testing Guide | OWASP Foundation](https://owasp.org/www-project-web-security-testing-guide/)
* [Mitigate cross-site scripting (XSS) with a strict Content Security Policy (CSP) (web.dev)](https://web.dev/i18n/en/strict-csp/)
* [Authentication - OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/cheatsheets/Authentication\_Cheat\_Sheet.html)
* [Web Security (mozilla.org)](https://infosec.mozilla.org/guidelines/web\_security)
* [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/index.html)

## Sources

\[1]: [qazbnm456/awesome-web-security: 🐶 A curated list of Web Security materials and resources. (github.com)](https://github.com/qazbnm456/awesome-web-security/)

\[2]: [Authentication - OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/cheatsheets/Authentication\_Cheat\_Sheet.html)

\[3]: [Web Security (mozilla.org)](https://infosec.mozilla.org/guidelines/web\_security)

\[4]: [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/index.html)

\[5]: [OWASP Web Security Testing Guide | OWASP Foundation](https://owasp.org/www-project-web-security-testing-guide/)
