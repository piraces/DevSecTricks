---
description: APIs are essential nowadays, make them secure
---

# APIs

## About

A foundational element of innovation in today’s app-driven world is the API. From banks, retail and transportation to IoT, autonomous vehicles and smart cities, APIs are a critical part of modern mobile, SaaS and web applications and can be found in customer-facing, partner-facing and internal applications. By nature, APIs expose application logic and sensitive data such as Personally Identifiable Information (PII) and because of this have increasingly become a target for attackers. Without secure APIs, rapid innovation would be impossible. \[1]

## Best practices

Extracted from \[2], \[3] and \[4].

### Authentication

* [ ] Don't use `Basic Auth`. Use standard authentication instead (e.g., [JWT](https://jwt.io/)).
* [ ] Don't reinvent the wheel in `Authentication`, `token generation`, `password storage`. Use the standards.
* [ ] Use `Max Retry` and jail features in Login.
* [ ] Use encryption on all sensitive data.

### JWT (JSON Web Tokens)

* [ ] Use a random complicated key (`JWT Secret`) to make brute forcing the token very hard.
* [ ] Don't extract the algorithm from the header. Force the algorithm in the backend.
* [ ] Make token expiration (`TTL`, `RTTL`) as short as possible.
* [ ] Don't store sensitive data in the JWT payload, it can be decoded [easily](https://jwt.io/#debugger-io).
* [ ] Avoid storing too much data. JWT is usually shared in headers and they have a size limit.

### Access

* [ ] Limit requests (Throttling) to avoid DDoS / brute-force attacks.
* [ ] Use HTTPS on server side with TLS 1.2+ and secure ciphers to avoid MITM (Man in the Middle Attack).
* [ ] Use `HSTS` header with SSL to avoid SSL Strip attacks.
* [ ] Turn off directory listings.
* [ ] For private APIs, allow access only from safelisted IPs/hosts.

### OAuth

* [ ] Always validate `redirect_uri` server-side to allow only safelisted URLs.
* [ ] Always try to exchange for code and not tokens (don't allow `response_type=token`).
* [ ] Use `state` parameter with a random hash to prevent CSRF on the OAuth authorization process.
* [ ] Define the default scope, and validate scope parameters for each application.

### Input

* [ ] Use the proper HTTP method according to the operation: `GET`, `POST`, `PUT/PATCH`, and `DELETE`, and respond with `405 Method Not Allowed` if the requested method isn't appropriate for the requested resource.
* [ ] Validate `content-type` on request Accept header (Content Negotiation) to allow only your supported format (e.g., `application/xml`, `application/json`, etc.) and respond with `406 Not Acceptable` response if not matched.
* [ ] Validate `content-type` of posted data as you accept (e.g., `application/x-www-form-urlencoded`, `multipart/form-data`, `application/json`, etc.).
* [ ] Validate user input to avoid common vulnerabilities (e.g., `XSS`, `SQL-Injection`, `Remote Code Execution`, etc.).
* [ ] Don't use any sensitive data (`credentials`, `Passwords`, `security tokens`, or `API keys`) in the URL, but use standard Authorization header.
* [ ] Use only server-side encryption.
* [ ] Use an API Gateway service to enable caching, Rate Limit policies (e.g., `Quota`, `Spike Arrest`, or `Concurrent Rate Limit`) and deploy APIs resources dynamically.

### Processing

* [ ] Check if all the endpoints are protected behind authentication to avoid broken authentication process.
* [ ] &#x20;User own resource ID should be avoided. Use `/me/orders` instead of `/user/654321/orders`.
* [ ] &#x20;Don't auto-increment IDs. Use `UUID` instead.
* [ ] If you are parsing XML data, make sure entity parsing is not enabled to avoid `XXE` (XML external entity attack).
* [ ] If you are parsing XML, YAML or any other language with anchors and refs, make sure entity expansion is not enabled to avoid `Billion Laughs/XML bomb` via exponential entity expansion attack.
* [ ] Use a CDN for file uploads.
* [ ] If you are dealing with huge amount of data, use Workers and Queues to process as much as possible in background and return response fast to avoid HTTP Blocking.
* [ ] Do not forget to turn the DEBUG mode OFF.
* [ ] Use non-executable stacks when available.

### Output

* [ ] Send `X-Content-Type-Options: nosniff` header.
* [ ] Send `X-Frame-Options: deny` header.
* [ ] Send `Content-Security-Policy: default-src 'none'` header.
* [ ] Remove fingerprinting headers - `X-Powered-By`, `Server`, `X-AspNet-Version`, etc.
* [ ] Force `content-type` for your response. If you return `application/json`, then your `content-type` response is `application/json`.
* [ ] Don't return sensitive data like `credentials`, `passwords`, or `security tokens`.
* [ ] Return the proper status code according to the operation completed. (e.g., `200 OK`, `400 Bad Request`, `401 Unauthorized`, `405 Method Not Allowed`, etc.).

### CI/CD

* [ ] Audit your design and implementation with unit/integration tests coverage.
* [ ] Use a code review process and disregard self-approval.
* [ ] Ensure that all components of your services are statically scanned by AV software before pushing to production, including vendor libraries and other dependencies.
* [ ] Continuously run security tests (static/dynamic analysis) on your code.
* [ ] Check your dependencies (both software and OS) for known vulnerabilities.
* [ ] Design a rollback solution for deployments.

### Monitoring

* [ ] Use centralized logins for all services and components.
* [ ] Use agents to monitor all traffic, errors, requests, and responses.
* [ ] Use alerts for SMS, Slack, Email, Telegram, Kibana, Cloudwatch, etc.
* [ ] Ensure that you aren't logging any sensitive data like credit cards, passwords, PINs, etc.
* [ ] Use an IDS and/or IPS system to monitor your API requests and instances.

### More!

* [ ] Take a look into these checklists:
  * [ ] [API Security Checklist](https://github.com/shieldfy/API-Security-Checklist)
  * [ ] [OWASP API Security Top 10 Checklist](https://owasp.org/API-Security/editions/2023/en/0x00-toc/)
  * [ ] [another API Security checklist](https://github.com/HolyBugx/HolyTips/blob/main/Checklist/API%20Security.pdf)
  * [ ] [API audit checklist](https://www.apiopscycles.com/api-audit-checklist)
  * [ ] [API penetration testing checklist](https://apimike.com/api-penetration-testing-checklist)
  * [ ] [API Testing Checklist](https://hackanythingfor.blogspot.com/2020/07/api-testing-checklist.html)
  * [ ] [31 days of API Security Tips](https://github.com/smodnix/31-days-of-API-Security-Tips)
  * [ ] [OAuth2: Security checklist](https://web.archive.org/web/20210607123429/https://www.binarybrotherhood.io/oauth2\_threat\_model.html)
  * [ ] [GraphQL API — GraphQL Security Checklist](https://www.apollographql.com/blog/graphql/security/9-ways-to-secure-your-graphql-api-security-checklist/)
  * [ ] [REST API Security Essentials](https://restfulapi.net/security-essentials/)
* [ ] Take a look at these cheatsheets:
  * [ ] [REST Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST\_Security\_Cheat\_Sheet.html)
  * [ ] [REST Assessment Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST\_Assessment\_Cheat\_Sheet.html)
  * [ ] [JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON\_Web\_Token\_for\_Java\_Cheat\_Sheet.html)
  * [ ] [Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input\_Validation\_Cheat\_Sheet.html)
  * [ ] [Content Security Policy (CSP) Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content\_Security\_Policy\_Cheat\_Sheet.html)
  * [ ] [Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication\_Cheat\_Sheet.html)
  * [ ] [GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL\_Cheat\_Sheet.html)
  * [ ] [JSON Web Token Security Cheat Sheet](https://assets.pentesterlab.com/jwt\_security\_cheatsheet/jwt\_security\_cheatsheet.pdf)
  * [ ] [Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Injection\_Prevention\_Cheat\_Sheet.html)
  * [ ] [Microservices Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Microservices\_Security\_Cheat\_Sheet.html)
  * [ ] [OWASP API Security Top 10](https://apisecurity.io/encyclopedia/content/owasp-api-security-top-10-cheat-sheet-a4.pdf)

## Resources

Find here other resources for APIs security...

### Tools

#### Generic

* [API Development tools](https://github.com/yosriady/api-development-tools): A collection of useful resources for building RESTful HTTP+JSON APIs.
* [API Guesser](https://api-guesser.netlify.app/): Simple website to guess API Key / OAuth Token by Muhammad Daffa.
* [API Key Leaks: Tools and exploits](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/API%20Key%20Leaks): An API key is a unique identifier that is used to authenticate requests associated with your project. Some developers might hardcode them or leave it on public shares.
* [Key-Checker](https://github.com/daffainfo/Key-Checker) (⚠️): Go scripts for checking API key / access token validity.
* [Keyhacks](https://github.com/streaak/keyhacks): Keyhacks is a repository which shows quick ways in which API keys leaked by a bug bounty program can be checked to see if they’re valid.
* [Private key usage verification](https://github.com/trufflesecurity/driftwood): Driftwood is a tool that can enable you to lookup whether a private key is used for things like TLS or as a GitHub SSH key for a user.
* [Burp API enumeration](https://portswigger.net/support/using-burp-to-enumerate-a-rest-api): Using Burp to Enumerate a REST API.
* [ZAP scanning](https://www.zaproxy.org/blog/2017-06-19-scanning-apis-with-zap/): Scanning APIs with ZAP.
* [ZAP exploring](https://www.zaproxy.org/blog/2017-04-03-exploring-apis-with-zap/): Exploring APIs with ZAP.
* [ZAP API Scan](https://www.zaproxy.org/docs/docker/api-scan/): A ZAP add-on that automates API security scanning.
* [w3af scanning](http://docs.w3af.org/en/latest/scan-rest-apis.html): Scan REST APIs with w3af.
* [Wallarm Free API Firewall](https://github.com/wallarm/api-firewall): Fast and light-weight API proxy firewall for request and response validation by OpenAPI specs.
* [dredd](https://github.com/apiaryio/dredd): Language-agnostic HTTP API Testing Tool.
* [getallurls (gau)](https://github.com/lc/gau): Fetch known URLs from AlienVault’s Open Threat Exchange, the Wayback Machine, and Common Crawl.
* [SoapUI](https://github.com/SmartBear/soapui): SoapUI is a free and open-source cross-platform functional testing solution for APIs and web services.
* [Step CI](https://github.com/stepci/stepci): Open-source framework for API Quality Assurance, which tests REST, GraphQL and gRPC automated and from Open API spec.
* [unfurl](https://github.com/tomnomnom/unfurl): Pull out bits of URLs provided on stdin.
* [ModSecurity](https://www.github.com/SpiderLabs/ModSecurity): An open-source web application firewall (WAF) that can help protect APIs.

#### GraphQL

* [BatchQL](https://github.com/assetnote/batchql) (⚠️): GraphQL security auditing script with a focus on performing batch GraphQL queries and mutations.
* [clairvoyance](https://github.com/nikitastupin/clairvoyance): Obtain GraphQL API schema despite disabled introspection!.
* [GraphQLmap](https://github.com/swisskyrepo/GraphQLmap): GraphQLmap is a scripting engine to interact with a graphql endpoint for pentesting purposes.
* [graphql-path-enum](https://gitlab.com/dee-see/graphql-path-enum): Tool that lists the different ways of reaching a given type in a GraphQL schema.
* [graphql-playground](https://github.com/graphql/graphql-playground): GraphQL IDE for better development workflows (GraphQL Subscriptions, interactive docs & collaboration).
* [graphql-threat-matrix](https://github.com/nicholasaleks/graphql-threat-matrix): GraphQL threat framework used by security professionals to research security gaps in GraphQL implementations.
* [graphw00f](https://github.com/dolevf/graphw00f): graphw00f is GraphQL Server Engine Fingerprinting utility for software security professionals looking to learn more about what technology is behind a given GraphQL endpoint.
* [graphql-shield](https://github.com/maticzav/graphql-shield): A library for securing GraphQL APIs with fine-grained access control.

#### SOAP

* [Wsdler](https://github.com/NetSPI/Wsdler) (⚠️): WSDL Parser extension for Burp.
* [wsdl-wizard](https://github.com/portswigger/wsdl-wizard) (⚠️): WSDL Wizard is a Burp Suite plugin written in Python to detect current and discover new WSDL (Web Service Definition Language) files.

#### REST APIs

* [Akto](https://github.com/akto-api-security/akto): API discovery, automated business logic testing and runtime detection.
* [APICheck](https://bbva.github.io/apicheck/): The DevSecOps toolset for REST APIs.
* [APIClarity](https://github.com/apiclarity/apiclarity): Reconstruct Open API Specifications from real-time workload traffic seamlessly.
* [APIFuzzer](https://github.com/KissPeter/APIFuzzer): Fuzz test your application using your OpenAPI or Swagger API definition without coding.
* [APIKit](https://github.com/API-Security/APIKit): Discovery, Scan and Audit APIs Toolkit All In One.
* [Arjun](https://github.com/s0md3v/Arjun): HTTP parameter discovery suite.
* [Astra](https://github.com/flipkart-incubator/Astra): Automated Security Testing For REST API’s.
* [Automatic API Attack Tool](https://github.com/imperva/automatic-api-attack-tool) (⚠️): Imperva’s customizable API attack tool takes an API specification as an input, generates and runs attacks that are based on it as an output.
* [CATS](https://github.com/Endava/cats): CATS is a REST API Fuzzer and negative testing tool for OpenAPI endpoints.
* [Cherrybomb](https://github.com/blst-security/cherrybomb): Stop half-done API specifications with a CLI tool that helps you avoid undefined user behaviour by validating your API specifications.
* [ffuf](https://github.com/ffuf/ffuf): Fast web fuzzer written in Go.
* [fuzzapi](https://github.com/Fuzzapi/fuzzapi) (⚠️): Fuzzapi is a tool used for REST API pentesting anTnT-Fuzzerd uses API\_Fuzzer gem.
* [gotestwaf](https://github.com/wallarm/gotestwaf): An open-source project in Golang to test different web application firewalls (WAF) for detection logic and bypasses.
* [kiterunner](https://github.com/assetnote/kiterunner) (⚠️): Contextual Content Discovery Tool.
* [Metlo](https://github.com/metlo-labs/metlo) | [Open-source API security tool](https://metlo.com/): to discover, inventory, test, and protect your APIs.
* [mitmproxy2swagger](https://github.com/alufers/mitmproxy2swagger): Automagically reverse-engineer REST APIs via capturing traffic.
* [Optic](https://github.com/opticdev/optic): Verify the accuracy of your OpenAPI 3.x spec using real traffic and automatically apply patches that keep it up-to-date.
* [RESTler](https://github.com/microsoft/restler-fuzzer): RESTler is the first stateful REST API fuzzing tool for automatically testing cloud services through their REST APIs and finding security and reliability bugs in these services.
* [Swagger-EZ](https://github.com/RhinoSecurityLabs/Swagger-EZ): A tool geared towards pentesting APIs using OpenAPI definitions.
* [TnT-Fuzzer](https://github.com/Teebytes/TnT-Fuzzer) (⚠️): OpenAPI 2.0 (Swagger) fuzzer written in python. Basically TnT for your API.
* [wadl-dumper](https://github.com/dwisiswant0/wadl-dumper): Dump all available paths and/or endpoints on WADL file.
* [fuzz-lightyear](https://github.com/Yelp/fuzz-lightyear) (⚠️): A pytest-inspired, DAST framework, capable of identifying vulnerabilities in a distributed, micro-service ecosystem through chaos engineering testing and stateful, Swagger fuzzing.

### Books

* [API Security for dummies](https://query.prod.cms.rt.microsoft.com/cms/api/am/binary/RWJ9kN): This book is a high-level introduction to the key concepts of API security and DevSecOps.&#x20;
* [API Security in Action](https://www.manning.com/books/api-security-in-action): API Security in Action teaches you how to create secure APIs for any situation.&#x20;
* [Black Hat GraphQL](https://nostarch.com/black-hat-graphql): Black Hat GraphQL book.&#x20;
* [Hacking APIs](https://nostarch.com/hacking-apis): Breaking Web Application Programming Interfaces.
* [Understanding API Security](https://livebook.manning.com/book/understanding-api-security/introduction/): Several chapters from several Manning books that give you some context for how API security works in the real world.
* [RESTful API Design: Best Practices in API Design with REST](https://www.amazon.in/dp/B01L6STMVW?ref=KC\_GS\_GB\_IN): A book focusing on RESTful API design principles, including security considerations, by Matthias Biehl.
* [OAuth 2.0: Getting Started in API Security](https://www.amazon.in/OAuth-2-0-Getting-Security-University/dp/1507800916): A practical guide to OAuth 2.0 and API security by Matthias Biehl.
* [GraphQL in Action](https://www.manning.com/books/graphql-in-action): A book covering GraphQL API design, development, and security best practices by Samer Buna.
* [Practical API Architecture and Development with Azure and AWS](https://www.amazon.in/Practical-Architecture-Development-Azure-Implementation/dp/1484235541): A book on API architecture and development, including security considerations, for both Azure and AWS by Thurupathan Vijayakumar.
* [API Management: An Architect’s Guide to Developing and Managing APIs for Your Organization](https://www.amazon.com/API-Management-Architects-Developing-Organization/dp/1484213068): A book by Brajesh De that includes API security aspects and best practices.
* [Advanced API Security: OAuth 2.0 and Beyond](https://www.amazon.in/Advanced-API-Security-OAuth-Beyond-ebook/dp/B082WRYJJM/ref=sr\_1\_2?qid=1683721842\&s=books\&sr=1-2): A book by Prabath Siriwardena that focuses on OAuth 2.0 and OpenID Connect protocols for API security.

### Videos & presentations

#### YouTube Playlists

* [API Security: What & How?](https://youtube.com/playlist?list=PLKUnjn-fSXRTy8sPPXGrNNBDPVOOi3U49)
* [Everything API Hacking](https://youtube.com/playlist?list=PLbyncTkpno5HqX1h2MnV6Qt4wvTb8Mpol)
* [OWASP API Security Top 10](https://www.youtube.com/playlist?list=PLyqga7AXMtPOguwtCCXGZUKvd2CDCmUgQ)
* [API Security deep dive](https://youtube.com/playlist?list=PLiUwrB-tuUUpJIQxo4qqHWKJBfFCTeqh9)
* [REST API Security](https://youtube.com/playlist?list=PLSId5Ee-5md9FdqzaLrnB30k7Z4YPjBAk)
* [API security](https://youtube.com/playlist?list=PL4HR6c9eR2yLnBYYwZqhwiV4rhRN1S8f5)
* [API Security 101: Talks](https://youtube.com/playlist?list=PLwfL2EOOZ36weMxjo1Wk7bV4TFP08HBj9)
* [API Security in Microservice world](https://youtube.com/playlist?list=PLV47o9J4XHfmTL99nc2b4k-SPSVBF9MIq)
* [API Security essentials](https://youtube.com/playlist?list=PL8IDSDRZxCCANEpMNtod31YOI1JpB30Qt)
* [Understanding OAuth & API security](https://youtube.com/playlist?list=PLxeJU39M7tLG1-3UAa1\_90YgN9\_1bDag4)

#### Other videos & presentations

* [pentesting-rest-apis](https://www.slideshare.net/OWASPdelhi/pentesting-rest-apis-by-gaurang-bhatnagar): Pentesting Rest API’s by Gaurang Bhatnagar.
* [Securing your APIs](https://owasp.org/www-chapter-singapore/assets/presos/Securing\_your\_APIs\_-\_OWASP\_API\_Top\_10\_2019,\_Real-life\_Case.pdf): “How Secure are you APIs?” - Securing your APIs: OWASP API Top 10 2019, Case Study and Demo.
* [api-security-testing-for-hackers](https://www.bugcrowd.com/resources/webinars/api-security-testing-for-hackers): API Security Testing For Hackers.
* [bad-api-hapi-hackers](https://www.bugcrowd.com/resources/webinars/bad-api-hapi-hackers): Bad API, hAPI Hackers!
* [disclosing-information-via-your-apis](https://www.bugcrowd.com/resources/webinars/hidden-in-plain-site-disclosing-information-via-your-apis/): Hidden in Plain Site: Disclosing Information via Your APIs.
* [rest-in-peace-abusing-graphql](https://www.bugcrowd.com/resources/webinars/rest-in-peace-abusing-graphql-to-attack-underlying-infrastructure): REST in Peace: Abusing GraphQL to Attack Underlying Infrastructure.
* [Everything API Hacking](https://www.youtube.com/playlist?list=PLbyncTkpno5HqX1h2MnV6Qt4wvTb8Mpol): A video collection from Katie Paxton-Fear, @InsiderPhD, and other people creating a playlist of API hacking knowledge!
* [API hacking](https://www.youtube.com/c/TheXSSrat/search?query=API%20hacking): API hacking videos from @theXSSrat.

### Specifications

* [API Blueprint](https://apiblueprint.org/documentation/specification.html): API Blueprint Specification.
* [AscyncAPI](https://www.asyncapi.com/docs/specifications/latest): AsyncAPI Specification.
* [OpenAPI](https://swagger.io/specification/): OpenAPI Specification.
* [JSON API](https://jsonapi.org/format/): JSON API Specification.
* [GraphQL](https://spec.graphql.org/): GraphQL Specification.
* [RAML](https://github.com/raml-org/raml-spec): RAML Specification.
* [JSON Web Tokens (JWT)](https://jwt.io/introduction): A compact, URL-safe means of representing claims to be transferred between parties.
* [OAuth 2.0](https://oauth.net/2/): A widely-adopted authorization framework for securing API access.
* [OpenID Connect](https://openid.net/connect/): An identity layer built on top of OAuth 2.0 for authentication and single sign-on.
* [HAL (Hypertext Application Language)](http://stateless.co/hal\_specification.html): A standard for describing RESTful APIs using hypermedia.
* [WS-Security](https://www.oasis-open.org/committees/tc\_home.php?wg\_abbrev=wss): A set of specifications for securing SOAP-based web services.

### Learning

* [Know your HTTP Headers!](http://prezo.s3.amazonaws.com/pixi\_california\_2018/basics/headers.pdf): HTTP Headers: a simplified and comprehensive table.
* [Know your HTTP Status codes!](http://prezo.s3.amazonaws.com/pixi\_california\_2018/basics/status-codes.pdf): HTTP Status codes: a simplified and comprehensive table.
* [HTTP Status Codes](https://httpstatuses.com/): is an easy to reference database of HTTP Status Codes with their definitions and helpful code references all in one place.
* [Know your HTTP \* Well](https://github.com/for-GET/know-your-http-well): HTTP headers, media-types, methods, relations and status codes, all summarized and linking to their specification.

#### Learning Path

| **Topic**                                  | **Resources**                                                                                                                     |
| ------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------- |
| Understanding APIs and their importance    | [What is an API?](https://www.freecodecamp.org/news/what-is-an-api-in-english-please-b880a3214a82/)                               |
|                                            | [RESTful API Design](https://restfulapi.net/)                                                                                     |
| API Security Basics                        | [Why is API Security Important?](https://www.indusface.com/blog/what-is-api-security-and-why-is-it-important/)                    |
|                                            | [API Security: Challenges and Solutions](https://www.cloudflare.com/learning/security/api/what-is-api-security/)                  |
| Authentication and Authorization           | [Introduction to OAuth 2.0](https://www.digitalocean.com/community/tutorials/an-introduction-to-oauth-2)                          |
|                                            | [Understanding JSON Web Tokens (JWT)](https://jwt.io/introduction/)                                                               |
| API Security Best Practices                | [API Security Best Practices](https://blogs.mulesoft.com/api-integration/api-security-threats-best-practices-solutions/)          |
|                                            | [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)                                                          |
| Rate Limiting and Throttling               | [Rate Limiting in APIs](https://www.cloudflare.com/learning/bots/what-is-rate-limiting/)                                          |
|                                            | [Throttling in APIs](https://www.tibco.com/reference-center/what-is-api-throttling)                                               |
| Input Validation and Sanitization          | [Input Validation for APIs](https://cheatsheetseries.owasp.org/cheatsheets/Input\_Validation\_Cheat\_Sheet.html)                  |
| Transport Security                         | [Transport Security in APIs](https://developer.okta.com/books/api-security/tls/)                                                  |
|                                            | [Using HTTPS for API Security](https://www.cloudflare.com/learning/ssl/why-use-https/)                                            |
| API Security Testing                       | [API Security Testing](https://www.soapui.org/learn/security/)                                                                    |
|                                            | [Top 10 API Security Testing Tools](https://www.techtarget.com/searchsecurity/tip/10-API-security-testing-tools-to-mitigate-risk) |
| Project 1 - Building a Secure RESTful API  | [Tutorial: Build a Secure RESTful API](https://www.toptal.com/nodejs/secure-rest-api-in-nodejs)                                   |
| Project 2 - Implementing OAuth 2.0 and JWT | [Tutorial: Implement OAuth 2.0 and JWT](https://auth0.com/docs/quickstart/backend/nodejs)                                         |
| Project 3 - API Security Audit             | [API Security Audit Checklist](https://github.com/shieldfy/API-Security-Checklist)                                                |

#### Workshops & labs

* [API security, REST Labs](https://attackdefense.pentesteracademy.com/listing?labtype=rest\&subtype=rest-api-security): Pentester Academy - attack & defense.
* [API Security University](https://university.apisec.ai/): APIsec University provides training courses for application security professionals.
* [BankGround API](https://apimate.eu/bankground.html): Banking-like REST and GraphQL API for training/learning purposes.
* [GraphQL challenges](https://www.hackerone.com/ethical-hacker/graphql-week-hacker101-capture-flag-challenges): GraphQL Week on The Hacker101 Capture the Flag Challenges.
* [GraphQL Labs](https://demo.securityknowledgeframework.org/labs/view): GraphQL Labs on the OWASP Security Knowledge Framework.
* [Hacking APIs](https://sway.office.com/HVrL2AXUlWGNDHqy): Hacking APIs: workshop.
* [OWASP Top 10 for API](https://application.security/free/owasp-top-10-API): Is a series of free interactive application security training modules that teach developers how to identify and mitigate security vulnerabilities in their web API endpoints.
* [Practical API Security Walkthrough](https://github.com/approov/shipfast-api-protection): Learn practical Mobile and API security techniques: API Key, Static and Dynamic HMAC, Dynamic Certificate Pinning, and Mobile App Attestation.

#### Fuzzing and others

* [API names wordlist](https://github.com/chrislockard/api\_wordlist): A wordlist of API names for web application assessments.
* [API HTTP requests methods](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/http-request-methods.txt): HTTP requests methods wordlist by @danielmiessler.
* [API Routes Wordlists](https://github.com/assetnote/wordlists/blob/master/data/automated.json): API Routes - Automated Wordlists provided by Assetnote.
* [Common API endpoints](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/common-api-endpoints-mazen160.txt) (⚠️): Wordlist for common API endpoints.
* [Filenames by fuzz.txt](https://github.com/Bo0oM/fuzz.txt): Potentially dangerous files.
* [Fuzzing APIs](https://www.fuzzingbook.org/html/APIFuzzer.html): Fuzzing APIs chapter from “The Fuzzing Book”.
* [GraphQL SecList](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/graphql.txt) (⚠️): It’s a GraphQL list used during security assessments, collected in one place.
* [Hacking-APIs](https://github.com/hAPI-hacker/Hacking-APIs): Wordlists and API paths by @hapi\_hacker.
* [Kiterunner Wordlists](https://github.com/assetnote/wordlists/blob/master/data/kiterunner.json) (⚠️): Kiterunner Wordlists provided by Assetnote.
* [List of API endpoints & objects](https://gist.github.com/yassineaboukir/8e12adefbd505ef704674ad6ad48743d): A list of common API endpoints and objects designed for fuzzing.
* [List of Swagger endpoints](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/swagger.txt): Swagger endpoints.
* [SecLists for API’s web-content discovery](https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content/api): It is a collection of web content discovery lists for APIs used during security assessments.

#### Vulnerable APIs to learn

* [APISandbox](https://github.com/API-Security/APISandbox): Pre-Built Vulnerable Multiple API Scenarios Environments Based on Docker-Compose.
* [Bookstore](https://tryhackme.com/room/bookstoreoc): TryHackMe room - A Beginner level box with basic web enumeration and REST API Fuzzing.
* [crAPI](https://github.com/OWASP/crAPI): completely ridiculous API (crAPI)
* [Damn-Vulnerable-GraphQL-Application](https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application):  Damn Vulnerable GraphQL Application is intentionally vulnerable implementation of Facebook’s GraphQL technology to learn and practice GraphQL Security.
* [Damn Vulnerable Micro Services](https://github.com/ne0z/DamnVulnerableMicroServices) (⚠️): This is a vulnerable microservice written in many languages to demonstrating OWASP API Top Security Risk (under development).
* [Damn Vulnerable Web Services](https://github.com/snoopysecurity/dvws-node): Damn Vulnerable Web Services is a vulnerable web service/API/application that we can use to learn webservices/API vulnerabilities.
* [Generic-University](https://github.com/InsiderPhD/Generic-University): Vulnerable API with Laravel App.
* [node-api-goat](https://github.com/layro01/node-api-goat): A simple Express.JS REST API application that exposes endpoints with code that contains vulnerabilities.
* [Pixi](https://github.com/DevSlop/Pixi) (⚠️): The Pixi module is a MEAN Stack web app with wildly insecure APIs!
* [REST API Goat](https://github.com/optiv/rest-api-goat) (⚠️): This is a “Goat” project so you can get familiar with REST API testing.
* [VAmPI](https://github.com/erev0s/VAmPI): Vulnerable REST API with OWASP top 10 vulnerabilities for APIs.
* [vAPI](https://github.com/roottusk/vapi): vAPI is Vulnerable Adversely Programmed Interface which is Self-Hostable API that mimics OWASP API Top 10 scenarios through Exercises.
* [vulnapi](https://github.com/tkisason/vulnapi): Intentionaly very vulnerable API with bonus bad coding practices.
* [vulnerable-graphql-api](https://github.com/CarveSystems/vulnerable-graphql-api) (⚠️): A very vulnerable implementation of a GraphQL API.
* [Websheep](https://github.com/marmicode/websheep): Websheep is an app based on a willingly vulnerable ReSTful APIs.
* [DVNA](https://github.com/appsecco/dvna) (⚠️): Damn Vulnerable Node.js Application with insecure APIs.
* [WebGoat](https://github.com/WebGoat/WebGoat): A deliberately insecure web app for security training.
* [Juice Shop](https://github.com/juice-shop/juice-shop): A modern, intentionally insecure web application
* [Gruyere](https://google-gruyere.appspot.com/): A web application with security holes used for training.
* [Railsgoat](https://github.com/OWASP/railsgoat): A vulnerable Ruby on Rails application for learning security.
* [Mutillidae](https://github.com/webpwnized/mutillidae): A deliberately vulnerable set of PHP scripts.
* [NodeGoat](https://github.com/OWASP/NodeGoat): A Node.js/Express app with security vulnerabilities.
* [Hackazon](https://github.com/Rapid7/hackazon) (⚠️): A modern, vulnerable e-commerce web app.
* [GoatDroid](https://github.com/jackMannino/OWASP-GoatDroid-Project) (⚠️): A vulnerable Android app with insecure APIs.
* [AltoroJ](http://www.altoromutual.com/): A vulnerable Java web app for learning application security.
* [Hackademic](https://github.com/Hackademic/hackademic) (⚠️): A vulnerable web app to learn and practice web application security.

#### Others

* [The API Specification Toolbox](http://api.specificationtoolbox.com/): This Toolbox goal is to try and map out all of the different API specifications in use, as well as the services, tooling, extensions, and other supporting elements.
* [Understanding gRPC, OpenAPI and REST](https://cloud.google.com/blog/products/api-management/understanding-grpc-openapi-and-rest-and-when-to-use-them): gRPC vs REST: Understanding gRPC, OpenAPI and REST and when to use them in API design.
* [API security design best practices](https://habr.com/en/post/595075/): API security design best practices for enterprise and public cloud.
* [REST API Design Guide](https://www.apiopscycles.com/resources/rest-api-design-guide): This design guide or style guide contains best practices suitable for most REST APIs.
* [How to design a REST API](https://blog.octo.com/en/design-a-rest-api): How to design a REST API? - Full guide tackling security, pagination, filtering, versioning, partial answers, CORS, etc.
* [Awesome REST](https://github.com/marmelab/awesome-rest): A collaborative list of great resources about RESTful API architecture, development, test, and performance. Feel free to contribute to this ongoing list.
* [Collect API Requirements](https://www.apiopscycles.com/collecting-requirements): Collecting Requirements for your API with APIOps Cycles.
* [API Audit](https://www.apiopscycles.com/method/api-audit): API Audit is a method to ensure APIs are matching the API Design guidelines. It also helps check for usability, security and API management platform compatibility

### Podcasts

* [The Secure Developer](https://www.heavybit.com/library/podcasts/the-secure-developer/): A podcast that discusses security best practices for developers, including API security topics.
* [Application Security Weekly](https://securityweekly.com/shows/appsec-weekly/): A weekly podcast covering application security news, including API security updates.
* [The New Stack Podcast](https://thenewstack.io/podcasts/): A podcast that covers various technology topics, occasionally featuring API security discussions.
* [The CyberWire Daily Podcast](https://thecyberwire.com/podcasts/daily-podcast): A daily cybersecurity news podcast that occasionally discusses API security.
* [Security Now](https://twit.tv/shows/security-now): A weekly podcast discussing a wide range of security topics, including API security.
* [Darknet Diaries](https://darknetdiaries.com/): A podcast that tells true stories from the dark side of the internet, occasionally featuring episodes about API security incidents.
* [Risky Business](https://risky.biz/netcasts/risky-business/): A podcast that covers information security news and events, sometimes discussing API security.
* [Smashing Security](https://www.smashingsecurity.com/): A cybersecurity podcast that occasionally discusses API security topics.
* [The Privacy, Security, & OSINT Show](https://inteltechniques.com/podcast.html): A podcast focusing on privacy, security, and open-source intelligence topics, occasionally featuring API security discussions.
* [Hacking APIs](https://forallsecure.com/blog/the-hacker-mind-podcast-hacking-apis): The Hacker Mind Podcast: Hacking APIs.
* [Hack Your API-Security Testing](https://testguild.com/podcast/automation/21-troy-hunt-hack-your-api-security-testing/): 21: Troy Hunt: Hack Your API-Security Testing.
* [Episode 38 API Security Best Practices](https://wehackpurple.com/podcast/episode-38-api-security-best-practices/): We Hack Purple Podcast Episode 38 API Security Best Practices.

### Wikis & Collections

* [OWASP API Security Project](https://owasp.org/www-project-api-security/): An OWASP project that provides resources and guidelines on API security.
* [API Security Encyclopedia](https://www.apisecurity.io/encyclopedia/): A comprehensive encyclopedia of API security terms and concepts.
* [API Security on Infosec](https://www.infosecinstitute.com/topics/api-security/): A collection of API security articles and resources by Infosec Institute.
* [API Security on DZone](https://dzone.com/security): A collection of API security articles, tutorials, and news on DZone.
* [API Security on Medium](https://medium.com/tag/api-security): A collection of API security articles and stories on Medium, contributed by various authors.
* [API Security on Hacker Noon](https://hackernoon.com/tagged/api-security): A collection of API security articles on Hacker Noon, contributed by various authors.
* [API Security on Dev.to](https://dev.to/t/apisecurity): A collection of API security articles, tutorials, and discussions on [Dev.to](http://dev.to/).

#### **Mind maps:**

* [API Pentesting - ATTACK](https://github.com/cyprosecurity/API-SecurityEmpire/blob/main/assets/API%20Pentesting%20Mindmap%20ATTACK.pdf): Mind map: API Pentesting - ATTACK.
* [API Pentesting - Recon](https://github.com/cyprosecurity/API-SecurityEmpire/blob/main/assets/API%20Pentesting%20Mindmap.pdf): Mind map: API Pentesting - Recon.
* [GraphQL Attacking](https://github.com/cyprosecurity/API-SecurityEmpire/blob/main/assets/API%20Pentesting%20Mindmap%20%7B%7BGraphQL%20Attacking%7D%7D.pdf): Mind map: GraphQL Attacking.
* [IDOR Techniques](https://www.xmind.net/m/CSKSWZ/): Mind map: IDOR Techniques.
* [MindAPI](https://dsopas.github.io/MindAPI/play/): Organize your API security assessment by using MindAPI.
* [XML attacks](https://www.xmind.net/m/xNEY9b/): Mind map: XML attacks.
* [REST API defenses](https://mobile.twitter.com/abhaybhargav/status/1373982049019654149/photo/1): Mind map: REST API defenses.
* [REST API Security Mind Map](https://www.mindmeister.com/555874413/rest-api): A mind map that covers key security aspects of RESTful APIs.
* [OAuth 2.0 Mind Map](https://luisfsgoncalves.wordpress.com/2016/06/26/oauth-2-0-mind-map/): A visual representation of OAuth 2.0 concepts and components, which are crucial for API security.
* [API Security Testing Mind Map](https://media-exp1.licdn.com/dms/document/C561FAQFMUiAa5fYPhg/feedshare-document-pdf-analyzed/0/1649057128703?e=2147483647\&v=beta\&t=2MXCYdO\_Lpeq1vXOFgwr4exZT-gw16kAhaGG9ZapsH4): A mind map that provides an overview of API security testing concepts and techniques.
* [API Management Mind Map](https://media-exp1.licdn.com/dms/document/C561FAQFMUiAa5fYPhg/feedshare-document-pdf-analyzed/0/1649057128703?e=2147483647\&v=beta\&t=2MXCYdO\_Lpeq1vXOFgwr4exZT-gw16kAhaGG9ZapsH4): A mind map covering various aspects of API management, including security considerations.
* [Web Services Security Mind Map](https://github.com/nmmcon/MindMaps/blob/532ee4a6ecfad1c7df3cc186b0538477d9e838d8/WebApplicationVulnerabilities.png): A mind map that delves into security aspects of web services, including APIs.

#### Books, collections:

* [APIs Pentest Book](https://pentestbook.six2dez.com/enumeration/webservices/apis): APIs Pentest Book.
* [API Pentest tips](https://csbygb.gitbook.io/pentips/web-pentesting/api): CSbyGB’s Pentips.
* [API Security Empire](https://github.com/cyprosecurity/API-SecurityEmpire): The API Security Empire Project aims to present unique attack & defense methods in the API Security field.
* [API Security Encyclopedia](https://apisecurity.io/encyclopedia/content/api-security-encyclopedia.htm): API Security Encyclopedia.
* [Web API Pentesting](https://book.hacktricks.xyz/pentesting/pentesting-web/web-api-pentesting): HackTricks - Web API Pentesting.
* [GraphQL](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/graphql): HackTricks - GraphQL.

### Newsletters

* [The Hacker News](https://thehackernews.com/search/label/API%20Security): A blog and newsletter that covers various API topics, including security.
* [API Evangelist](http://apievangelist.com/): A blog and newsletter by Kin Lane that covers various API topics, including security.
* [The New Stack](https://thenewstack.io/): A platform for news and analysis on various technology topics, including API security. Subscribe to their newsletter for regular updates.
* [Secjuice](https://www.secjuice.com/): A cybersecurity publication with a dedicated section for API security articles. Subscribe to their newsletter for updates.
* [Security Weekly](https://securityweekly.com/): A cybersecurity podcast network and newsletter that occasionally covers API security topics.
* [StatusCode Weekly](https://webopsweekly.com/): A weekly newsletter that covers web operations and occasionally includes API security articles.
* [api security articles](https://apisecurity.io/#newsletter1): API Security Articles - The Latest API Security News, Vulnerabilities & Best Practices.

### Conferences

* [APIsecure](https://apisecure.co/): The world’s first conference dedicated to API threat management; bringing together breakers, defenders, and solutions in API security.

### Others

* [awesome-security-apis](https://github.com/jaegeral/security-apis): A collective list of public JSON APIs for use in security.
* [API Hacking Articles](https://danaepp.com/blog): API Hacking Fundamentals, Tools, Techniques, Fails and Mindset articles.
* [API Security: The Complete Guide](https://brightsec.com/blog/api-security): API Security, The Complete Guide.
* [API Penetration Testing](https://blog.securelayer7.net/api-penetration-testing-with-owasp-2017-test-cases): API Penetration Testing with OWASP 2017 Test Cases.
* [API Penetration Testing Report](https://underdefense.com/wp-content/uploads/2019/05/Anonymised-API-Penetration-Testing-Report.pdf): Anonymised API Penetration Testing Report - vendor sample template.
* [API Pentesting with Swagger Files](https://rhinosecuritylabs.com/application-security/simplifying-api-pentesting-swagger-files/): Simplifying API Pentesting With Swagger Files.
* [API security path resources](https://dsopas.github.io/MindAPI/references/): Resources to help out in the API security path; diverse content from talks/webinards/videos, must read, writeups, bola/idors, oauth, jwt, rate limit, ssrf and practice entries.
* [API Security Testing](https://sphericaldefence.com/api-security-testing): Principles of API Security Testing and how to perform a Security Test on an API.
* [Finding and Exploiting Web App APIs](https://bendtheory.medium.com/finding-and-exploiting-unintended-functionality-in-main-web-app-apis-6eca3ef000af): Finding and Exploiting Unintended Functionality in Main Web App APIs.
* [How to Hack an API and Get Away with It](https://smartbear.com/blog/test-and-monitor/api-security-testing-how-to-hack-an-api-part-1/): How to Hack an API and Get Away with It (Part 1 of 3).&#x20;
* [How to Hack APIs in 2021](https://labs.detectify.com/2021/08/10/how-to-hack-apis-in-2021): How to Hack APIs in 2021.
* [How to Hack API in 60 minutes with Open Source Tools](https://www.wallarm.com/what/how-to-hack-api-in-60-minutes-with-open-source): How to Hack API in 60 minutes with Open Source Tools.
* [GraphQL penetration testing](https://blog.yeswehack.com/yeswerhackers/how-exploit-graphql-endpoint-bug-bounty/): How to exploit GraphQL endpoint: introspection, query, mutations & tools.
* [Fixing the 13 most common GraphQL Vulnerabilities](https://wundergraph.com/blog/the\_complete\_graphql\_security\_guide\_fixing\_the\_13\_most\_common\_graphql\_vulnerabilities\_to\_make\_your\_api\_production\_ready): GraphQL Security Guide, Fixing the 13 most common GraphQL Vulnerabilities to make your API production ready.
* [Hacking APIs - Notes from Bug Bounty Bootcamp](https://attacker-codeninja.github.io/2021-08-28-Hacking-APIs-notes-from-bug-bounty-bootcamp/): My Notes on Hacking APIs from Bug Bounty Bootcamp.
* [SOAP Security Vulnerabilities and Prevention](https://www.neuralegion.com/blog/top-7-soap-api-vulnerabilities/): SOAP Security, Top Vulnerabilities and How to Prevent Them.
* [API and microservice security](https://portswigger.net/burp/vulnerability-scanner/api-security-testing/guide-to-api-microservice-security): What are API and microservice security?
* [Strengthening Your API Security Posture](https://42crunch.com/knowledge-series/strengthening-api-security-posture/): Strengthening Your API Security Posture – Ford Motor Company.

## Sources

\[1]: [OWASP API Security Project | OWASP Foundation](https://owasp.org/www-project-api-security/)

\[2]: [JBAhire/awesome-api-security-essentials: Awesome API Security: A Curated Collection of Resources for Bulletproof API Protection! (github.com)](https://github.com/JBAhire/awesome-api-security-essentials)

\[3]: [arainho/awesome-api-security: A collection of awesome API Security tools and resources. The focus goes to open-source tools and resources that benefit all the community. (github.com)](https://github.com/arainho/awesome-api-security)

\[4]: [shieldfy/API-Security-Checklist: Checklist of the most important security countermeasures when designing, testing, and releasing your API (github.com)](https://github.com/shieldfy/API-Security-Checklist)
