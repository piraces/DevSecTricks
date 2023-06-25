---
description: >-
  "DevSec", "DevSecOps", "SecDevOps"...  lots of buzzwords, but here the idea is
  to aggregate all things related to a secure development & operations (always
  from the DEV perspective).
---

# DevSec

**Welcome to the page where you will find all security related topics/tools/techniques made by developers for developers concerned about security.**

This page is intended as an always updated source for devs, inspired in the work of ["HackTricks"](https://book.hacktricks.xyz/), to serve as a reference for a secure development and related operations. Lots of references/resources in this page are extracted from other public sources, all credit to the **original authors (that will be referenced as sources).**

{% hint style="info" %}
🚧 Please note that this is now under heavy development so expect some sections to have little/no content 🚧
{% endhint %}

### Introduction

You may heard about **DevSecOps**, the **shifting left** concept and **GitOps**...\[1] They all share a lot of principles, **reduce the time devs spend on security while achieving their objectives.**

With **DevOps**, we shifted to make developers more accountable for operational topics and issues (joining the responsability of development and operations). Here the same mindset is meant to be done with Security in DevSecOps.

In lots of products or projects we are already shifting left a lot of controls earlier in the development lifecycle, where the development teams are (such as testing)... So why not including security testing to an earlier step? We could make fewer mistakes, and we can move more quickly (quickly addressing newly discovered vulnerabilities and fixing them).

The overall aim is to create a culture where everyone is responsible for security, reducing the risk of security issues and allowing teams to deliver secure, high-quality software more quickly.

**This is a process change, it's not about a single/specific tool or controls. It's about making all of security more developer-centric.**

### Sources and links

1. [GitHub Blog - Secure at every step: A guide to DevSecOps, shifting left, and GitOps](https://github.blog/2020-08-13-secure-at-every-step-a-guide-to-devsecops-shifting-left-and-gitops/)
2. [IBM - Cost of a data breach 2022](https://www.ibm.com/reports/data-breach)
3. [GitHub Blog - Leaked a secret? Check your GitHub alerts…for free](https://github.blog/2022-12-15-leaked-a-secret-check-your-github-alerts-for-free/)
4. [debricked blog - Vulnerabilities in Dependencies, Third Party Components and Open Source: What you need to know](https://debricked.com/blog/vulnerabilities-dependencies/)

### Digital preservation

Due to the large amount of information and external links that could be stored in this "book", there is a daily process based in GitHub Actions ([see the action](https://github.com/piraces/DevSecTricks/actions/workflows/digital-preservation.yml)) that archives in the [Internet Archive](https://archive.org/) all pages with the external links too.

This process allows us to always make available these pages and every referenced page in them, accesible and navigable at any time with multiple "versions" or snapshots.

So do not worry if a link goes down, a blog post gets deleted, some repository is made private or not available any more, we have all covered.

If you find yourself in that situation you can access the page by entering the following URL in your browser:

```
https://web.archive.org/{URL}
```

Where {URL} is the raw URL you are trying to access.

You can also use the [Wayback Machine UI](https://web.archive.org/) directly.

Please, if you find these functionality useful, consider [donating to the Internet Archive](https://archive.org/donate) (they do a very great work).

### License

**Copyright (c) 2023 Raúl Piracés Alastuey.** **Except where otherwise specified (the external information copied into the book belongs to the original authors), the text on** [**DevSecTricks**](https://github.com/piraces/DevSecTricks) **by Raúl Piracés is licensed under the**[ **Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**](https://creativecommons.org/licenses/by-nc/4.0/) **.**\
**If you want to use it with commercial purposes, contact me.**

### Disclaimer

{% hint style="info" %}
This page is intended for educational and informational purposes only. The content within this book is provided on an 'as is' basis, and the authors and publishers make no representations or warranties of any kind, express or implied, about the completeness, accuracy, reliability, suitability, or availability of the information, products, services, or related graphics contained within this book. Any reliance you place on such information is therefore strictly at your own risk.

The authors and publishers shall in no event be liable for any loss or damage, including without limitation, indirect or consequential loss or damage, or any loss or damage whatsoever arising from loss of data or profits arising out of, or in connection with, the use of this book.

Furthermore, the techniques and tips described in this book are provided for educational and informational purposes only, and should not be used for any illegal or malicious activities. The authors and publishers do not condone or support any illegal or unethical activities, and any use of the information contained within this book is at the user's own risk and discretion.

The user is solely responsible for any actions taken based on the information contained within this book, and should always seek professional advice and assistance when attempting to implement any of the techniques or tips described herein.

By using this book, the user agrees to release the authors and publishers from any and all liability and responsibility for any damages, losses, or harm that may result from the use of this book or any of the information contained within it.provided on an 'as is' basis, and the authors and publishers make no representations or warranties of any kind, express or implied, about the completeness, accuracy, reliability, suitability, or availability of the information, products, services, or related graphics contained within this book. Any reliance you place on such information is therefore strictly at your own risk.

The authors and publishers shall in no event be liable for any loss or damage, including without limitation, indirect or consequential loss or damage, or any loss or damage whatsoever arising from loss of data or profits arising out of, or in connection with, the use of this book.

Furthermore, the techniques and tips described in this book are provided for educational and informational purposes only, and should not be used for any illegal or malicious activities. The authors and publishers do not condone or support any illegal or unethical activities, and any use of the information contained within this book is at the user's own risk and discretion.

The user is solely responsible for any actions taken based on the information contained within this book, and should always seek professional advice and assistance when attempting to implement any of the techniques or tips described herein.

By using this book, the user agrees to release the authors and publishers from any and all liability and responsibility for any damages, losses, or harm that may result from the use of this book or any of the information contained within it.
{% endhint %}

[![Creative Commons License](https://licensebuttons.net/l/by-nc/4.0/88x31.png)](https://creativecommons.org/licenses/by-nc/4.0/)
