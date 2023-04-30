---
description: >-
  "DevSec" is a derived name from "DevSecOps" and "SecDevOps", a idea to
  aggregate all things related to a secure development & operations (always from
  the DEV perspective).
---

# DevSec

**Welcome to the page where you will find all security related topics/tools/techniques made by developers for developers concerned about security.**

This page is intended as an always updated source for devs, inspired in the work of ["HackTricks"](https://book.hacktricks.xyz/), to serve as a reference for a secure development and related operations.

### Introduction

You may heard about **DevSecOps**, the **shifting left** concept and **GitOps**...\[1] They all share a lot of principles, **reduce the time devs spend on security while achieving their objectives.**

With **DevOps**, we shifted to make developers more accountable for operational topics and issues (joining the responsability of development and operations). Here the same mindset is meant to be done with Security in DevSecOps.

In lots of products or projects we are already shifting left a lot of controls earlier in the development lifecycle, where the development teams are (such as testing)... So why not including security testing to an earlier step? We could make fewer mistakes, and we can move more quickly (quickly addressing newly discovered vulnerabilities and fixing them).

**This is a process change, it's not about a single/specific tool or controls. It's about making all of security more developer-centric.**

### **State of security**

<table data-view="cards"><thead><tr><th></th><th></th><th></th></tr></thead><tbody><tr><td></td><td><strong>$4.35M is the global average total cost of a data breach</strong> [2]</td><td></td></tr><tr><td></td><td>Platforms such as GitHub are seeing <strong>more credential leaks than ever</strong> [3]</td><td></td></tr><tr><td>There are lot of dependencies in our projects. It's estimated that <strong>about a 80-90% of a codebase is made of dependencies</strong> [4]</td><td></td><td></td></tr><tr><td><strong>Remediation costs</strong> are always lower in early stages of development</td><td></td><td></td></tr></tbody></table>

### Sources

1. [GitHub Blog - Secure at every step: A guide to DevSecOps, shifting left, and GitOps](https://github.blog/2020-08-13-secure-at-every-step-a-guide-to-devsecops-shifting-left-and-gitops/)
2. [IBM - Cost of a data breach 2022](https://www.ibm.com/reports/data-breach)
3. [GitHub Blog - Leaked a secret? Check your GitHub alerts…for free](https://github.blog/2022-12-15-leaked-a-secret-check-your-github-alerts-for-free/)
4. [debricked blog - Vulnerabilities in Dependencies, Third Party Components and Open Source: What you need to know](https://debricked.com/blog/vulnerabilities-dependencies/)

### License

Copyright (c) 2023 Raul Piraces Alastuey. This entire page and its contents are licensed under the MIT License.

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
