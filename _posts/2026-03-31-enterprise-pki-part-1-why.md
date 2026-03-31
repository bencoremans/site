---
layout: post
title: "What I Learned Running Enterprise PKI"
date: 2026-03-31
categories: [pki, adcs, security]
tags: [ADCS, PKI, enterprise, certificate-authority]
author: Ben Coremans
published: true
---

# What I Learned Running Enterprise PKI

I've run enterprise Public Key Infrastructure in production for over ten years. A multi-tenant environment. Multiple organizational boundaries. Real compliance requirements. This is the kind of setup where mistakes are expensive and downtime is not an option.

This series shares what I learned.

Not what textbooks say. Not what vendor documentation recommends. I want to show what actually works when certificates are the backbone of authentication, encryption, and trust across a complex enterprise setup.

## Why Another PKI Series?

When I started deploying PKI, Vadim Podāns' deployment guide was my bible. It's still the best step-by-step Active Directory Certificate Services (ADCS) resource available. Clear. Full. Technically sound.

But guides are snapshots. They capture what made sense at the time they were written. Since then, a lot has changed:

- HSMs became accessible. What was enterprise-only hardware is now standard. Part 2 covers why HSM belongs in every deployment from day one.
- Certificate attacks matured. ESC1 through ESC7 are real threats, not theoretical.
- Automation evolved. YAML-driven deployments replaced manual scripts.
- OCSP reconsidered. Part 4 covers when OCSP makes sense in enterprise, and why conventional wisdom from 2018 no longer holds.
- Post-quantum looms. Not urgent, but planning starts now.

More importantly: production taught me things no guide can. The subtle interactions. The edge cases. Those "why didn't anyone mention this" moments that only surface when you're three years into operations.

That's what this series is about.

Here is a taste of what I mean. During a routine review, I found a typo in a CAPolicy.inf file: `PathLegth` instead of `PathLength`. ADCS never complained. No error, no warning. The CA installed and ran perfectly. The BasicConstraints PathLength=0 constraint, the one that prevents an Issuing CA from creating subordinate CAs, was simply never applied. That typo had survived five years of production operations, multiple administrators, and at least one external audit. Nobody noticed because ADCS silently ignores fields it does not recognize.

That is a production lesson. You will not find it in a lab.

## What You'll Learn

This isn't a beginner's tutorial. You should know what PKI is, why certificates matter, and have some Windows Server experience. If you've never heard of a Certificate Authority or don't know what TLS does, start elsewhere.

This series is for people deploying or operating enterprise PKI who want to learn from someone who's been there. No fluff, no filler.

**Part 1 (this article):** Context. Why this series exists and what it covers.

**Part 2 - Hierarchy & Planning:**
2-tier vs 3-tier. When a multi-tenant environment justifies the extra layer. Naming conventions that age well. HSM from day one, not as an afterthought. Root CA renewal strategy (plan it 5 years before expiration). Get your Certificate Policy OIDs wrong and you are re-issuing your Root CA.

**Part 3 - Cryptography in 2026:**
RSA 4096 is still fine. ECC is tempting but compatibility matters. Key lengths that matter (and the ones that don't). Why signature algorithm choice affects more than you think. Post-quantum readiness timeline.

**Part 4 - Revocation:**
Base CRL + Delta CRL: validity periods that balance security and performance. When OCSP makes sense in enterprise. OCSP stapling as a free performance boost. CRL partitioning for when 5MB CRLs become a problem.

**Part 5 - Templates:**
Why default templates are a security risk. Template versioning (V2 vs V3) and when V3 breaks .NET apps. TameMyCerts: practical ESC mitigation in production. Subject name validation strategies.

**Part 6 - Automation:**
From manual to YAML-driven deployments. Configuration validation: pre-flight checks, not post-failure fixes. Git-based audit trails for every config change. Why automation without verification is just faster mistakes.

**Part 7 - Monitoring & Auditing:**
Default auditing logs everything and tells you nothing. What to watch: issuance patterns, revocations, config changes, HSM operations. Real-time alerting that doesn't cry wolf. SIEM integration strategies.

**Part 8 - The Future:**
Windows Server 2025 features (partitioned CRLs, TLS 1.3). ACME for internal PKI. EST for mobile/IoT provisioning. Post-quantum migration roadmap: assessment, pilot, hybrid, full PQC.

## What This Series Is Not

**Not vendor-neutral theater.** I run Microsoft ADCS because it integrates with Active Directory and most enterprise environments already have it. The principles apply broadly, but examples are ADCS-specific.

**Not criticism of other guides.** Podāns' work is excellent. Keith Brown's writing is foundational. Brian Komar's book taught me CryptoAPI. This series stands on their shoulders.

**Not theoretically perfect.** I care about what works in production. Sometimes the "right" answer is impractical. I'll tell you what I chose and why.

**Not a sales pitch.** No vendor lock-in. No "buy my tooling." If there's a better way using open-source or different platforms, I'll say so.

## How Production Changes Your Perspective

When you deploy PKI in a lab, mistakes are cheap. Rebuild the VM. Start over. No one cares.

In production, mistakes compound:

- A certificate with the wrong EKU? That's six months of certificates you can't revoke cleanly.
- A misconfigured CAPolicy.inf? ADCS silently ignores unknown fields. No error, no warning. You won't know until an auditor checks the resulting certificate.
- A CRL that expires while you're on vacation? That's a Monday morning incident where nothing authenticates.

Production teaches you to validate before deploying. Test your backup restore procedure before you need it. Monitor CRL expiration with alerts set for 48 hours out, not 6.

It also teaches you what matters and what doesn't:

- Certificate lifetimes? Matter. A lot.
- SHA256 vs SHA384 for your hash algorithm? Doesn't matter. Both are fine.
- CRL publication interval? Matters. Get it wrong and you're either burning bandwidth or delaying revocation propagation.
- PKCS#1 v1.5 vs v2.1? Matters for compliance, doesn't matter for security in most cases.

## What's Different About This Series

Most PKI guides are either:

1. **Step-by-step tutorials.** Do this, then this, then this. Great for first deployment. Less useful when you hit edge cases.
2. **Reference documentation.** Technically accurate but assumes you already know what you're looking for.
3. **Vendor documentation.** Optimized for selling licenses, not operational reality.

This series is **experience-driven.**

I'll tell you what I deployed, why I chose it, what broke, and what I'd do differently next time. You'll see real configurations, real lessons, real trade-offs.

Some decisions were right. Some were wrong. Some were right at the time but wrong three years later when requirements changed.

You'll learn from both.

## Who This Is For

**You should read this series if:**

- You're deploying enterprise PKI for the first time and want to avoid common mistakes.
- You're operating existing PKI and wondering if you could do better.
- You're a security engineer tasked with auditing or modernizing PKI.
- You're preparing for compliance audits and need to understand what "best practice" actually means.

**You probably don't need this series if:**

- You've never heard of PKI and want an introduction. (Start with Wikipedia, then come back.)
- You're using a fully managed cloud PKI service with no control over configuration.
- You're deploying PKI in a small, isolated lab environment with no production dependencies. Just follow Podāns' guide.

## A Note on Confidentiality

I work in environments with strict confidentiality requirements. Organizational names, project details, network architecture, all of that stays private.

What I share is:

- **Architectural decisions.** Why we chose 3-tier over 2-tier, for example.
- **Technical configurations.** CAPolicy.inf examples, CRL validity periods, template settings.
- **Lessons learned.** What worked, what didn't, what surprised us.

All examples are generalized or anonymized. The principles are real. The specifics are sanitized.

## What's Next

Part 2 covers hierarchy planning. 2-tier vs 3-tier. When to add a middle layer (hint: multi-tenant scenarios). Naming conventions. HSM from the start. Root CA renewal strategy. And planning decisions like Name Constraints and EKU Qualified Subordination that you bake into the CA certificate at install time.

This series publishes weekly on LinkedIn. GitHub gets companion scripts and templates.

If you're responsible for enterprise PKI in 2026, follow along. Part 2 drops next week and goes straight into hierarchy decisions that most people get wrong.

---

**Sources:**
- Vadims Podāns (Crypt32): [ADCS Deployment Guide](https://habr-com.translate.goog/en/companies/microsoft/articles/348944/?_x_tr_sl=ru&_x_tr_tl=en&_x_tr_hl=en) (the guide that started it all - originally published in Russian on Habr)
- Vadims Podāns (Crypt32): [Blog](https://www.sysadmins.lv/) - PowerShell PKI module author and ADCS expert
- Vadims Podāns (Crypt32): [PSPKI - PowerShell PKI Module](https://github.com/Crypt32/PSPKI) - open-source ADCS management and automation
- Uwe Gradenegger (Sleepw4lker): [PKI and ADCS knowledge base](https://www.gradenegger.eu/en/) (the most comprehensive ADCS reference online)
- Uwe Gradenegger (Sleepw4lker), TameMyCerts: [Policy module for ADCS](https://github.com/Sleepw4lker/TameMyCerts) (open-source, ESC mitigation)
- Uwe Gradenegger (Sleepw4lker), TameMyCerts: [Documentation](https://docs.tamemycerts.com/)

---

**Next in series:** Part 2 - Hierarchy & Planning
**Publication schedule:** Weekly on LinkedIn
**Feedback:** Comments on LinkedIn, GitHub issues for technical questions