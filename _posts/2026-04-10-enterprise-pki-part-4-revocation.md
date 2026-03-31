---
layout: post
title: "CRL & OCSP: Revocation That Actually Works"
date: 2026-04-10
categories: [pki, adcs, security]
tags: [ADCS, PKI, enterprise, certificate-authority]
author: Ben Coremans
published: false
---

# CRL & OCSP: Revocation That Actually Works

You can build a perfect hierarchy. Pick the right algorithms. Harden every template. And then your CRL expires on a Saturday night and nobody notices until Monday morning when VPN authentication stops working for 3,000 users.

Revocation is the operational backbone of production PKI. It is also the part most people configure once during installation and never think about again. Until it breaks.

CRL availability is more critical than CA availability. Your CA can be offline for days and nobody notices, certificates keep working, autoenrollment queues up and retries. But if your CRL distribution point is unreachable or serves an expired CRL, certificate validation fails. Hard. Every client that checks revocation will reject every certificate issued by that CA. Not just revoked ones. All of them.

This article covers how CRLs work in Active Directory Certificate Services (ADCS), how to plan validity periods that do not create operational emergencies, when OCSP is worth the complexity, and how CRL partitioning (new in Windows Server 2025) solves the scaling problem that large enterprises inevitably hit.

## CRL Fundamentals: What ADCS Actually Publishes

A CRL is a signed list of revoked certificate serial numbers. The CA publishes it at regular intervals, and clients download it to check whether a certificate they received is still trusted.

ADCS CRLs contain three time fields that matter:

**This Update:** When the CRL was published. Microsoft CAs set this 10 minutes in the past to compensate for clock skew between systems.

**Next Update:** When the CRL expires. Microsoft CAs add 10 minutes to compensate for clock skew. After this time, clients consider the CRL stale and (depending on configuration) either reject all certificates or fall back to cached data.

**Next CRL Publish:** This is a Microsoft proprietary extension. It tells the CA when to publish the next CRL, which is typically before the Next Update time. The gap between Next CRL Publish and Next Update is the CRL overlap period.

The overlap period exists for distribution lag. When the CA publishes a new CRL, it takes time for that CRL to propagate to all CDP locations, get cached by proxies, and be downloaded by clients. If the old CRL expired the instant the new one was published, clients that have not yet downloaded the new CRL would see an expired CRL and reject certificates. The overlap gives you a buffer.

Default overlap in ADCS is 10% of the CRL validity period, with a minimum of 1 hour. For a 1-week CRL, that is about 17 hours of overlap. For shorter CRLs the overlap may be capped at 12 hours; for longer ones it can extend further depending on your configuration. Verify it against your CDN or web server caching settings.

### Revocation Reasons

When you revoke a certificate, ADCS records a reason code:

| Code | Reason | When to use |
|------|--------|-------------|
| 0 | Unspecified | Default. Use when no specific reason applies |
| 1 | Key Compromise | Private key exposed or stolen |
| 2 | CA Compromise | The CA itself was compromised |
| 3 | Affiliation Changed | User left the organization or changed role |
| 4 | Superseded | Certificate replaced by a new one |
| 5 | Cessation of Operation | Service or system decommissioned |
| 6 | Certificate Hold | Temporary suspension (reversible) |

Code 6 is the only reversible one. Putting a certificate on hold adds it to the CRL. Removing the hold (code 8, Remove from CRL) takes it off again. This sounds useful in theory. In practice, I avoid it. Certificate Hold creates operational confusion: is the cert revoked or not? If a client cached the CRL while the cert was on hold, it considers it revoked even after you remove the hold, until the client fetches a fresh CRL. Use it only when you have a genuine temporary suspension scenario and understand the caching implications.

One detail that keeps CRL size manageable: Microsoft's CA automatically removes expired certificates from the CRL. Once a certificate's validity period has passed, there is no point listing it as revoked. It is already invalid. This means your CRL does not grow forever, it stabilizes around the number of revoked certificates that are still within their validity period.

## Base CRL and Delta CRL: The Trade-off

ADCS supports two types of CRLs.

**Base CRL:** The complete list of all revoked certificates. Published at a regular interval (default: 1 week for enterprise CAs). Clients must download the full list.

**Delta CRL:** An incremental update containing only certificates revoked since the last base CRL was published. Much smaller. Published more frequently (default: 1 day).

The idea is straightforward. A client downloads the base CRL once per week. Between base CRL publications, it downloads the much smaller delta CRL daily to stay current. This reduces bandwidth and speeds up revocation checks.

The catch: delta CRLs have higher availability requirements than base CRLs.

A base CRL is valid for its entire validity period. If the CDP goes down for a few hours, clients use their cached copy. With a 1-week base CRL and a 10% overlap, you have almost a day of buffer.

A delta CRL has a shorter validity period, typically 1 day. If your CDP is unreachable when a delta CRL expires, clients have at most a few hours of overlap. After that, certificate validation fails.

This is the core trade-off. Delta CRLs give you faster revocation propagation (revoked certs appear in the delta within a day instead of waiting up to a week for the next base CRL). But they require your CDP infrastructure to be more reliable. If your web servers hosting the CRL have occasional outages, delta CRLs amplify the impact.

My recommendation: enable delta CRLs for Issuing CAs where revocation timeliness matters. Disable them for the Root CA (the Root CA rarely revokes anything, and when it does, a manual CRL publication is appropriate). If your CDP infrastructure is not highly available, extend the delta CRL validity period or skip deltas entirely and shorten the base CRL interval instead.

## CRL Validity Planning: Concrete Numbers

Here are the intervals I use for a standard enterprise deployment.

### Root CA (Offline)

| Setting | Value | Reason |
|---------|-------|--------|
| Base CRL validity | 6 months | Root CRL is published manually; 6 months gives operational breathing room |
| Delta CRL | Disabled | Root CA revocations are rare and always manual |
| CRL overlap | 2 weeks | Long overlap because publishing requires physical access to an offline CA |

The Root CA sits in a safe. Publishing a CRL means powering it on, signing the CRL, copying it to removable media, and publishing it to the CDP. You do this twice a year. Set a calendar reminder. If you forget and the Root CRL expires, every certificate in your entire hierarchy becomes untrusted.

I have seen this happen. A Root CRL expired because the scheduled publication was missed during a holiday period. The result was a complete authentication outage across the enterprise on a Monday morning. Calendar reminders are not optional.

### Issuing CA (Online)

| Setting | Value | Reason |
|---------|-------|--------|
| Base CRL validity | 7 days | Weekly publication, automatic |
| Delta CRL validity | 1 day | Daily updates for timely revocation |
| CRL overlap | 10% (default) | ~17 hours buffer for distribution |

These are starting points. Adjust based on your environment:

**Higher security requirements?** Shorten the base CRL to 2-3 days. This means revoked certificates are removed from trusted status faster. The cost is more frequent, larger downloads.

**Unreliable CDP infrastructure?** Extend validity periods. A 14-day base CRL with 2-day delta CRLs gives you more buffer. The cost is slower revocation propagation.

**Very high certificate volume (50,000+ active certs)?** Consider CRL partitioning (covered below) before shortening intervals. Shorter intervals with large CRLs mean more bandwidth consumption across your network.

## CDP and AIA Configuration: HTTP Only

CDP (CRL Distribution Point) tells clients where to download the CRL. AIA (Authority Information Access) tells clients where to find the issuing CA certificate (for chain building) and optionally the OCSP responder URL.

ADCS defaults to publishing CRLs via both LDAP and HTTP. My position: remove LDAP from CDP and AIA extensions in certificates. Use HTTP only.

**Why no LDAP?**

LDAP distribution works by publishing CRLs to Active Directory and relying on AD replication to distribute them. This has three problems.

First, replication lag. In a multi-site AD environment, a CRL published to AD at the hub site takes time to replicate to spoke sites. During that window, clients at spoke sites fetch a stale CRL. With HTTP, you control the distribution. Publish to a web server, optionally behind a CDN, and all clients get the same CRL immediately.

Second, non-domain-joined clients cannot use LDAP. If you issue certificates to DMZ servers, partner systems, or anything not joined to your AD domain, those clients cannot resolve the LDAP CDP path. They need HTTP.

Third, LDAP URLs in certificates expose your Active Directory structure. The distinguished name of your CDP container reveals your domain name, forest structure, and CA naming. For certificates that leave your network (mutual TLS with partners, for example), this is unnecessary information disclosure.

**HTTP CDP configuration principles:**

One important detail: use HTTP, not HTTPS, for CDP and AIA URLs. This sounds counterintuitive, but RFC 5280 specifies HTTP for CRL distribution, and there is a good reason. If a client needs to validate a TLS certificate to download a CRL over HTTPS, it needs to check the revocation status of the HTTPS server's certificate first. That creates a circular dependency. HTTP avoids this. The CRL itself is signed by the CA, so integrity is already guaranteed regardless of transport security.

Use a dedicated hostname for your CDP. Something like `pki.yourdomain.com`. Do not use the CA server's hostname directly. If you ever need to move the CDP to a different server, load balancer, or CDN, a dedicated hostname lets you do that without reissuing certificates.

Configure the CDP URL in ADCS before issuing any certificates. The CDP URL is embedded in every certificate the CA issues. Changing it later means all previously issued certificates still point to the old URL. You must maintain the old URL until all certificates issued with it have expired.

For AIA, the same logic applies. HTTP for the CA certificate location. If you deploy OCSP, add the OCSP responder URL to the AIA extension as well.

The CDP and AIA configuration in ADCS is CA-wide. Every certificate issued by that CA gets the same CDP and AIA URLs. If you need different URLs per template (internal vs external certificates, for example), TameMyCerts can override CDP and AIA on a per-template basis. Native ADCS cannot do this. This is covered in detail in Part 5.

## When CRLs Get Too Big: Partitioned CRLs

In a large enterprise with hundreds of thousands of active certificates, CRLs grow. Not forever (expired certs drop off), but they can reach several megabytes. A 5MB CRL downloaded by every client during every revocation check is a bandwidth problem. On slow WAN links or in environments with thousands of simultaneous clients, it becomes a real performance issue.

CRL partitioning solves this. It was introduced in Windows Server 2025 and backported to Server 2022 and Server 2019 via cumulative updates in late 2025. This is native ADCS functionality, not a third-party extension.

### How Partitioned CRLs Work

Instead of one CRL containing all revoked serial numbers, the CA maintains multiple smaller CRLs (partitions). When a certificate request is submitted, ADCS assigns it a partition index. If that certificate is later revoked, its serial number appears only in that partition's CRL.

The key insight: no client-side changes are required. The CA embeds the correct partition-specific CDP URL in each certificate at issuance time. When a client needs to check revocation, it downloads only the small partition CRL that covers that specific certificate. The client does not know or care that partitioning exists.

### Partition Zero: Two Strategies

Partition 0 is special. It handles certificates issued before partitioning was enabled and certificates that need special treatment. You have two design choices:

**Type A (Aggregate):** Partition 0 contains a complete CRL with all revoked certificates across all partitions. This is backward compatible. Any system that needs a full CRL (including OCSP responders, which I will explain shortly) can use partition 0. The downside: partition 0 keeps growing, just like the old monolithic CRL.

**Type B (Exclusive):** Partition 0 contains only certificates that were issued before partitioning was enabled, plus any special-case certificates. It stops growing once all pre-partitioning certificates expire. The downside: there is no single CRL that covers everything, which breaks OCSP responders that need a complete CRL as their data source.

### Which Strategy to Choose

If you run OCSP (covered in the next section), use Type A. Microsoft's OCSP responder is CRL-based. It needs one complete CRL to build its response database. Without it, the OCSP responder cannot answer queries for certificates in other partitions.

If you do not run OCSP and your CRL size is the only problem, Type B is cleaner. Partition 0 eventually stops growing, and all new certificates get small, evenly distributed partition CRLs.

### Assignment Methods

**Random (default):** Each new certificate gets a random partition index. Over time, partitions are roughly equal in size. Slightly uneven distribution is possible but acceptable.

**Round-robin:** Sequential assignment. More predictable partition sizes. But if you decommission and reissue large batches of certificates, you might end up with uneven partitions anyway.

Random is fine for most environments. Round-robin adds predictability if you care about exact partition balance, but the operational difference is minimal.

### When to Enable Partitioning

Do not enable partitioning on day one. It adds complexity to your CDP configuration and monitoring. Enable it when your CRL grows large enough to cause measurable problems: slow downloads, bandwidth complaints, or client timeout errors during revocation checks.

**Operational impact on monitoring:** With partitioning enabled, the CA publishes a separate base CRL (and delta CRL, if enabled) for each partition. With 10 partitions and delta CRLs, you go from monitoring 2 files to monitoring 20 or more. Your CDP URLs now include a `<CRLPartitionIndex>` variable that generates filenames like `My-CA_Partition00001.crl` through `My-CA_Partition00010.crl`, each with its own delta variant. Existing monitoring scripts, Nagios/PRTG checks, or SIEM rules built around "2 CRL files must be current" will break or generate false positives. Before enabling partitioning, update your monitoring to either use wildcard checks or query the CA's `CRLPartitionCount` property to dynamically discover all partition CRLs.

A rough threshold: if your base CRL exceeds 1-2MB and you have clients on slow links, partitioning starts making sense. Below that, the complexity is not worth it.

One operational detail to be aware of: when you enable partitioning, ADCS generates both base and delta CRLs per partition. With 10 partitions and delta CRLs enabled, that is 20 CRL files per publication cycle. Factor this into your CDP storage and monitoring. If you monitor CRL health (and you should), you now have 20 files to track instead of 2.

This leads to a design opportunity: with partitioned CRLs, each partition's base CRL is small enough that you might be able to publish base CRLs more frequently and drop delta CRLs entirely. If your base CRL per partition is 50KB instead of 5MB, publishing it every 2 days instead of every 7 is cheap. That eliminates the delta CRLs, cuts your file count in half, and removes the higher availability requirements that delta CRLs impose.

## OCSP: When It Makes Sense in Enterprise PKI

Part 1 introduced OCSP at a high level. Here I go deeper into the operational reality of running OCSP in an ADCS environment.

The conventional wisdom says OCSP is for internet PKI and CRLs are for enterprise. That was true ten years ago. Today, OCSP has legitimate enterprise use cases, but you need to understand what Microsoft's implementation actually does before you deploy it.

### How Microsoft OCSP Works (It Is Not What You Think)

Microsoft's OCSP responder does not talk to the CA directly. It does not have a real-time connection to the CA's revocation database. Instead, it downloads CRLs from the CDP, just like any other client, and uses the CRL as its data source.

This has a critical implication: OCSP response validity is tied to the underlying CRL. Specifically, the OCSP response is valid for the remaining validity of the CRL at the time the responder processed it. If the responder fetched a CRL that expires in 5 days, the OCSP response is valid for those 5 days, not the full 7-day CRL period. OCSP does not give you "real-time" revocation in the Microsoft implementation. It gives you the same revocation data as the CRL, served over a different protocol.

So why bother?

**Bandwidth.** An OCSP response is a few hundred bytes. A CRL can be megabytes. For environments with many clients checking revocation frequently, OCSP dramatically reduces bandwidth. The client sends a request with one serial number and gets a small, signed response back. No downloading the entire revocation list.

**Speed.** Parsing a multi-megabyte CRL takes time. An OCSP lookup is faster, especially on resource-constrained devices.

**Per-certificate status.** With CRLs, the client downloads the entire list and searches it locally. With OCSP, the client asks about one specific certificate and gets a targeted answer.

### The Magic Number: When Windows Switches from OCSP to CRL

Windows clients have a built-in heuristic called the "Magic Number." When a client checks certificates from the same issuing CA, it counts the total number of OCSP queries. Once that count exceeds a threshold (default: 50), the client stops using OCSP for that CA and switches to downloading the full CRL instead. This is a performance optimization, not a failure fallback. The logic is simple: if you are validating 200 certificates from the same CA (Monday morning, everyone logs in), downloading one CRL is cheaper than making 200 individual OCSP requests.

The Magic Number is per-client, per-CA. It resets after a configurable timeout.

The practical impact: during mass authentication events, Windows clients silently switch from OCSP to CRL. You might think OCSP is handling the load because your OCSP responder logs show responses. But the busiest clients have already switched to CRL downloads. Monitor both your OCSP responder and your CDP web server logs to understand the actual client behavior.

### Deterministic "Good" Responses

Here is something that catches people off guard. When an OCSP responder receives a query for a serial number, it checks its CRL database. If the serial number is not in the CRL, the response is "Good."

But "not in the CRL" does not mean "issued by this CA." It means "not revoked." The OCSP responder has no way to verify that the CA actually issued a certificate with that serial number. It only knows which serial numbers are revoked. Everything else is "Good."

This is called the deterministic "Good" problem. An attacker could query your OCSP responder with a fabricated serial number and get a "Good" response. In isolation, this is not exploitable (the attacker still needs a valid certificate chain). But it means OCSP responses are not positive proof of issuance.

Be aware of this when designing your security model. OCSP confirms revocation status, not issuance status.

### Browser Behavior: Chrome and Edge Do Not Check

Chrome and Edge do not perform online revocation checks by default. They rely on CRLSets (Chrome) or similar proprietary mechanisms for public certificates. For enterprise internal certificates, this means Chrome and Edge users are not checking your CRL or OCSP responder at all, unless you enforce it via Group Policy.

If your environment uses Chrome or Edge for internal web applications secured by enterprise PKI certificates, configure revocation checking via policy. Otherwise, a revoked certificate will continue to work in those browsers indefinitely.

## OCSP Operational Reality

Running an OCSP responder is not "install the role and forget it." There are operational considerations that will bite you if you ignore them.

### Signing Certificates

OCSP responses must be signed. The OCSP responder uses a dedicated signing certificate for this, issued by the same CA whose certificates it validates.

These signing certificates have a short validity period (default 14 days, configurable). They auto-renew. This sounds fine until you consider the edge case: OCSP signing certificates cannot be revoked.

Why? Because revoking the OCSP signing certificate creates a loop. To check the revocation status of the OCSP signing certificate, the client would need to query the OCSP responder, which uses that same signing certificate. The RFC explicitly addresses this by including a "no revocation checking" extension in OCSP signing certificates.

The implication: if an OCSP signing key is compromised, you cannot revoke the certificate. You must wait for it to expire (up to 14 days) or manually remove it from the OCSP responder and force a new signing certificate enrollment. This is why HSM protection for OCSP signing keys is recommended. The signing key is effectively irrevocable for its lifetime, so protect it accordingly.

### Caching Layers

OCSP responses are cached at multiple levels:

**Client-side disk cache:** Windows stores OCSP responses on disk. Subsequent checks for the same certificate use the cached response until it expires.

**Client-side memory cache:** Active sessions cache responses in memory for the duration of the session.

**IIS web server cache:** If your OCSP responder runs behind IIS (which it does in a standard ADCS deployment), IIS caches responses. This reduces load on the OCSP responder but means a fresh revocation might not be visible to clients until the IIS cache expires.

**Proxy/CDN cache:** If you front your OCSP responder with a reverse proxy or CDN, add another caching layer.

The net effect: after you revoke a certificate, it can take the combined cache lifetime of all these layers before every client sees the revocation via OCSP. In practice, this is bounded by the CRL validity period (since OCSP response validity matches CRL validity). But in the short term, caching can delay visibility.

Plan your revocation SLA accordingly. "Certificate revoked within 24 hours" is achievable. "Certificate revoked and all clients updated within 1 hour" requires careful tuning of all caching layers and short CRL/OCSP validity periods.

### Monitoring

Monitor your OCSP responder like any critical web service:

- Response time (should be under 500ms for local clients)
- Error rate (HTTP 5xx responses indicate backend issues)
- Signing certificate expiry (alert at 3 days remaining)
- CRL freshness (the underlying CRL the OCSP responder uses must be current)
- IIS application pool health (recycles, crashes)

If the OCSP responder fails silently, clients fall back to CRL. You will not notice until someone checks the logs or the CRL web server starts getting hammered.

## OCSP Stapling: Free Performance

OCSP stapling is not an ADCS feature per se. It is a TLS extension (RFC 6066, section 8) implemented by web servers. But it solves a real problem with OCSP deployment, so it belongs here.

Without stapling, the TLS client must contact the OCSP responder separately during the handshake to verify the server's certificate. This adds latency (an extra round trip). In internet PKI, this also creates a privacy concern: the OCSP responder operator sees which clients connect to which servers. This is one of the reasons Let's Encrypt shut down their OCSP servers in late 2024. In enterprise environments where you operate your own OCSP responder, the privacy argument is less relevant, but the latency cost remains.

With stapling, the TLS server periodically fetches its own OCSP response from the responder and includes ("staples") it in the TLS handshake. The client gets the OCSP response directly from the server. No extra round trip. No privacy leak.

IIS supports OCSP stapling natively. No configuration required beyond having the OCSP responder URL in the AIA extension of the server's certificate. IIS handles the rest: it fetches the OCSP response, caches it, and includes it in TLS handshakes automatically.

For internal web servers using enterprise PKI certificates, stapling eliminates the need for every client to independently contact the OCSP responder. The server does it once, and all clients benefit. In environments with hundreds of concurrent TLS connections, this is a meaningful bandwidth and latency reduction.

The catch: stapling only works for server certificates in TLS. It does not apply to client certificates, smart card certificates, or code signing. For those use cases, the client still performs its own OCSP lookup or CRL check.

## The Decision Framework: CRL, OCSP, or Both

Not every CA needs OCSP. Not every environment benefits from delta CRLs. Here is how I decide.

**CRL only (most common):**

Use CRLs alone when your certificate volume is moderate (under 50,000 active certs), your CRL size stays under 1-2MB, your CDP infrastructure is reliable, and your revocation timeliness requirement is measured in days, not hours. This covers 80% of enterprise deployments. Simple, reliable, well-understood.

**CRL + Delta CRL:**

Add delta CRLs when you need faster revocation propagation (daily instead of weekly) and your CDP infrastructure can sustain the higher availability requirements. This is my default for Issuing CAs.

**CRL + OCSP:**

Add OCSP when bandwidth is a concern (large CRLs, many clients, slow links), when you want per-certificate lookups instead of full CRL downloads, or when you have TLS-heavy environments that benefit from OCSP stapling. Remember that OCSP does not give you faster revocation than CRLs in the Microsoft implementation. It gives you the same data in a more efficient delivery mechanism.

**CRL + OCSP + Partitioned CRLs:**

The full stack. Use this for large-scale environments (100,000+ certificates) where CRL size is a proven problem. Use Type A partitioning so the OCSP responder can access a complete CRL. This gives you both the bandwidth efficiency of OCSP and the size management of partitioned CRLs.

| Scenario | CRL | Delta CRL | OCSP | Partitioning |
|----------|-----|-----------|------|-------------|
| Small enterprise (<10K certs) | Yes | Optional | No | No |
| Medium enterprise (10K-50K) | Yes | Yes | Optional | No |
| Large enterprise (50K-200K) | Yes | Yes | Yes | Evaluate |
| Very large / multi-tenant (200K+) | Yes | Maybe not* | Yes | Yes (Type A) |

*With partitioned CRLs, individual partition CRLs are small enough that more frequent base CRL publication may replace the need for delta CRLs.

## Monitoring and Health Checks

CRL expiration is the single most common PKI outage cause. Automate monitoring for these:

**CRL expiry alerts:** Check every CDP URL daily. Alert when a CRL's Next Update is less than 50% of its validity period away. For a 7-day CRL, alert at 3.5 days remaining. For a 6-month Root CRL, alert at 3 months remaining.

**CDP reachability:** HTTP health checks against every CDP URL. If the URL returns anything other than HTTP 200 with a valid CRL, alert.

**CRL freshness:** Verify that the CRL's This Update timestamp is recent. A reachable CDP serving a stale (but not yet expired) CRL means the CA stopped publishing. Catch this before it becomes an outage.

**OCSP responder health:** If you run OCSP, send test queries and verify responses. Check signing certificate expiry. Monitor the OCSP responder's CRL download (if it cannot fetch fresh CRLs, it serves stale data).

**Root CA CRL calendar:** This is not automated monitoring. This is a calendar entry shared with at least three people, including someone outside the PKI team. "Publish Root CRL" with a date, a procedure document, and a secondary reminder two weeks before. The Root CA is offline. There is no automated publishing. If the humans forget, the CRL expires. As discussed in Part 2, plan your Root CA renewal years in advance. The CRL publication schedule requires the same discipline.

Build this monitoring before you go to production. Not after. A CRL expiry at 2 AM on a Sunday is not the time to discover you have no alerting.

## What's Next

Part 5 covers TameMyCerts, the policy module that fills the gaps ADCS leaves open. Per-template CDP and AIA configuration. Subject name validation. Key algorithm enforcement. The operational hardening layer that turns a default ADCS installation into something you can trust in production.

---

**Previous in series:** Part 3 - Cryptography in 2026: Choosing Algorithms for Enterprise PKI
**Next in series:** Part 5 - TameMyCerts: The Policy Module ADCS Should Have Had

---

**Sources:**
- Uwe Gradenegger (Sleepw4lker): [Basics of the Online Responder (OCSP)](https://www.gradenegger.eu/en/basics-online-responder-ocsp/)
- Uwe Gradenegger (Sleepw4lker): [Basics of certificate revocation](https://www.gradenegger.eu/en/basics-certificate-revocation/)
- Uwe Gradenegger (Sleepw4lker): [TameMyCerts per-template CDP/AIA configuration](https://www.gradenegger.eu/en/)
- Vadims Podāns (Crypt32): [AD CS Partitioned CRLs - Introduction (Part 1)](https://www.sysadmins.lv/blog-en/ad-cs-partitioned-crls-introduction-part1.aspx) (5-part series, October 2025)
- Vadims Podāns (Crypt32): [AD CS Partitioned CRLs - Configuration Components (Part 3)](https://www.sysadmins.lv/blog-en/ad-cs-partitioned-crls-configuration-components-part-3.aspx) (CRL naming, CDP URL variables)
- Vadims Podāns (Crypt32): [AD CS Partitioned CRLs - API and Events (Part 5)](https://www.sysadmins.lv/blog-en/ad-cs-partitioned-crls-partitioned-crl-api-and-events-part-5.aspx) (CRLPartitionCount property, monitoring)
- Vadims Podāns (Crypt32): [Blog](https://www.sysadmins.lv/) - PowerShell PKI module author and ADCS expert
- Vadims Podāns (Crypt32): [PSPKI - PowerShell PKI Module](https://github.com/Crypt32/PSPKI) - open-source ADCS management and automation
- Uwe Gradenegger (Sleepw4lker), TameMyCerts: [Policy module for ADCS](https://github.com/Sleepw4lker/TameMyCerts) (per-template CDP/AIA override)
- Uwe Gradenegger (Sleepw4lker), TameMyCerts: [Documentation](https://docs.tamemycerts.com/)
- RFC 5280: Internet X.509 PKI Certificate and CRL Profile
- RFC 6960: X.509 Internet PKI Online Certificate Status Protocol (OCSP)
- RFC 6066: TLS Extensions (OCSP Stapling, Section 8)