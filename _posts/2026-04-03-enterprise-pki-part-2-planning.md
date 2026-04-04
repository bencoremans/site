---
layout: post
title: "Hierarchy & Planning: The Decisions That Define Your PKI"
date: 2026-04-08 10:00:00 +0200
categories: [pki, adcs, security]
tags: [ADCS, PKI, enterprise, certificate-authority, planning, HSM, constraints]
author: Ben Coremans
published: false
---

# Hierarchy & Planning: The Decisions That Define Your PKI

Planning a PKI is not like planning a file server. Get this wrong and you're stuck with your choices for 10-15 years. Change your mind later? You get to rebuild the entire thing from scratch and touch every single device that trusts your Root CA.

This is where you make the calls that will either save you or haunt you.

In Part 1 I wrote that I have enough scars from running enterprise PKI to write this series. After 10+ years of running and auditing enterprise PKI, the same three categories of critical mistakes keep showing up, and they all happen before anyone touches a CAPolicy.inf file.

**The organizational failure.** The AD team installed ADCS because someone needed certificates. They had the rights, so they ran the wizard, published a few templates, and moved on. Years later nobody could clearly say who actually owned the PKI. Domain admins had Enterprise Admin rights but lacked deep PKI knowledge. The PKI specialist understood certificates but not the full impact on Active Directory authentication and Group Policy. When a serious misconfiguration surfaced, nobody knew who was responsible or how to assess the impact.

**The security failure.** A standard ADCS installation with default configuration. Someone followed a best-practice guide and published a domain controller certificate template. What nobody noticed: the CA was automatically added to the NTAuth container. Combined with a template that allowed "Supply in the request" and included Client Authentication, any authenticated user could request a certificate with `administrator@domain.local` in the SAN. This is a well-documented escalation path (ESC1). I have seen it live in production environments that had been running for years.

**The technical failure.** During a deployment, the team defined a new Certificate Policy OID and added it to the Issuing CA's CAPolicy.inf. The Root signed the request. Everything looked fine, until the Issuing CA refused to install the certificate. The error: the policy OID was not present in the Root CA certificate. RFC 5280 is strict: a child CA can only reference policies that exist in its parent. The fix required pulling the offline Root from the safe, re-issuing its certificate, and redistributing the new Root to every client.

Three failures. Organizational, security, and technical. All permanent. All preventable. All caused by skipping proper planning.

Every section in this article covers a decision like these.

---

## Part I: Before You Install

These are the questions you answer before you touch a server. They are organizational and security decisions that exist independent of your architecture choices.

### Delegation of Control: Who Owns Your PKI?

Here is the planning decision most people skip entirely: who is going to manage this PKI?

By default, ADCS installation requires Enterprise Admin rights. Template management requires Enterprise Admin rights. Publishing to NTAuth requires Enterprise Admin rights. If you follow the default path, your PKI is managed by whoever holds those keys.

The instinctive reaction is: separate it. Dedicated PKI admin group, delegated permissions, no dependency on domain admins. Separation of duties. Least privilege. All the right principles.

But here is the tension. ADCS is not a standalone system. It is deeply integrated into Active Directory. Certificate templates live in the Configuration partition. NTAuth controls authentication trust. Domain controller certificates determine whether smart card logon works. Group Policy controls autoenrollment. Every significant PKI decision has Active Directory implications, and every significant AD change can affect PKI.

This means whoever manages your PKI needs to understand both. Not just certificate extensions and CRL distribution points, but also AD replication, Group Policy processing, Kerberos authentication, and how NTAuth interacts with domain controller certificates. In my experience, domain admins are rarely PKI specialists. And PKI specialists often don't have enough AD depth to understand the full impact of their changes.

That is the real problem. Not "who has the permissions," but "who has the knowledge."

**If your domain admins are also PKI-competent** (or willing to become so), there is a legitimate argument for keeping PKI management with them. They already understand the AD integration points. They see the full picture. A domain admin who understands PKI would catch the NTAuth issue described in the introduction. A dedicated PKI admin who does not understand AD authentication might not.

**If your domain admins are not PKI specialists** (which is the more common situation), you need delegation. Set up a dedicated PKI admin group with permissions on:

- Certificate template objects (CN=Certificate Templates)
- OID container
- Enrollment Services
- AIA and CDP containers
- KRA container
- NTAuth (if this CA serves authentication)

This is not simple to configure. The permissions span multiple AD containers, each needing specific ACEs. But it is worth doing. Once configured, your PKI team operates without waiting for an Enterprise Admin to be available.

**Either way, the critical point is:** whoever manages PKI must understand its AD integration. A PKI admin who does not understand NTAuth, domain controller templates, and Group Policy autoenrollment is a risk. A domain admin who does not understand certificate extensions, CRL validity, and policy modules is equally a risk.

Plan for this before installation. Identify who will own PKI operations, make sure they have the right knowledge (not just the right permissions), and set up the access model accordingly. Do not let it be an afterthought.

### Certificate-Based Authentication: A Conscious Decision

When you install an enterprise CA, ADCS automatically publishes the CA certificate to the NTAuth container in Active Directory. This single action enables certificate-based authentication across your environment: smart card logon, client certificate authentication, Windows Hello for Business, NPS-based 802.1x, the works.

Most people do not realize this happened. They installed ADCS, published a domain controller template (often from a best-practice guide), and moved on. What they did not notice is that they just enabled every certificate issued by that CA to potentially be used for Active Directory logon, depending on the EKU and subject.

Here is where it gets dangerous. If you have a template that issues client authentication certificates, and that template allows the requester to supply their own subject name (or SAN), and you are not running a policy module like TameMyCerts, then anyone who can request a certificate can request one with `administrator@yourdomain.local` in the SAN. If the CA is in NTAuth, that certificate works for domain logon. Game over.

This is not a theoretical attack. It is a well-documented escalation path (ESC1 and variants). And it applies to any certificate with Client Authentication EKU, not just user certificates.

The planning decision is not "remove from NTAuth or leave it." It is broader than that.

#### Strong Certificate Mapping: The Mitigation That Changed the Game

Microsoft addressed this class of attacks with the May 2022 security update. Enterprise CAs now automatically embed the requester's Security Identifier (SID) in a new certificate extension. Domain controllers in Full Enforcement mode (default since September 2025, with no opt-out for new installations) verify that the SID in the certificate matches the authenticating account. This makes the classic ESC1 attack, requesting a certificate with another user's UPN in the SAN, significantly harder: the certificate will carry the requester's own SID, not the administrator's.

This is not a reason to relax. Strong certificate mapping mitigates one attack vector, but it does not replace proper template hardening. Certificates issued by standalone CAs, non-Microsoft CAs, or MDM platforms do not automatically receive the SID extension. Legacy environments that delayed the September 2025 update may still run in Compatibility mode. And new attack variants continue to emerge. Strong mapping is one layer. Template hardening, policy modules, and EKU restrictions remain essential.

#### What Certificate Authentication Actually Controls

When the CA is in NTAuth, it is not just smart card logon that is enabled. Several features depend on the CA being in NTAuth:

- Smart card logon and Windows Hello for Business
- Enroll on Behalf Of (EOBO) / enrollment agents
- Key Recovery and Private Key Archiving
- Network Policy Server (NPS) for 802.1x, DirectAccess, Always On VPN
- EFS File Recovery Agents
- IIS Client Certificate Mapping against Active Directory
- NDES renewal mode

Removing the CA from NTAuth breaks all of these. It is the most drastic measure, and it has consequences that are easy to overlook.

#### Deciding Whether Certificate Logon Should Be Enabled

This is not a PKI team decision alone. Involve your domain admins and security team. If the organization wants smart card logon or certificate-based VPN authentication, configure it properly: dedicated templates with strict SAN validation, a policy module enforcing subject name rules, and EKU Qualified Subordination on the CA certificate to limit what types of certificates it can issue.

#### Restricting or Disabling Certificate Logon

If certificate-based logon is not desired, you have several options, from least to most drastic:

- **Template hardening:** Do not publish templates that allow requesters to supply their own subject. Use "Build from this Active Directory information" instead of "Supply in the request."
- **Policy module (TameMyCerts):** Enforce strict SAN validation on every request. Even if a template allows subject supply, the policy module rejects anything that does not match the rules.
- **EKU Qualified Subordination:** Restrict the CA certificate itself so it cannot issue certificates with Smart Card Logon or Client Authentication EKU.
- **Domain controller templates:** Use a custom domain controller template that supports LDAPS but does not enable smart card logon processing. This is a subtle but important distinction.
- **Remove from NTAuth:** The nuclear option. Effective, but breaks other features. Only appropriate if you are certain none of the dependent features are needed.

The point is: this must be a conscious decision. Not something that happens by default because you followed an installation guide. Discuss it with your domain admins. Document the decision. And implement the appropriate controls before you go to production.

---

## Part II: Architecture Decisions

With ownership and security awareness established, you can make informed architecture choices. These decisions define the structure of your PKI for the next 10-15 years.

### The Tier Decision: 1-Tier is a Disaster, 2-Tier is the Sweet Spot, 3-Tier When You Need It

#### Why 1-Tier is Unacceptable

A single-tier PKI means one CA that is both your Root and your Issuing CA. Usually domain-joined, because convenience. It issues certificates directly to users, computers, services.

This is a security nightmare.

If that server is compromised, your entire trust anchor is gone. You cannot revoke a Root CA certificate. Clients will not honor it, because revoking your own Root breaks the chain of trust. Your only option is to manually remove the Root certificate from every single client in your environment and deploy a new one. For an enterprise with thousands of devices, this is a catastrophic failure.

And it gets worse. If an attacker compromises your Root CA, they can issue certificates for anything. Any user. Any service. Code signing. Whatever they want. Forever, until you notice and rebuild from scratch.

There is no scenario where single-tier PKI is acceptable in production. None.

#### 2-Tier: The Right Choice for Most Enterprises

For 95% of organizations, two tiers is the answer.

**Tier 1: Offline Root CA**

A standalone, non-domain-joined Windows Server (or Linux box, more on that later) that lives in a safe. Literally. It only wakes up three times in its life:

1. Initial setup: create the Root CA certificate, sign the Root CRL.
2. Issuing CA installation: sign the Issuing CA certificate.
3. Renewal events: renew the Root CA certificate or re-sign Issuing CA certificates.

The rest of the time it is powered off. Air-gapped. Not on the network. If someone wants to compromise it, they need physical access to your server room or safe.

**Tier 2: Online Issuing CA(s)**

Domain-joined enterprise CAs that handle day-to-day operations. Users request certificates. Autoenrollment provisions machine certs. Services request TLS certificates. This is where the action happens.

If an Issuing CA is compromised, you pull the Root CA out of the safe, revoke the compromised Issuing CA's certificate, publish the updated CRL, and stand up a new Issuing CA. The trust in your Root remains intact. Clients see the revoked Issuing CA certificate, stop trusting it, and you move on.

That is the value of separation. The Root is your trust anchor. Protect it like your life depends on it, because operationally, it does.

#### When 3-Tier Makes Sense

You add a third tier (Root - Policy/Intermediate - Issuing) when you need policy or namespace separation that cannot be achieved any other way.

Examples where I have seen 3-tier justified:

- Multi-tenant environments where different business units must be cryptographically isolated. Each tenant gets their own Intermediate CA under a shared Root.
- Geographic distribution with high-latency or unreliable WAN links. Regional Intermediate CAs reduce dependency on a central Issuing CA.
- Legal or compliance requirements demanding separate policy trees for different certificate types (e.g., certificates for employees vs contractors).

If none of those apply, you are adding complexity for no gain. Three-tier hierarchies are harder to operate, harder to renew, and harder to troubleshoot. Only deploy them when 2-tier genuinely cannot meet your requirements.

### HSM: Standard, Not Optional

I need to be blunt here. If your CA private keys are stored on a hard drive, in Windows Key Storage Provider, or as a .pfx file, they are portable. An admin can export them. An attacker who gains admin rights can copy them.

Hardware Security Modules (HSMs) solve this.

An HSM stores your CA private key inside tamper-resistant hardware. Signing operations happen inside the device. The key never leaves. If you try to physically attack the HSM, it zeroes the key. FIPS 140-2 Level 3 certified modules have sensors for temperature, voltage, physical intrusion. Mess with them and the keys are gone.

"HSMs are too expensive" stopped being a valid excuse five years ago. Network HSMs are expensive, yes. Multi-AZ, HA clusters with vendor support run into five figures easily. But entry-level FIPS-certified USB HSMs cost a few hundred euros. For a Root CA that sits in a safe and signs maybe 10 certificates in its entire 15-year life, a USB HSM is perfectly adequate.

For your Issuing CAs, which handle thousands of signing operations per day, you want something more capable. But even then, the cost is a one-time investment. Once deployed, the ongoing cost is minimal. Support contracts, maybe. Hardware replacement every 7-10 years.

Compare that to the cost of rebuilding your entire PKI after a key compromise. HSM is not optional.

### The Root CA Platform: It Doesn't Matter, Until It Does

Windows is not sacred for the Root CA. Neither is Linux. What matters is: can you protect the private key, and can you maintain the CA over its 15-year lifetime?

Your Root CA has exactly two jobs: sign subordinate CA certificates and sign CRLs. It does this maybe three times in five years. The rest of the time it sits powered off in a safe, air-gapped.

The real question is key protection.

If you use an HSM (and you should), the platform matters less. The key lives in hardware regardless. But the HSM needs a client, a PKCS#11 driver or a KSP on Windows. Most HSM vendors ship Windows tooling with a KSP that integrates natively with ADCS. If your Root CA runs Windows with ADCS in standalone mode, the signing workflow is familiar: certutil, MMC snap-in, well-documented Microsoft procedures. Your team already knows how to do this.

If you use Linux with OpenSSL, the signing workflow is different but equally valid. OpenSSL supports PKCS#11 for HSM integration. The commands are scriptable and reproducible. But you need someone comfortable with OpenSSL certificate operations and basic Linux administration. If that person leaves and nobody can operate the Root CA in 10 years, you have a problem.

Without an HSM, the platform matters more, because the key is stored in software. Windows KSP stores it in the file system (exportable by any admin). OpenSSL stores it as a PEM file. Either way, the key is portable and vulnerable. Without an HSM, you are relying on physical security (the safe, the air gap) as your only protection. It works, but it is one layer instead of two.

My take: use an HSM. Then pick whichever platform your team can maintain for 15 years. Windows with ADCS standalone is the path of least resistance for most enterprises. Linux with OpenSSL is leaner and equally capable. Both work. Pick the one you can support.

Your Issuing CAs will still be Windows Server running ADCS, because Active Directory integration requires it. But the Root CA is a different story. It is offline. It does not need AD. Choose what works for your team and your key protection strategy.

### Naming Conventions That Age Well

Your CA name needs to identify who owns it. You need the organization name in there. When someone inspects a certificate chain, they need to know whose Root they are trusting. That is non-negotiable.

What you do not want is organizational structure, location, or dates baked into the name. Do not name your CA "CORP-HQ-CA01" or "EMEA-ROOT-2025". In 10 years, your company may restructure. Datacenters move. Regions reorganize. That CA name is baked into every certificate you issue. It is in the Authority Key Identifier extension. It is in the Issuing Distribution Point. Changing it means standing up a new CA and migrating everything.

Keep it simple: organization name, function, generation.

- Root CA: `Contoso Root CA G1`
- Issuing CA: `Contoso Issuing CA G1`

The `G1` (Generation 1) is critical. When you stand up your next PKI in 15 years, it will be `G2`. Your scripts, documentation, and disaster recovery procedures will thank you.

If you need to distinguish multiple Issuing CAs, use functional descriptors, not location-based ones:

- `Contoso Issuing CA - Web G1`
- `Contoso Issuing CA - VPN G1`
- `Contoso Issuing CA - Smart Cards G1`

Not "EMEA-CA" or "HQ-CA". Locations change. Functions are stable.

### Certificate Lifetime Planning: The Pyramid

Plan your CA certificate lifetimes in a pyramid:

- **Root CA: 15 years**
- **Intermediate/Policy CA: 10 years** (if you have a 3-tier hierarchy)
- **Issuing CA: 5 years**

Why the pyramid? Because a CA cannot issue a certificate with a validity period longer than its own remaining lifetime.

If your Issuing CA certificate expires in 1 year, it cannot issue certificates that outlive it. The signing operation will fail, or worse, succeed but produce an invalid certificate that clients reject.

And think about what is happening with end-entity certificate lifetimes. Public TLS certificates are already down to 1 year maximum, and the industry is pushing toward 90-day certificates. Even for internal certificates, there is a strong argument for following the same direction. Shorter lifetimes limit the window of exposure if a key is compromised, and they force you to automate renewal, which is a good thing. If you are still issuing 2-year internal TLS certificates, you are behind the curve. Plan your CA lifetimes with the assumption that end-entity certificates will keep getting shorter.

#### The Half-Life Renewal Rule

You must plan to renew each CA when it reaches half of its validity period.

If your Issuing CA has a 5-year certificate, you renew it at 2.5 years. Not at 4.5 years when you are in panic mode. At the halfway point.

Why? Because renewal is not instant. You need to:

1. Generate a new CA certificate (either renew with the same key or generate a new key, reusing the key is simpler but less secure).
2. Distribute the new CA certificate to all clients.
3. Verify that clients trust both the old and new CA certificate during the overlap period.
4. Monitor for clients still using the old CA certificate after the overlap ends.

If you wait until 6 months before expiration, you are in a high-pressure situation where mistakes happen. And PKI mistakes are expensive.

### Root CA Renewal Strategy: Plan It 5 Years Before You Need It

Your Root CA certificate has a 15-year lifetime. You need to renew it around year 7 or 8. That sounds far away, so it is easy to ignore.

Do not.

Renewing a Root CA is not like renewing an Issuing CA. When you renew the Root, you have two options:

1. **Renew with the same key:** The new Root CA certificate has a new validity period but the same public/private key pair. Clients that trust the old Root automatically trust the new one (same key = same trust anchor).
2. **Renew with a new key:** You generate a new key pair. This is more secure (limits exposure if the old key is somehow compromised), but it is also more complex. You must distribute the new Root CA certificate to all clients before the old one expires.

Most enterprises choose option 1 for the first renewal. It is simpler. The second time (around year 15), you stand up a new Root CA with a new key (G2) and plan a migration.

#### What Happens If You Don't Plan Renewal

If your Root CA certificate expires, every certificate issued by your entire PKI becomes invalid. Instantly. No authentication. No encrypted traffic. Nothing works.

Replacing an expired Root CA certificate requires manually touching every client. Workstations. Servers. Network devices. IoT endpoints. Mobile phones. If you have 10,000 devices, you have 10,000 touches. Even with automation, this is weeks of work.

Plan the renewal 5 years in advance. Test the procedure in a lab. Document the process. Assign ownership. Set calendar reminders for the people who will be doing this, because they might not be you. I have seen PKI deployments where the original architect left the company years before renewal was due, and nobody knew how it was built.

#### The 2030/2035 Deadline: Your CA's Expiry is Sooner Than You Think

Here is the reality of planning a PKI in 2026: the "15-year Root" assumption needs adjustment.

NIST's guidance (IR 8547 and updates to SP 800-131A) sets aggressive timelines for moving away from classical public-key cryptography:
- **By 2030:** Classical algorithms at ~112-bit security strength (RSA-2048, ECC P-256) are **deprecated** for new systems.
- **By 2035:** All classical asymmetric cryptography is targeted to be **disallowed** in federal and high-assurance environments.

If you build a Root CA today with a 15-year lifetime, it expires in 2041, six years after the 2035 target. This means your "long-lived" Root will outlive the cryptographic algorithms it is based on.

This changes your planning:
1. **Lifetime:** A 15-year Root is still fine for trust continuity, but treat 2035 as a hard migration milestone. Design your renewal cycle around it.
2. **Agility:** Your hierarchy must be "Quantum Ready." Windows Server 2025 ships ML-KEM and ML-DSA support in its CNG libraries (GA since November 2025), meaning the cryptographic primitives are available at the OS level. Microsoft has announced PQC support for ADCS, including PQC-signed certificates and CRLs across all role services, but this has not shipped yet as of early 2026. Plan for hybrid certificates (classical + PQC signatures) during the transition.
3. **The "Next Root":** Your "G2" Root (see Naming Conventions) should not be a simple RSA-4096 renewal. Plan it as PQC or hybrid from the start.

Do not build a 15-year monument to legacy crypto. Build a bridge that gets you safely to post-quantum.

---

## Part III: Security Constraints

These are the cryptographic restrictions you bake into CA certificates at install time. They cannot be changed after issuance. Get them right, because there is no undo.

### Name Constraints: Hard Restrictions You Decide Now

Here is a planning decision that most guides skip: Name Constraints.

Name Constraints restrict which DNS names and email addresses a CA is allowed to issue certificates for. You set them in CAPolicy.inf at installation time. Once the CA certificate is issued, they are baked in. You cannot change them without revoking the CA certificate and starting over.

Example: you have an Issuing CA dedicated to internal web services. You want it to only issue certificates for `*.internal.company.com`. You add a Permitted Subtrees Name Constraint for `internal.company.com`.

Now, even if an attacker compromises that Issuing CA, they cannot issue a certificate for `google.com` or `login.company.com` (outside the `internal` subdomain). The certificate will technically be valid (correct signature, trusted chain), but clients that honor Name Constraints will reject it because it violates the permitted namespace.

This is what I call a HARD restriction. It is baked into the CA certificate at issuance time. It is cryptographically enforced. An attacker who compromises the CA cannot disable it via policy changes, configuration tweaks, or registry edits. The only way to change it is to revoke the CA certificate and re-issue it. Every constraint discussed in this section (Name Constraints, EKU Qualified Subordination, Certificate Policy OIDs, PathLength) shares this property. Decide them carefully, because you will live with them for the lifetime of the CA.

#### When to Use Name Constraints

Use Name Constraints when:

- You have multiple Issuing CAs dedicated to specific namespaces (internal vs external, different business units, different DNS zones).
- You want defense in depth against CA compromise (even if the CA is hacked, the attacker's reach is limited).
- You have compliance requirements mandating namespace isolation.

Do not use them if you need flexibility. Once set, they are permanent. If your namespace changes (company acquires another domain, you reorganize DNS structure), you are stuck. You will need to stand up a new CA with updated constraints or accept that the old CA cannot issue certs for the new namespace.

### EKU Qualified Subordination: Limit Certificate Types Per CA

Extended Key Usage (EKU) constraints are another planning decision you make at install time.

Normally, an Issuing CA can issue any type of certificate. TLS server certs. Client authentication. Code signing. Email encryption. Whatever.

With EKU Qualified Subordination, you restrict the Issuing CA to only issue certificates with specific EKUs. You set this in the Issuing CA's own certificate (via CAPolicy.inf at the time you request the Issuing CA cert from the Root).

Example: you have an Issuing CA dedicated to web server certificates. You add only the Server Authentication EKU (`1.3.6.1.5.5.7.3.1`) to the Issuing CA's certificate.

Now, if someone requests a code signing certificate from that CA (EKU `1.3.6.1.5.5.7.3.3`), two things happen. First, the Microsoft CA itself will refuse to issue the certificate in its default configuration, because the requested EKU does not match the CA certificate's allowed EKUs. Second, even if a certificate with a non-matching EKU were somehow issued (through a different CA implementation or misconfiguration), clients that enforce EKU constraints will reject it during chain validation, because the CA's own certificate does not authorize code signing. Note that this enforcement is application-dependent. Microsoft's CryptoAPI, Firefox, and OpenSSL all support it, but no universally valid guarantee covers every application.

Like Name Constraints, this is a hard restriction baked into the CA certificate (see above).

#### When to Use EKU Qualified Subordination

Use it when:

- You have dedicated CAs for different certificate types (one for TLS, one for code signing, one for smart cards).
- You want to limit blast radius if a CA is compromised (a compromised web CA cannot issue code signing certs).
- You have compliance requirements demanding separation of duties.

Do not use it if you need a general-purpose Issuing CA. Most enterprises start with one Issuing CA that handles all certificate types. EKU constraints make sense when you scale up to multiple Issuing CAs with specific roles.

### Certificate Policy OIDs: Plan Your Hierarchy Before You Install

Certificate Policies are OIDs embedded in CA certificates that declare under which issuance policy a certificate was issued. They tie your technical PKI to your organization's Certificate Practice Statement (CPS). This is a planning decision because, like Name Constraints and EKU, the policy OIDs are baked into the CA certificate at installation time via CAPolicy.inf.

The rule is simple but unforgiving: **a child CA can only use a subset of the policies defined in its parent. It cannot introduce new ones.**

Here is how the hierarchy works:

- **Root CA:** Include the `All Issuance Policies` wildcard OID (2.5.29.32.0). This means the Root trusts any policy defined below it. You want this at the top.
- **Intermediate / Policy CA:** Define your specific policy OIDs here. This is where you register your organization's policies, one per issuance class (e.g., standard validation, high assurance, code signing).
- **Issuing CA:** Reference a subset of the policies from the intermediate. Or the same set. But never a policy OID that does not exist in the parent certificate.

To get your own policy OIDs, register a Private Enterprise Number (PEN) with IANA. It is free and takes a few days. You get a root OID under `1.3.6.1.4.1.{your-number}`, and you can define your own policy tree below it. Podans documented the entire process and the technical implementation in his two-part series on Certificate Policies (linked in the sources below).

#### Get it right before you install

The OID mistake from the introduction of this article happened because nobody checked the policy hierarchy before writing CAPolicy.inf. The lesson is simple: before you write a single OID into your CAPolicy.inf, map the entire policy hierarchy from Root to Issuing. Verify which OIDs exist at every level. Your Issuing CA's policies must be a subset of what the parent allows. If the Root uses All Issuance Policies (2.5.29.32.0), any child policy is valid. If the Root or Intermediate defines specific policies, your Issuing CA must use those exact OIDs or a subset. Podans documented the mechanics in detail in his two-part series (linked in the sources below).

There is no way to change Certificate Policies after the CA certificate is issued.

### PathLength Constraint: A Planning Decision You Cannot Afford to Skip

PathLength is a basic extension that controls how many levels of subordinate CAs can exist below a given CA.

- **PathLength = 0:** This CA can issue end-entity certificates (certificates to users, servers, devices) but cannot issue subordinate CA certificates.
- **PathLength = 1:** This CA can issue one level of subordinate CAs. Those subordinate CAs must have PathLength = 0.
- **No PathLength constraint:** Unlimited. This CA can issue subordinate CAs, which can issue subordinate CAs, forever.

For an Issuing CA, you want PathLength = 0. It should only issue end-entity certificates. If it can issue subordinate CAs, then anyone with the ability to request certificates can potentially request a subordinate CA certificate and set up their own rogue CA under your hierarchy.

You set PathLength in CAPolicy.inf at install time:

```
[BasicConstraintsExtension]
PathLength=0
Critical=TRUE
```

One thing to be aware of: ADCS does not validate field names in CAPolicy.inf. Unknown or misspelled fields are silently ignored. No error, no warning. If PathLength is not in the resulting certificate, your CA has no depth restriction at all.

The solution: always verify the resulting CA certificate against your expected configuration after installation. Do not trust that the script ran successfully. Open the certificate, check the Basic Constraints extension, confirm PathLength is present and set correctly. Automate this verification step. A post-install check that compares the certificate extensions to your design document takes five minutes to build and saves you from discovering the gap years later during an audit.

### Hard vs Soft Restrictions: Plan for Flexibility

Name Constraints and EKU Qualified Subordination are HARD restrictions. They are in the CA certificate. They are immutable (barring revocation and re-issue). They are your last line of defense if everything else fails.

There is another layer: SOFT restrictions. These are enforced by policy modules like TameMyCerts (covered in Part 5). TameMyCerts runs on the Issuing CA and validates every certificate request against a configurable policy. It can enforce subject name patterns, SAN validation, issuance approval workflows, EKU restrictions at the template level, and more.

The key difference: TameMyCerts policies can be updated without rebuilding the CA. You can tighten restrictions, add exceptions, adjust rules as your environment evolves. This is the flexibility layer.

The planning decision you make now is: how much to lock down via hard constraints (Name Constraints + EKU in the CA cert) versus soft constraints (TameMyCerts policy)?

My approach:

- **Use hard constraints for broad, permanent boundaries.** If you know this CA will never issue certificates outside `internal.company.com`, bake that in. If it is dedicated to TLS and will never do code signing, bake that in.
- **Use soft constraints for fine-grained, evolving rules.** Subject name formats. SAN patterns. Approval workflows for certain templates. These change over time. Keep them in TameMyCerts where you can adjust them.

This is defense in depth. The hard constraints protect you if TameMyCerts is misconfigured or disabled. The soft constraints give you the day-to-day control and flexibility you need.

---

## Part IV: Operational Planning

These decisions affect how you operate, maintain, and recover your PKI. They are not baked into certificates, but they are just as critical to get right before installation.

### Role Separation: The Right Design That Nobody Enables

ADCS supports role-based access control that separates CA administration from certificate management. The roles are distinct: the CA Administrator configures the CA and manages its settings. The Certificate Manager approves and revokes certificate requests. The Enrollment Agent requests certificates on behalf of others. The Backup Operator handles CA backups.

When role separation is enabled, no single account can perform all operations. A CA Administrator cannot issue certificates. A Certificate Manager cannot change CA configuration. This is separation of duties, and for production PKI in regulated environments it is the correct design.

In practice, most organizations do not enable it.

The reason is operational friction. When the PKI administrator who configured a certificate template also needs to test-issue a certificate against that template, role separation prevents it. The administrator must ask someone with the Certificate Manager role to approve the request. In small teams where one or two people manage the entire PKI, this feels like bureaucracy for its own sake.

That friction is the point. The same mechanism that prevents you from test-issuing a certificate also prevents a compromised admin account from silently issuing certificates to itself. In environments where PKI issues authentication certificates (smart card logon, domain controller certificates), an unrestricted CA admin account is an escalation path to domain compromise.

My recommendation: enable role separation for production Issuing CAs. Plan your team structure around it before installation. If you have a two-person PKI team, assign one as CA Admin and one as Certificate Manager. If you are the only PKI administrator, keep role separation disabled but document the risk acceptance. This is a conscious decision, not a default you accept without thinking.

The configuration itself is straightforward (a checkbox in CA properties), but its implications cascade through your operational procedures. Every runbook, every template change workflow, every emergency procedure must account for which role can perform which action. Plan this before you install, not after the first time someone cannot issue a certificate and does not understand why.

### Backup and Recovery: Plan It Before You Need It

CA backup and recovery is not an operational detail. It is a planning decision because the consequences of getting it wrong are catastrophic and the recovery procedure depends on choices you make at installation time.

If your Issuing CA fails and you cannot restore it, every certificate it issued is orphaned. You cannot revoke them. You cannot renew them. You cannot publish CRLs. The certificates keep working until they expire or until the last published CRL expires, whichever comes first. Then everything stops.

What to plan before installation:

**CA private key backup.** The CA's private key is the single most critical artifact in your PKI. Back it up to a PKCS#12 file, encrypted with a strong password, stored offline. If you use an HSM, verify the HSM vendor's key backup and restore procedure. Test it. A key backup you have never restored is not a backup.

**CA database backup.** Use the built-in ADCS backup (certutil -backup) or Windows Server Backup with the CA role-aware writer. Back up the database and logs. Store them separately from the OS backup. This is why the database belongs on a separate volume (covered in the next section).

**Backup frequency.** For an active Issuing CA, daily backups are the minimum. Every certificate issued between the last backup and a failure is lost in the restore. In high-volume environments, consider more frequent backups.

**Recovery procedure documentation.** Write the full restore procedure. Step by step. Store it outside the CA (obviously). Include: where the backups are stored, how to access them, the encryption password (or who holds it), the HSM restore procedure, and the expected recovery time.

**Test the restore.** At least once a year, restore the CA to a test environment. Verify that the database is intact, the private key works, and you can issue and revoke certificates. A backup you have never tested is a hope, not a plan.

**Root CA backup is different.** The Root CA is offline. Back up its private key and database after every operation (certificate issuance, CRL publication). Store the backup media in a separate physical location from the CA itself. If the safe containing your Root CA burns down, the backup in the same safe is useless.

Part 7 covers backup and recovery procedures in operational detail. This section is about the planning decision: decide your backup strategy, test it, and document it before your CA issues its first certificate.

### Key Archival: Know When You Need It

Key archival allows the CA to store a copy of a certificate's private key in its database at issuance time, so it can be recovered later if the original is lost. This applies only to encryption certificates, not signing certificates. ADCS enforces this: if a template is configured for digital signature only, the CA will refuse to archive the key.

The primary use case is encrypting persistent data. If an employee encrypts files with EFS or S/MIME email, and then loses their private key (hardware failure, account reset, leaving the organization), the encrypted data is unrecoverable without key archival. For organizations that rely on email encryption or EFS, key archival is not optional.

For most other certificate types (TLS server, client authentication, code signing), key archival is unnecessary and undesirable. You do not want the CA holding copies of TLS private keys.

The planning decision: identify which certificate templates serve encryption use cases (S/MIME, EFS, document encryption) and enable key archival on those templates. Designate one or more Key Recovery Agents (KRA) and enroll their certificates before enabling archival. The KRA certificate must exist in the CA's configuration before the first archived key is stored. This is a "configure before you issue" decision.

There is an operational trap here. Default KRA certificates have a 2-year validity. When a KRA certificate expires and is replaced, previously archived keys are not re-encrypted with the new certificate. The KRA must maintain the entire history of their certificates and private keys to decrypt older archives. Over a 20-year CA lifetime with 2-year KRA certificates, that is 10 different key pairs per KRA. Keys get lost during computer replacements and migrations. This is where key recovery fails in practice, not in theory.

Podans proposed an elegant solution: use self-signed KRA certificates with a validity matching the CA lifetime. Self-signed is acceptable here because KRA certificates only need to be trusted by the CA itself, not by any external party. Create a pair of long-lived self-signed KRA certificates, store the private keys on smart cards or HSM, install the certificates as trusted only on the CA server, and configure them as KRA certificates. This reduces the number of keys to maintain from 10 to 1 per KRA, and aligns KRA certificate renewal with CA renewal. See Podans' article on KRA certificate management (linked in sources) for the full implementation.

### CA Database Location: Separate It From Day One

This is a short one, but it matters. Place the CA database and log files on a separate volume from the operating system. Not the same disk. Not the same partition. A separate physical or logical volume.

Two reasons. First, backup and restore. If you need to restore the CA, having the database on a dedicated volume simplifies the procedure. You can back up and restore the CA database independently from the OS. If the OS disk fails, the database survives. If the database needs recovery, the OS is untouched.

Second, performance. In high-volume environments (tens of thousands of issuances per day), the CA database generates significant I/O. Sharing a disk with the OS means competing for I/O bandwidth. On a dedicated volume, the database gets its own throughput.

Configure this during ADCS installation. The setup wizard asks for the database and log file locations. Do not accept the defaults (which place everything on C:). Point them to a separate volume. This is a one-time decision that you cannot easily change after installation without migrating the database.

### CRL and AIA Publication: Plan Before You Install

CRL Distribution Points (CDP) and Authority Information Access (AIA) URLs are embedded in every certificate your CA issues. Once a certificate is issued with a specific CDP or AIA URL, that URL must remain reachable for the entire lifetime of that certificate. Changing these URLs after installation means all previously issued certificates still point to the old location.

This makes CDP and AIA configuration a planning decision, not an operational one.

Before you install your Issuing CA, decide:

- **The hostname for your CDP and AIA.** Use a dedicated alias (like `pki.yourdomain.com`), not the CA server's hostname. This lets you move the web server later without invalidating certificates.
- **HTTP only.** Do not use LDAP in CDP or AIA extensions. Part 4 covers the reasons in detail: replication lag, non-domain clients, information disclosure.
- **Web server infrastructure.** Your CDP web server must be highly available. CRL availability is more critical than CA availability. If the CDP is unreachable, certificate validation fails for every certificate issued by that CA.

Configure CDP and AIA in ADCS immediately after installation, before issuing any certificates. The first certificate you issue carries these URLs for its entire validity period.

Part 4 covers CRL validity periods, delta CRLs, OCSP configuration, and CRL partitioning in detail. This section is about the planning decision: know your URLs before you install.

---

## Putting It All Together: The Planning Checklist

Before you install your first CA, answer these questions:

**Before you install:**
1. **Delegation of Control:** Who manages the PKI? Set up dedicated PKI admin permissions before installation, not after. Ensure they have the right knowledge, not just the right permissions.
2. **Certificate-based authentication:** Will this CA issue authentication certificates? Understand what NTAuth enables. Decide on template hardening, policy modules, and EKU restrictions before you go to production.

**Architecture:**
3. **Tier choice:** 2-tier or 3-tier? (Spoiler: almost always 2-tier.)
4. **HSM:** What hardware will protect your Root and Issuing CA private keys?
5. **Root CA platform:** Windows or Linux? Pick what your team can maintain for 15 years.
6. **Naming convention:** What will you call your CAs? (Think 10 years ahead.)
7. **Certificate lifetimes:** Root 15yr, Issuing 5yr. When will you renew each?
8. **Root CA renewal strategy:** Renew with same key or new key? When do you start planning for it?

**Security constraints:**
9. **Name Constraints:** Do you need to restrict DNS/email namespaces per CA?
10. **EKU Qualified Subordination:** Do you need to restrict certificate types per CA?
11. **Certificate Policy OIDs:** Map the policy hierarchy from Root to Issuing. Register your PEN with IANA. Verify parent CA policies before defining your own.
12. **PathLength:** Set to 0 for Issuing CAs. Verify it in the certificate after installation.
13. **Hard vs Soft:** What gets locked in the CA cert, and what stays configurable via TameMyCerts?

**Operational planning:**
14. **Role separation:** Enable it for production CAs. Plan your team roles (CA Admin vs Certificate Manager) before installation.
15. **Backup and recovery:** Define your backup strategy, key backup location, and recovery procedure. Test the restore before going to production.
16. **Key archival:** Do you have encryption use cases (S/MIME, EFS)? If yes, plan KRA enrollment and enable archival on those templates.
17. **CA database location:** Separate volume for database and log files. Not on C:.
18. **CDP and AIA URLs:** Decide your publication hostname and protocol (HTTP only) before issuing any certificates.

Document your answers. Put them in version control. These decisions define your PKI for the next 10-15 years.

Get them right now. Because there is no undo button.

## What's Next

Part 3 covers cryptography choices. RSA 4096 vs ECC. SHA-256 vs SHA-384. PKCS#1 v2.1 signature algorithms. Post-quantum readiness. Key lengths that matter and the ones that don't.

You have planned your hierarchy. Now you need to choose the algorithms that will secure it for the next decade.

---

**Next in series:** Part 3 - Cryptography in 2026
**Previous in series:** Part 1 - What I Learned Running Enterprise PKI

---

**Sources:**
- Vadims Podāns (Crypt32): [Certificate Policies extension - all you should know (Part 1)](https://www.sysadmins.lv/blog-en/certificate-policies-extension-all-you-should-know-part-1.aspx)
- Vadims Podāns (Crypt32): [Certificate Policies extension - all you should know (Part 2)](https://www.sysadmins.lv/blog-en/certificate-policies-extension-all-you-should-know-part-2.aspx)
- Vadims Podāns (Crypt32): [Key Recovery Agent certificate management](https://www.sysadmins.lv/blog-en/key-recovery-agent-certificate-management.aspx) (self-signed KRA solution)
- Vadims Podāns (Crypt32): [Blog](https://www.sysadmins.lv/) - PowerShell PKI module author and ADCS expert
- Vadims Podāns (Crypt32): [PSPKI - PowerShell PKI Module](https://github.com/Crypt32/PSPKI) - open-source ADCS management and automation
- Uwe Gradenegger (Sleepw4lker): [EKU Qualified Subordination and CA certificate restrictions](https://www.gradenegger.eu/en/) (comprehensive ADCS reference)
- Uwe Gradenegger (Sleepw4lker), TameMyCerts: [Policy module for ADCS](https://github.com/Sleepw4lker/TameMyCerts) (open-source, certificate request validation)
- Uwe Gradenegger (Sleepw4lker), TameMyCerts: [Documentation](https://docs.tamemycerts.com/)
- IANA: [Private Enterprise Numbers (PEN) registration](https://www.iana.org/assignments/enterprise-numbers/)
- NIST: [IR 8547 - Transition to Post-Quantum Cryptography Standards](https://csrc.nist.gov/pubs/ir/8547/ipd)
- NIST: [SP 800-131A Rev 3 - Transitioning the Use of Cryptographic Algorithms](https://csrc.nist.gov/pubs/sp/800/131/a/r3/ipd)
- Microsoft Security Blog: [Post-Quantum Cryptography APIs Now Generally Available on Microsoft Platforms](https://techcommunity.microsoft.com/blog/microsoft-security-blog/post-quantum-cryptography-apis-now-generally-available-on-microsoft-platforms/4469093) (November 2025)
- Microsoft Support: [KB5014754 - Certificate-based authentication changes on Windows domain controllers](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16) (Strong Certificate Mapping enforcement timeline)
- Uwe Gradenegger (Sleepw4lker): [Automatically add the SID certificate extension to certificates requested via MDM - with TameMyCerts](https://www.gradenegger.eu/en/automatically-add-the-security-identifier-sid-certificate-extension-to-certificates-requested-via-mobile-device-management-mdm-with-the-tamemycerts-policy-module-for-microsoft-active-directory-certificate-services-adcs/) (SID extension for non-autoenrollment scenarios)
- Richard M. Hicks: [Strong Certificate Mapping Enforcement February 2025](https://directaccess.richardhicks.com/2025/01/27/strong-certificate-mapping-enforcement-february-2025/) (practical impact and preparation)
