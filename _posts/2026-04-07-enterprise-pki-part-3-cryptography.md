---
layout: post
title: "Cryptography in 2026: Choosing Algorithms for Enterprise PKI"
date: 2026-04-07
categories: [pki, adcs, security]
tags: [ADCS, PKI, enterprise, certificate-authority]
author: Ben Coremans
published: false
---

# Cryptography in 2026: Choosing Algorithms for Enterprise PKI

Every PKI deployment starts with the same set of questions. RSA or ECC? SHA-256 or SHA-384? What about post-quantum? Is PKCS#1 v1.5 still acceptable, or should I enable the "more secure" option?

These questions feel deceptively simple. Pick the strongest algorithm, apply it everywhere, move on. But enterprise PKI does not work that way. Algorithm choice in 2026 is a balancing act between security, compatibility, operational reality, and a migration horizon that is not as distant as people assume.

I'll tell you what I chose, why I chose it, and where the traps are.

## RSA-4096: The Bridge Algorithm

The RSA vs ECC debate has been going on for years. ECC wins on paper: smaller keys, faster operations, equivalent or better security at lower bit counts. P-256 provides 128 bits of security, roughly equivalent to RSA-3072. P-384 provides 192 bits, comparable to RSA-7680.

So why am I running RSA-4096 on both my Root CA and Issuing CA?

Three reasons.

**First: compatibility.** RSA works everywhere. Not "most places" or "all modern systems." Everywhere. Every Windows version from XP SP3 forward. Every Java runtime. Every network appliance. Every VPN client. Every printer. Enterprise networks accumulate legacy systems the way old houses accumulate electrical standards. RSA-4096 is the algorithm that signs certificates that everything will accept without complaint.

**Second: the Active Directory Certificate Services (ADCS) limit.** The ADCS GUI caps key size at 4096 bits. You can go higher via certutil and manual configurations, but doing so puts you outside the normal operating envelope. In a production environment with multiple administrators, "works only when you remember the special procedure" is a risk. 4096 bits in the GUI is clean, documented, supported.

**Third: the quantum argument does not hold above 4096.** This is the one that surprises people. The intuition is: bigger keys = more quantum resistance. Unfortunately, that is not how Shor's algorithm works.

Shor's algorithm breaks RSA by solving the integer factorization problem in polynomial time on a quantum computer. The critical point: its runtime scales sub-exponentially with key size. Going from RSA-2048 to RSA-4096 does not double your quantum resistance, it adds a few weeks of quantum compute time. Going to RSA-8192 or RSA-16384 adds more weeks, maybe months. But it does not change the fundamental outcome. A sufficiently powerful quantum computer breaks all of them. The only protection against quantum is post-quantum cryptography, not bigger RSA keys.

Gradenegger's analysis confirms this clearly: RSA-4096 with SHA-256 and PKCS#1 v1.5 is the correct enterprise standard today. The only reason to go higher would be certain compliance frameworks with unusual requirements, and those are rare.

For your Root CA and Issuing CA, RSA-4096 is your answer. It is the most compatible, within the ADCS GUI limit, and appropriately sized for the threat model. Spend your energy on PQC planning instead.

## ECC: Tempting, But Read This First

ECC is genuinely attractive. Smaller certificates mean faster handshakes. P-256 is computationally faster than RSA-2048 for signature verification. For high-volume TLS environments, that matters.

But ECC in an enterprise PKI is not "deploy everywhere and enjoy the benefits." It has a compatibility matrix that will cause production incidents if you ignore it.

Here is what I know from Gradenegger's research and direct experience:

**NDES/SCEP RA certificates:** Not supported. NDES still relies on the legacy CryptoAPI stack (CSP), and ECC is a CNG construct. If you configure ECC for your Issuing CA and then try to deploy NDES, the RA certificate enrollment will fail.

**Microsoft Intune:** Not supported for certain enrollment flows. Intune's certificate connector has known limitations with ECC keys. This matters in any organization moving toward Intune-based device management, which is most enterprises right now.

**VMware Workspace One:** Not supported. If you are deploying ECC issuing CA certificates in an environment with Workspace One for MDM, you are looking at enrollment failures.

**Windows Defender Application Control (WDAC):** Not supported. Microsoft's own documentation explicitly states that ECDSA is not supported in WDAC policy signing. This one is easy to miss because WDAC is often managed by a separate team from PKI.

**Domain Controller certificates:** Technically supported, but with client-side compatibility caveats. Older Windows clients may have issues. If your environment spans Windows Server 2016 and Windows 10 1903, test this thoroughly before deploying.

**TPM autoenrollment with ECC keys:** Works only from Windows 10 21H2 and Windows 11 forward. Anything older will fail silently or fall back to RSA.

The NSA's guidance is instructive here. Suite B specified P-256 for Secret and P-384 for Top Secret classification levels. But CNSA 2.0 (CNSSP-15), published in September 2022, explicitly discourages new ECC deployments because post-quantum cryptography is on the horizon and ECC does not survive it. The resources you spend building an ECC-everywhere PKI today will need to be rebuilt for PQC anyway.

My recommendation: do not deploy ECC on your CA hierarchy. Use RSA-4096 for Root and Issuing CAs. If specific endpoint templates benefit from ECC keys (server TLS in controlled environments, for example), use them there, but know which systems will receive those certificates and verify the compatibility matrix first.

ECC for client certificates in a tightly controlled Windows 10 21H2+ fleet with no NDES, no Intune connector, no Workspace One: fine. ECC for your Issuing CA signing endpoint certificates that go to everything: a support ticket waiting to happen.

## SHA-256: Not Boring, Just Correct

People sometimes ask if they should use SHA-384 or SHA-512 for their CA certificates. The logic is understandable: bigger hash = more security.

The answer is SHA-256. Not because it is "good enough," but because it is the right tool for the job.

SHA-256 provides 128 bits of collision resistance. For a CA certificate, this means an attacker trying to forge a certificate signature would need, on average, 2^128 attempts. That number is computationally unreachable with any classical hardware. It will also not be reachable with quantum computers using Grover's algorithm, because Grover provides a quadratic speedup on symmetric operations, not an exponential one. SHA-256 against Grover gives you 64 bits of effective security. SHA-384 gives you 96 bits. Neither changes the threat model in a meaningful way for certificate signing.

SHA-384 and SHA-512 produce larger signatures, consume more processing time, and generate larger certificates. In high-volume issuance environments, the cumulative effect on storage and network is real. The security gain over SHA-256 is theoretical.

The only scenario where you should reach for SHA-384 is NSA Suite B Top Secret compliance. If that applies to you, you already know it. For everyone else: SHA-256.

SHA-1 is dead. Windows Server 2022 and Windows 11 will not accept SHA-1 certificates in most contexts. If you have any infrastructure still issuing SHA-1, that is your most urgent cryptography problem and it has nothing to do with post-quantum.

## PKCS#1 v1.5 vs v2.1: Why I Keep the Old One

In your `CAPolicy.inf`, there is a setting called `AlternateSignatureAlgorithm`. Set it to 1 and your CA uses PKCS#1 v2.1 (also known as RSASSA-PSS). Set it to 0 and you use PKCS#1 v1.5.

The standard advice is to use the newer version because it addresses the Bleichenbacher attack. This is technically correct and practically misleading.

The Bleichenbacher attack exploits vulnerabilities in RSA PKCS#1 v1.5 signature padding. It is a real attack with real CVEs. However, and this is the part that gets overlooked: the Bleichenbacher attack works against TLS handshakes, specifically the RSA key exchange step in TLS 1.2 and earlier. It does not work against certificate signatures.

A certificate is a signed data structure. The signature is verified but not used in a way that exposes the padding oracle that Bleichenbacher requires. The threat model that motivates PKCS#1 v2.1 does not apply to certificate issuance.

Meanwhile, PKCS#1 v2.1 has real compatibility problems. Cisco devices have incomplete implementations. Some older network appliances do not handle PSS-signed certificates correctly. Vadim Podans documented the ASN.1-level differences between the two schemes in detail, and they are non-trivial. In production environments, this translates to certificate validation failures that are difficult to diagnose.

Gradenegger's analysis is clear: PKCS#1 v1.5 is the correct choice for enterprise PKI. The security motivation for v2.1 does not apply to certificates, and the compatibility risk is real.

Set `AlternateSignatureAlgorithm = 0`. Leave it there.

## CSP vs KSP: Always CNG, With Important Exceptions

ADCS supports two cryptographic provider frameworks. The old one is Cryptographic Service Provider (CSP), which uses the legacy CryptoAPI stack. The new one is Key Storage Provider (KSP), which uses Cryptography API: Next Generation (CNG).

Always use KSP.

KSP is required for ECC keys. KSP is required for SHA-2 certificate signing in certain configurations. KSP provides key isolation, where private key operations happen in a separate process, which reduces the attack surface for key extraction. KSP supports hardware attestation. KSP enables audit logging at the key level. The Microsoft Software Key Storage Provider and the Microsoft Platform Crypto Provider (for TPM-backed keys) are both KSP.

In ADCS template terms: Version 3 templates use KSP. Version 2 templates use CSP.

Here is where the exceptions matter, and there are more than one.

Several services and applications explicitly require CSP-based keys:

**NDES Registration Authority certificates.** The NDES service uses the legacy CryptoAPI stack internally. If the RA certificates are enrolled with a KSP-based template, NDES will not start. You get events 2 and 10 in the event log and a service that refuses to initialize.

**Intune Connector for NDES.** Requires CSP for its client authentication certificate. KSP-based certificates cause setup to fail with: `"CryptAcquireContext failed with bad provider type 0x0"` (error 0x80090014).

**Active Directory Web Services (ADWS).** If any certificate in the machine store uses a KSP, ADWS can fail with event 1402 and a CryptographicException: `"Invalid provider type specified."` This is particularly insidious because ADWS does not just check its own certificate; it scans the entire machine store. One KSP certificate on a domain controller can break ADWS even if the DC's own certificate is CSP-based.

**Legacy .NET applications using `RSACryptoServiceProvider`.** Applications that use this class require a CSP-based private key. If the certificate was enrolled with a KSP provider, key access fails with `"Invalid provider type specified" (NTE_PROV_TYPE_NOT_DEF 0x80090017)` or `"The parameter is incorrect."` The application enrolls successfully, but key operations fail at runtime.

On the other side: **OCSP signing certificates must use KSP.** The Microsoft Online Responder will not accept CSP-based signing certificates.

For all CSP-dependent cases, both Podans and Gradenegger recommend V2 templates. V3 templates can technically be configured with a CSP provider in the Cryptography tab, and this may work in some cases. But some services check more than just the key provider type; the enrollment request structure differs between V2 and V3, and legacy services may evaluate the template version itself. V3+CSP is worth testing in your environment, but V2 is the safe and documented choice.

Gradenegger maintains a complete list of CSP and KSP requirements by use case (linked in sources below). Consult it before deploying templates.

The practical approach: use V3/KSP as your default for all new templates. For services with known CSP dependencies, use V2 templates unless you have verified that V3+CSP works in your specific environment. Audit your CSP dependencies before deploying new templates. Over time, as Microsoft migrates these services to CNG, phase out the V2 templates.

The Platform Crypto Provider is worth a special mention. This KSP provider binds keys to the device TPM. For machine certificates and certain high-assurance user scenarios, TPM-backed keys mean that private keys are non-exportable at the hardware level. An attacker who compromises the OS cannot extract the key; it exists only in the TPM. The tradeoff is that TPM enrollment requires Windows 10 21H2 or newer for ECC keys, and some management tooling has limitations.

## The Security Gap in ADCS: Policy Module Does Not Check Key Algorithms

This one is worth its own section because it surprises almost everyone.

When you configure a certificate template for ECC P-256, you expect ADCS to reject RSA certificate requests against that template. Or at least to reject requests using the wrong ECC curve.

It does not.

The ADCS policy module does not validate key algorithms at issuance time. If a client submits an RSA key in a CSR against a template configured for ECC P-256, ADCS will issue the certificate. The key algorithm check you think is enforced is not enforced.

Gradenegger documented this in detail. The policy module simply does not inspect the submitted key type.

The practical implication: if you deploy ECC templates expecting strong key algorithm enforcement, and a misconfigured client or a legacy application submits an RSA key, you get a certificate issued against your security policy with no error and no audit event that flags the mismatch.

The fix is TameMyCerts. It is the only ADCS extension I am aware of that enforces key algorithm validation at issuance time. TameMyCerts can be configured to reject certificate requests where the submitted key does not match the template's configured algorithm and key size. This closes the gap.

If you care about strong key algorithm enforcement, TameMyCerts is not optional. It is the enforcement layer that the ADCS policy module should have provided natively.

## PQC: The 2030/2035 Deadlines Are Not Far Away

Post-quantum cryptography is not a 2040 problem. The timelines are concrete, the standards are final, and the ADCS infrastructure changes are already happening.

In August 2024, NIST finalized three post-quantum cryptography standards:

- **FIPS 203 (ML-KEM):** Key Encapsulation Mechanism based on CRYSTALS-Kyber. This replaces RSA and ECC for key exchange.
- **FIPS 204 (ML-DSA):** Digital Signature Algorithm based on CRYSTALS-Dilithium. This replaces RSA and ECDSA for signatures.
- **FIPS 205 (SLH-DSA):** Hash-based signature scheme based on SPHINCS+. A backup to ML-DSA.

NIST's explicit statement: "They can and should be put into use now."

The transition timelines from NIST IR 8547 and SP 800-131A:

**2030:** Classical algorithms at ~112-bit security strength (RSA-2048, ECC P-256) are **deprecated** for new systems. Deprecated means still allowed but must be phased out.

**2035:** All classical asymmetric cryptography is targeted to be **disallowed** in federal and high-assurance environments. RSA, ECC, ECDSA, EdDSA, Diffie-Hellman. For enterprises in regulated sectors, expect compliance frameworks to follow the federal timeline.

A Root CA you deploy today with a 15-year lifetime will expire in 2041. The 2035 disallowed date falls within the operational lifetime of that Root CA. Your "forever PKI" is not forever. It is a bridge.

Microsoft has already responded. Windows Server 2025 shipped GA support for ML-KEM and ML-DSA in CNG in November 2025. Microsoft announced that ADCS PQC certificate template support is targeted for early 2026, though GA availability has not been confirmed at the time of writing. Microsoft expanded ADCS database fields to 16,384 bytes to accommodate PQC certificate sizes; ML-DSA-65 signatures are approximately 3.3KB, compared to ~512 bytes for RSA-4096.

The Harvest Now, Decrypt Later (HNDL) threat is real and operating right now. Nation-state actors are recording encrypted traffic today with the intention of decrypting it when quantum computers become available. The NSA's "Quantum Computing and Post-Quantum Cryptography FAQ" and CISA's advisory on post-quantum preparedness both confirm this as an active collection strategy. For long-lived secrets, anything with a classification lifetime extending past 2030, HNDL is an active threat, not a theoretical one. If you handle government, defense, or financial data with long retention requirements, this is your most urgent cryptography issue.

For most enterprise PKI deployments, the practical guidance is:

Build now on RSA-4096. It is the right bridge algorithm. Plan PQC migration for the 2030-2033 window. Do not wait for 2035 to start.

## What to Configure Now and When to Migrate

The decisions flow from everything above.

For your CA hierarchy, deployed today:

Your Root CA and Issuing CA get RSA-4096 with SHA-256, PKCS#1 v1.5 (AlternateSignatureAlgorithm = 0), using the Microsoft Software Key Storage Provider (or your HSM vendor's KSP). Template V3. No ECC at the CA level.

For endpoint certificates, your templates should target RSA-2048 or RSA-4096 depending on the use case. TLS server certificates from an Issuing CA: RSA-2048 is fine (it will be deprecated in 2030, but you will reissue by then). High-assurance certificates: RSA-4096. If you need ECC in specific templates, verify the compatibility matrix first and deploy TameMyCerts to enforce key algorithm at issuance.

For PQC migration planning:

Start the assessment phase now. Document which systems handle long-lived sensitive data (HNDL priority). Inventory your certificate consumers by platform and version: which ones will support ML-DSA when it arrives. Check your HSM vendor's PQC roadmap; any HSM purchased in 2026 or later should have a clear path to FIPS 203/204/205 firmware support.

Target 2030-2031 for a PQC pilot using hybrid certificates. A hybrid certificate carries both an RSA/ECC signature and an ML-DSA signature. If the relying party supports ML-DSA, it validates the PQC signature. If not, it falls back to RSA/ECC. This is the migration strategy with the lowest compatibility risk.

Target 2033 for full PQC deployment. That gives you a two-year buffer before the 2035 disallowed date.

The one mistake I would avoid: delaying assessment because "the standards are too new." FIPS 204 is final. The signatures are not going to change. Start modeling your migration now.

## Summary: Every Decision at a Glance

| Decision | Recommendation | Reason |
|----------|---------------|--------|
| Root CA key algorithm | RSA-4096 | Maximum compatibility, ADCS GUI limit, Shor's algorithm breaks all RSA regardless of key size |
| Issuing CA key algorithm | RSA-4096 | Same as Root, plus Gradenegger confirmation |
| Hash algorithm | SHA-256 | Secure, fast, universal. SHA-384/512 add no meaningful security |
| Signature padding | PKCS#1 v1.5 (AlternateSignatureAlgorithm = 0) | Bleichenbacher does not apply to certs; v2.1 has real compat issues |
| Crypto provider | KSP (CNG) | Required for ECC, SHA-2, key isolation, audit. V3 templates |
| ECC at CA level | Avoid | NDES, Intune, Workspace One, WDAC all have known incompatibilities |
| ECC in endpoint templates | Conditional | Only in controlled environments; check compatibility matrix first |
| Key algorithm enforcement | TameMyCerts required | ADCS policy module does not validate key type at issuance |
| CSP-dependent services | V2 templates for NDES/ADWS/Intune | V3+CSP may work for .NET apps but V2 is the safe choice for services |
| PQC preparation | Start assessment now | 2030 deprecation, 2035 disallowed, HNDL is active |
| PQC pilot | 2030-2031 | Hybrid certs (RSA + ML-DSA), ADCS template support expected 2026 |
| Full PQC migration | 2033 | Buffer before 2035 hard deadline |

## Where This Leaves You

The PKI you deploy today will outlive most of the algorithm choices you make. A Root CA with a 15-year lifetime, initialized in 2026, runs until 2041. The algorithms you choose for it need to be correct for 2026 and survive to 2035.

RSA-4096 with SHA-256 and PKCS#1 v1.5 on KSP gets you to 2035. Not 2041, not forever, but to 2035. That is the point. You are building a bridge to PQC, not a permanent monument. Plan the bridge well, plan the crossing early, and you will not be scrambling in 2033 to migrate a PKI whose architecture makes PQC adoption impossible.

The cryptography choices in this article are not exciting. They are deliberate. Boring, correct, and built for the actual threat model. That is what production PKI engineering looks like.

Part 4 covers revocation. CRL vs OCSP, when each makes sense, and how to configure both without creating operational nightmares.

---

**Sources:**
- Uwe Gradenegger (Sleepw4lker): [Key sizes for CAs and certificates](https://www.gradenegger.eu/en/which-key-sizes-should-be-used-for-certification-bodies-and-certificates/)
- Uwe Gradenegger (Sleepw4lker): [ECC compatibility list](https://www.gradenegger.eu/en/list-of-use-cases-of-certificates-for-which-compatibility-with-elliptic-curve-ecc-based-keys-is-known/)
- Uwe Gradenegger (Sleepw4lker): [Elliptic curve basics for PKI](https://www.gradenegger.eu/en/basics-of-elliptic-curves-with-regard-to-their-use-in-the-public-key-infrastructure/)
- Uwe Gradenegger (Sleepw4lker): [Key, signature, and hash algorithm basics](https://www.gradenegger.eu/en/basics-key-algorithms-signature-algorithms-and-signature-hash-algorithms/)
- Uwe Gradenegger (Sleepw4lker): [PKCS#1 v2.1 for Root CA](https://www.gradenegger.eu/en/use-pkcs1-version-2-1-for-a-root-certification-authority-root-ca/)
- Uwe Gradenegger (Sleepw4lker): [CSP and KSP basics](https://www.gradenegger.eu/en/basics-cryptographic-service-provider-csp-and-key-storage-provider-ksp/)
- Uwe Gradenegger (Sleepw4lker): [CSP and KSP requirements by use case](https://www.gradenegger.eu/en/list-of-use-cases-for-certificates-that-require-certain-csp-or-ksp/)
- Uwe Gradenegger (Sleepw4lker): [Key algorithm not checked by policy module](https://www.gradenegger.eu/en/key-algorithm-is-not-checked-by-the-policy-module/)
- Uwe Gradenegger (Sleepw4lker): [Blog](https://www.gradenegger.eu/en/) - comprehensive ADCS and PKI reference
- Vadims Podāns (Crypt32): [Standard and alternate signature algorithms](https://www.sysadmins.lv/blog-en/standard-and-alternate-signature-algorithms.aspx)
- Vadims Podāns (Crypt32): [Blog](https://www.sysadmins.lv/) - PowerShell PKI module author and ADCS expert
- Vadims Podāns (Crypt32): [PSPKI - PowerShell PKI Module](https://github.com/Crypt32/PSPKI) - open-source ADCS management and automation
- Uwe Gradenegger (Sleepw4lker), TameMyCerts: [Policy module for ADCS](https://github.com/Sleepw4lker/TameMyCerts) (key algorithm enforcement)
- Uwe Gradenegger (Sleepw4lker), TameMyCerts: [Documentation](https://docs.tamemycerts.com/)
- NIST: FIPS 203, 204, 205 (August 2024)
- NIST IR 8547 / SP 800-131A Rev 3: Algorithm transition timelines
- NSA: [Quantum Computing and Post-Quantum Cryptography FAQ](https://media.defense.gov/2021/Aug/04/2002821837/-1/-1/1/Quantum_FAQs_20210804.PDF)
- CISA: [Post-Quantum Cryptography Initiative](https://www.cisa.gov/quantum)
- NSA: [CNSA 2.0 / CNSSP-15](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF) (September 2022)
- Microsoft: [Post-Quantum Cryptography APIs Now Generally Available](https://techcommunity.microsoft.com/blog/microsoft-security-blog/post-quantum-cryptography-apis-now-generally-available-on-microsoft-platforms/4469093) (November 2025)

---

**Previous in series:** Part 2 - Hierarchy & Planning: The Decisions That Define Your PKI  
**Next in series:** Part 4 - Revocation