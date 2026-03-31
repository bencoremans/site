---
layout: post
title: "Templates: The Configuration That Defines Your Security Posture"
date: 2026-04-14
categories: [pki, adcs, security]
tags: [ADCS, PKI, enterprise, certificate-authority]
author: Ben Coremans
published: false
---

# Templates: The Configuration That Defines Your Security Posture

Certificate templates are where PKI theory meets reality. Everything you planned in Part 2, every algorithm you chose in Part 3, every revocation strategy from Part 4, it all flows through templates. A well-designed template enforces your security policy automatically. A poorly designed one hands domain admin to the first attacker who finds it.

Most Active Directory Certificate Services (ADCS) deployments I have seen use default templates with minimal modification. This is not a configuration choice. It is a security incident waiting to happen.

## Why Default Templates Are Dangerous

When you install an Enterprise CA, ADCS creates a set of default certificate templates. These templates are Schema Version 1. They were designed in the Windows 2000 era. They cannot be modified (you can only duplicate them), and their security model reflects assumptions from a time when certificate attacks were not part of the threat landscape.

The problems are concrete:

**Overly broad enrollment permissions.** Default templates like "Computer" and "User" grant enrollment rights to Domain Computers and Domain Users respectively. Every computer and every user in the forest can request certificates. In a multi-tenant or segmented environment, this means a workstation in HR can enroll for the same certificate template as a server in finance.

**Subject name from AD.** Most default templates auto-populate the subject name from Active Directory attributes. This sounds convenient until you realize it means the certificate content is determined by whoever controls the AD object, not by who should control certificate identity.

**No SAN validation.** Default templates do not validate Subject Alternative Name content. Combined with certain enrollment flags, this is the foundation of the ESC1 attack vector.

**Schema Version 1 cannot be hardened.** You cannot change the CSP/KSP settings, add issuance requirements, or modify most security-relevant settings on V1 templates. And V1 templates are vulnerable to ESC15: an attacker can inject arbitrary Application Policies extensions into certificate requests against V1 templates, because V1 templates do not filter these extensions.

The first step after installing any Enterprise CA: do not publish any default templates. Duplicate the ones you need, harden the duplicates, and publish only those.

### The NDES Trap

Even if you follow this advice, other role installations can undo your work. The NDES installer is the worst offender. When you install the Network Device Enrollment Service using the standard configuration wizard (`Install-AdcsNetworkDeviceEnrollmentService`), it automatically publishes two V1 templates on the CA: **CEPEncryption** and **Exchange Enrollment Agent (Offline Request)**. You do not get to choose. The installer requires Enterprise Admin rights, uses ancient user-based templates instead of machine templates, and may restart the CA service during installation.

The correct approach is to bypass the wizard entirely: install the NDES binaries without running the configuration cmdlet, create your own V2 machine-based RA templates, and configure NDES manually via the registry. Uwe Gradenegger documented this method in detail, and I have written a separate series on NDES deployment that covers the full process. The point for this article: be aware that role installations can silently publish V1 templates on your CA, even after you have cleaned them up.
- Uwe Gradenegger (Sleepw4lker): [Blog](https://www.gradenegger.eu/en/) - comprehensive ADCS and PKI reference

## Template Versioning: V1, V2, V3, V4

Template versions correspond to schema versions in Active Directory, not to the Windows version that introduced them. Understanding the differences matters because they affect security, crypto provider choice, and compatibility.

**Schema Version 1 (V1).** These are the built-in defaults. Not duplicatable in a useful way for hardening since the duplicate becomes V2+. The originals cannot be modified. Key limitation: no issuance requirements, no application policies filtering, no KSP support. Vulnerable to ESC15. Recommendation: unpublish all V1 templates from production CAs.

**Schema Version 2 (V2).** Introduced with Windows Server 2003. Supports CSP selection, issuance requirements (CA Manager approval, authorized signatures), and key archival. V2 templates are the safe choice for services that require CSP (NDES, Intune Connector, ADWS), as discussed in Part 3.

**Schema Version 3 (V3).** Introduced with Windows Server 2008. Adds KSP support, key attestation (TPM), and CNG algorithm selection. This is your default for all new templates. Use KSP unless you have a documented CSP dependency.

**Schema Version 4 (V4).** Introduced with Windows Server 2012 R2. Adds support for renewal with same key and key attestation policies. Use V4 when you need these features; otherwise V3 is fine.

The practical approach: create all new templates as V3 or V4. Keep V2 only for documented CSP dependencies. Remove all V1 templates from published template lists on production CAs. If a V1 template must remain (rare), understand the ESC15 risk and deploy TameMyCerts to filter Application Policies extensions.

## Subject Name: The Decision That Defines Your Attack Surface

How the subject name ends up in a certificate is the single most important security decision in template design. ADCS offers two approaches:

**Build from Active Directory information.** The CA auto-populates the Subject DN and SAN from AD attributes (UPN, email, DNS name, etc.). The user does not control what goes in the certificate. This is the safer default for user and computer certificates in a trusted AD environment.

**Supply in the request.** The requester specifies the Subject DN and SAN in the CSR. The CA accepts whatever the requester sends. This is necessary for web server certificates (the requester knows the server's FQDN) and for certificates issued to non-domain systems.

The danger is "Supply in the request" combined with enrollment permissions that are too broad. This is ESC1: if a template allows requesters to specify the SAN, and any domain user can enroll, an attacker can request a certificate with a domain admin's UPN in the SAN. That certificate authenticates as the domain admin.

The native ADCS mitigation is CA Manager approval: require manual approval for templates that allow supply-in-request with authentication EKUs. But CA Manager approval does not scale. If you issue hundreds of web server certificates per month, manual approval becomes a bottleneck that people route around.

This is where TameMyCerts becomes essential.

## TameMyCerts: The Enforcement Layer ADCS Should Have Had

TameMyCerts is an open-source policy module for ADCS. It intercepts every certificate request before issuance and validates it against configurable rules. It is the only tool I am aware of that closes the fundamental security gaps in the ADCS policy module.

I consider TameMyCerts non-negotiable for production ADCS deployments. Here is why, organized by what it prevents.

### ESC1: SAN Manipulation

When a template is configured for "Supply in the request" and includes Client Authentication or Smart Card Logon EKUs, any authorized requester can specify any SAN. TameMyCerts validates the requested SAN against a whitelist of allowed patterns per template. You can restrict SANs to specific DNS suffixes, specific UPN patterns, or require that the SAN matches the requesting machine's DNS name. A request with a SAN outside the allowed pattern is denied.

### ESC6/ESC7: EDITF_ATTRIBUTESUBJECTALTNAME2

This is the flag that has caused more forest compromises than any other single configuration error. When enabled on a CA, it allows any requester to add arbitrary SAN content via a request attribute, regardless of what the template specifies. Administrators enable it because they need to issue SAN certificates from templates that do not natively support it (typically because the requesting application cannot build a proper CSR with SAN). The flag is a global CA setting, not per-template.

TameMyCerts detects and blocks attempts to exploit this flag. Even if the flag is enabled (which it should not be, but sometimes is for legacy reasons), TameMyCerts will reject requests where the SAN attribute does not match the template's configured identity source.

Better yet, TameMyCerts solves the original problem that drives administrators to enable the flag. It can automatically construct a SAN extension from the Subject DN of the request (copying the CN to a dNSName SAN entry), making the certificates RFC 2818 compliant without enabling the dangerous flag.

### ESC15: Application Policies Injection

This is the newest attack vector, disclosed by TrustedSec in 2024. V1 templates do not filter the Application Policies certificate extension in requests. An attacker can submit a request against a V1 "Webserver" template and inject "Client Authentication" in the Application Policies extension. The issued certificate then contains both Server Authentication (from the template EKU) and Client Authentication (from the injected Application Policies), enabling authentication attacks.

TameMyCerts filters Application Policies extensions in certificate requests, preventing this injection regardless of template version.

### Key Algorithm Enforcement

As covered in Part 3: the ADCS policy module does not validate key algorithms at issuance time. If a template is configured for ECC P-256 and a requester submits an RSA key, ADCS will issue the certificate. TameMyCerts enforces key algorithm and key size validation per template.

### Per-Template CDP and AIA

Native ADCS configures CDP and AIA URLs at the CA level. Every certificate issued by that CA gets the same CDP and AIA URLs. TameMyCerts allows per-template override of CDP and AIA extensions. This is valuable in multi-tenant environments where different certificate consumers need different revocation endpoints, or where certain templates should point to a dedicated OCSP responder.

## Template Design Principles

With the tooling understood, here are the principles I follow when designing templates.

### Start with deny-all

Never start from a default template and remove what you do not need. Start with a blank duplicate, enable only what you need, and add permissions only for the specific groups that should enroll.

### One template per use case

Do not create generic templates. "Web Server" is not a use case. "Internal TLS for Application X on servers in OU Y" is a use case. Specific templates mean specific security controls. When template scope creeps, attack surface grows.

### Enrollment permissions follow the principle of least privilege

If only the web team needs TLS certificates, only the web team's security group gets Enroll permission. Not Domain Computers. Not Authenticated Users. A security group per template is not overhead; it is your access control.

### Autoenrollment: powerful but dangerous

Autoenrollment pushes certificates to machines and users via Group Policy. It is the right approach for domain controller certificates, workstation certificates, and user authentication certificates. But autoenrollment with broad enrollment permissions and auto-populated subject names means every machine or user in scope automatically receives a certificate. If the template is misconfigured, every machine in scope gets a misconfigured certificate. Test autoenrollment templates in a staging OU before deploying forest-wide.

### Issuance requirements for high-risk templates

Templates that allow "Supply in the request" with authentication EKUs should require either CA Manager approval or an authorized signature (from an enrollment agent). This is defense in depth on top of TameMyCerts SAN validation.

### Document every template

Maintain a template registry: template name, purpose, enrollment group, subject name source, EKUs, key algorithm, validity period, renewal settings, TameMyCerts policy rules. This registry is your audit artifact. When a penetration tester finds an ESC vector, you can trace exactly which template is affected and who has access.

## The EDITF_ATTRIBUTESUBJECTALTNAME2 Decision

This flag deserves its own section because the decision to enable or disable it will come up in every ADCS deployment.

**The flag should be disabled.** Period. It is a global CA setting that overrides per-template SAN configuration. Any requester can submit any SAN content, regardless of template design. Gradenegger documented how this flag leads to forest compromise, and SpecterOps classified it as ESC6 in the Certified Pre-Owned research.

The reason people enable it: legacy applications that submit CSRs without SAN extensions, and they need certificates with SAN for modern browser compatibility. The administrator enables the flag "temporarily." It stays enabled for years.

The correct solution: deploy TameMyCerts and use its SAN construction feature to automatically build RFC 2818 compliant SAN extensions from the Subject DN. This gives you the functionality without the attack surface.

If you inherit a CA with this flag enabled:

1. Install TameMyCerts immediately (it blocks ESC6 exploitation even with the flag enabled).
2. Identify which templates and applications depend on the flag.
3. Migrate those applications to proper CSR generation with SAN, or to TameMyCerts SAN auto-construction.
4. Disable the flag.
5. Monitor for broken enrollments.

## The SID Extension: Certificate-Based Authentication Hardening

Since the May 2022 patches (KB5014754), Microsoft added a Security Identifier (SID) extension to certificates used for authentication. This ties the certificate to a specific AD object, preventing certificate confusion attacks where a certificate issued to one principal is used to authenticate as another.

Microsoft has been rolling out enforcement in phases since 2022. In Windows Server 2025 and with recent cumulative updates for Server 2022 and 2019, Full Enforcement mode is the default for new installations. Older environments may still be in Audit mode, but the direction is clear: certificates without the SID extension will be rejected for authentication unless you explicitly opt out via registry settings.

The planning implication: every template used for authentication (Smart Card Logon, Client Authentication, Kerberos Authentication) must include the SID extension. For templates with "Build from AD," this happens automatically. For templates with "Supply in the request" (MDM enrollments, non-domain devices), you need TameMyCerts to validate and optionally inject the SID extension.

## MDM and NDES: Where Template Security Gets Real

Mobile Device Management deployments are where template security is tested hardest. MDM systems (Intune, Workspace One, Jamf, MobileIron) issue certificates to devices over the internet via SCEP/NDES. The devices are not domain-joined. The certificate requests come through a proxy (NDES or a cloud connector), not from the device directly.

This creates a specific threat model:

**The NDES service account enrolls on behalf of all devices.** From the CA's perspective, every MDM certificate request comes from the same identity: the NDES service account. If the template allows "Supply in the request" (which it must, because the MDM system specifies the device identity in the CSR), the NDES service account can request certificates with any subject name allowed by the template. If the template also includes authentication EKUs, this is ESC1 via the MDM enrollment path.

**MDM systems do not validate what they request.** The MDM system constructs the CSR based on its device record. If the device record is manipulated (compromised MDM console, API exploit, or simply a misconfigured MDM profile), the CSR will contain whatever the attacker injected. The CA sees a valid request from the NDES service account and issues the certificate.

**TameMyCerts closes this gap.** For NDES/MDM templates, configure TameMyCerts to:
- Validate that the Subject CN and SAN match expected patterns (e.g., device naming conventions, UPN suffixes)
- Restrict SAN types (only dNSName or only rfc822Name, depending on use case)
- Enforce key algorithm and minimum key size
- Filter Application Policies extensions (ESC15 prevention)

Gradenegger documented this scenario in detail, covering Intune, Workspace One, Jamf, and other MDM systems. The pattern is the same: the MDM system is not the security boundary, the CA policy is.

For NDES templates specifically: remember from Part 3 that the RA certificates must use CSP (V2 template). But the certificates issued through NDES to end devices can use V3/KSP. Keep these separate: one V2 template for the NDES RA certificates, and separate V3 templates for each device enrollment use case, each with its own TameMyCerts policy.

## Putting It Together: A Template Hardening Checklist

Before publishing any template to a production CA:

1. **Duplicate, never modify defaults.** Start from a copy. Name it clearly (prefix with your organization, include the use case).
2. **Set the minimum schema version.** V3 for KSP/CNG. V2 only for documented CSP dependencies.
3. **Restrict enrollment permissions.** Specific security groups only. Remove Authenticated Users and Domain Computers.
4. **Choose subject name source deliberately.** "Build from AD" for domain-joined resources. "Supply in the request" only with TameMyCerts SAN validation and issuance requirements.
5. **Set appropriate EKUs.** Only the EKUs needed for the use case. No "All purpose." No unnecessary authentication EKUs on server templates.
6. **Configure key algorithm and size.** RSA-2048 or RSA-4096 depending on use case. ECC only in controlled environments (Part 3).
7. **Set validity and renewal periods.** Match the certificate lifecycle to the use case. Short for TLS (1-2 years), longer for infrastructure certificates.
8. **Deploy TameMyCerts rules.** SAN validation, key algorithm enforcement, Application Policies filtering. Per template.
9. **Verify EDITF_ATTRIBUTESUBJECTALTNAME2 is disabled.** If it is enabled, install TameMyCerts first, then work toward disabling it.
10. **Unpublish all V1 templates.** If any must remain, deploy TameMyCerts to filter Application Policies (ESC15).
11. **Document the template** in your template registry.
12. **Test in staging.** Enroll a certificate, verify all extensions, validate with a test client, check the revocation path.

## Common Template Patterns

Over 10+ years I have settled on a set of template patterns that cover most enterprise use cases. These are starting points, not copy-paste configurations. Adjust enrollment groups, validity periods, and TameMyCerts rules to your environment.

**Internal Web Server (TLS).** V3, KSP, RSA-2048, Server Authentication EKU only. Supply in the request for Subject and SAN. TameMyCerts: restrict SAN to dNSName only, validate against allowed DNS suffixes (your internal domains). No authentication EKUs. No autoenrollment. 1-year validity.

**Workstation Authentication.** V3, KSP, RSA-2048, Client Authentication EKU. Build from AD (auto-populated from computer object). Autoenrollment via GPO. Enrollment group: a security group containing workstation OUs, not Domain Computers. 2-year validity with auto-renewal 6 weeks before expiry.

**User Authentication (Smart Card / WHfB).** V3, KSP, RSA-2048, Smart Card Logon + Client Authentication EKU. Build from AD. Autoenrollment. Enrollment group: specific user groups. SID extension included automatically. 1-year validity. Consider requiring TPM key attestation (V4) for high-security environments.

**Domain Controller.** V3, KSP, RSA-2048, Kerberos Authentication + Client Authentication + Server Authentication EKU. Build from AD. Autoenrollment. Enrollment restricted to Domain Controllers group only. This template is critical for AD security. Do not allow broad enrollment permissions. 1-year validity.

**OCSP Response Signing.** V3, KSP (required), RSA-2048, OCSP Signing EKU. Build from AD. No autoenrollment. Short validity (14 days default, auto-renewed by the OCSP responder). Enrollment limited to the OCSP responder's machine account.

**Code Signing.** V3, KSP, RSA-4096, Code Signing EKU only. Supply in the request. Require CA Manager approval. No autoenrollment. 1-year validity. TameMyCerts: validate Subject against allowed publisher names. Consider requiring TPM key attestation.

**MDM Device (via NDES/SCEP).** V3, KSP, RSA-2048, Client Authentication EKU. Supply in the request. TameMyCerts: validate SAN against device naming patterns, enforce key algorithm, filter Application Policies. Short validity (6-12 months). NDES RA certificate on a separate V2/CSP template.

These patterns share common traits: minimal EKUs, restricted enrollment permissions, explicit TameMyCerts rules, and appropriate validity periods. When someone asks for a "quick certificate template," point them to this list and ask which pattern matches their use case.

## What TameMyCerts Does Not Replace

TameMyCerts is a policy module, not a permission model. It validates certificate requests at issuance time. It does not replace:

- **Template permissions.** TameMyCerts cannot restrict who enrolls. That is an AD permission on the template object.
- **CA-level restrictions.** Name Constraints, EKU Qualified Subordination, and PathLength are baked into the CA certificate (Part 2). TameMyCerts operates below that level.
- **Monitoring.** TameMyCerts blocks bad requests. It does not alert you to patterns of bad requests. You still need audit logging and SIEM integration (Part 7).

Think of it as defense in depth: hard restrictions in the CA certificate, soft restrictions in TameMyCerts, access control in template permissions, and visibility through monitoring. Each layer catches what the others miss.

---

**Sources:**
- Uwe Gradenegger (Sleepw4lker): [TameMyCerts introduction](https://www.gradenegger.eu/en/a-policy-module-to-help-you-to-build-your-business-introduction-of-the-tamemycerts-policy-module/)
- Uwe Gradenegger (Sleepw4lker): [TameMyCerts ESC6/ESC7 prevention](https://www.gradenegger.eu/en/how-tamemycerts-can-detect-and-stop-attacks-against-the-esc6-attack-vector/)
- Uwe Gradenegger (Sleepw4lker): [TameMyCerts ESC1 prevention](https://www.gradenegger.eu/en/how-tamemycerts-can-reduce-severity-of-attacks-against-the-esc1-attack-vector/)
- Uwe Gradenegger (Sleepw4lker): [TameMyCerts SAN auto-construction (RFC 2818)](https://www.gradenegger.eu/en/how-tamemycerts-can-repair-incoming-certificate-requests-to-make-them-rfc-compliant-uc-supplement-dns/)
- Uwe Gradenegger (Sleepw4lker): [ESC15 vulnerability and countermeasures](https://www.gradenegger.eu/en/new-security-vulnerability-discovered-in-active-directory-certificate-services-and-easy-to-implement-countermeasures/)
- Uwe Gradenegger (Sleepw4lker): [EDITF_ATTRIBUTESUBJECTALTNAME2 forest compromise](https://www.gradenegger.eu/en/take-over-the-active-directory-overall-structure-with-the-flag-editf_attributesubjectaltname2/)
- Uwe Gradenegger (Sleepw4lker): [Key algorithm not checked by policy module](https://www.gradenegger.eu/en/key-algorithm-is-not-checked-by-the-policy-module/)
- Uwe Gradenegger (Sleepw4lker): [Template generations/versions](https://www.gradenegger.eu/en/description-of-the-generations-of-certificate-templates/)
- SpecterOps: [Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2) (ESC1-ESC8)
- TrustedSec: [EKUwu - ESC15](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- Uwe Gradenegger (Sleepw4lker), TameMyCerts: [Documentation](https://docs.tamemycerts.com/)
- Uwe Gradenegger (Sleepw4lker), TameMyCerts: [GitHub](https://github.com/Sleepw4lker/TameMyCerts)
- Microsoft: [KB5014754 - Certificate-based authentication changes](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)

---

**Previous in series:** Part 4 - Revocation
**Next in series:** Part 6 - Automation