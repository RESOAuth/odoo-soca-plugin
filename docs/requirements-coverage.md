# Requirements coverage

Assessed against [`soca-plugins/requirements.md` at `60ea4db827457b4a4a7b11d79e86b654612a75e1`](https://github.com/RESOAuth/soca-plugins/blob/60ea4db827457b4a4a7b11d79e86b654612a75e1/requirements.md).
Plugin version: **0.1.0a1**. Assessment/result date: **2026-10-21**.
This is an alpha assessment, not a certification or a production-ready release.
Supported means the stated bounded capability is implemented and has fixture evidence;
partial and planned rows retain the full target requirement without weakening it.

Evidence: [protocol fixtures](../tests/test_protocol.py), [native tests](../auth_soca/tests/test_host.py), [dated results](verification.md), [operations](operations.md),
[threat model](threat-model.md). Each row applies to this plugin version and date.

| ID | Status | Version | Evidence and remaining gap |
| --- | --- | --- | --- |
| F-01 | Partial | 0.1.0a1 | Exact discovery, isolated named profiles and explicit capability checks. Actual RESOAuth interoperability awaits a dated real login. |
| F-02 | Partial | 0.1.0a1 | Code flow, PKCE S256, independent state/nonce and ES256 private_key_jwt. Signed fixtures pass; provider and browser conformance remains. |
| F-03 | Partial | 0.1.0a1 | Issuer/subject/audience/nonce/time checks, exact response iss, conditional azp/hash claims and configured auth_time/acr/amr. Provider assurance semantics need operator verification. |
| F-04 | Partial | 0.1.0a1 | Public hosted CIMD/JWKS, application identity defaults and explicit HTTPS branding/legal overrides. Automated discovery of every host legal-page convention is incomplete. |
| F-05 | Partial | 0.1.0a1 | Default/custom path-only proxy templates, sorted compact UTF-8 JSON and unpadded base64url, document equality and hard size limits. Provider/proxy cache and URL limits require live confirmation; GUI reset remains planned. |
| F-06 | Supported | 0.1.0a1 | Only public keys/client metadata are published. Both inline jwks and jwks_uri are supported; public proxy disclosure documented and tested. |
| F-07 | Partial | 0.1.0a1 | Revision changes invalidate candidate evidence and pending callbacks. Automatic overlapping rotation, stable proxy key indirection and an identity migration wizard are planned. |
| F-08 | Partial | 0.1.0a1 | Persistent owner-only deployment P-256 keys and a separate encryption key. Non-exportable KMS/HSM, automated backup/restore and lost-key drills remain planned. |
| F-09 | Planned | 0.1.0a1 | Unattended overlapping rotation, cache warming, atomic promotion and monitoring are not implemented. Never replace keys as routine maintenance without a controlled migration. |
| F-10 | Partial | 0.1.0a1 | ES256/P-256 is pinned for assertions and defaults for verification. Python additionally verifies explicitly configured ES384/ES512/PS256/PS384/PS512/RS256. Fully specified EdDSA, ML-DSA, alternative assertion keys and all-algorithm published vectors remain gaps. |
| F-11 | Partial | 0.1.0a1 | Python fetches fresh issuer JWKS per login, with no stale cache or retry storm. Provider revocation feeds, coordinated key caches and forced-failure timing tests remain planned. |
| F-12 | Partial | 0.1.0a1 | Deny by default, verified boolean email, exact/wildcard DNS rules, deny precedence and save/startup validation. Sensitive accounts are blocked; a dedicated policy preview UI is planned. |
| F-13 | Partial | 0.1.0a1 | Only unique issuer/subject links resolve returning accounts. Disabled and privileged recovery accounts are rejected; no email auto-selection. Full per-site permission/session propagation tests remain. |
| F-14 | Partial | 0.1.0a1 | Opt-in atomic host account/link creation into portal access only, with collision refusal and no assigned password. Native positive/collision tests pass; multi-process fault injection remains planned. |
| F-15 | Partial | 0.1.0a1 | Existing local roles and privileges are preserved. No claim-driven elevation. Allowlisted role synchronisation and bounded revocation of existing SSO sessions are planned. |
| F-16 | Partial | 0.1.0a1 | Unique native issuer/subject associations require local administrator approval. Existing links are immutable; native deletion/reapproval provides recovery. Reauthentication UX and tamper-evident approval history remain gaps. |
| F-17 | Partial | 0.1.0a1 | No silent issuer/subject/email relinking. Explicit unlink/reapproval is required for migrations. Batch migration previews, pairwise-subject continuity and recovery drills remain planned. |
| F-18 | Partial | 0.1.0a1 | Create-only bounded text fields, ID-token precedence and subject-matched optional UserInfo. Returning local edits are preserved. Per-field mapping UI, custom claims and synchronisation policies are planned. |
| F-19 | Planned | 0.1.0a1 | No claim-inspection capture is implemented. Routine code never dumps tokens/claims. Operator-bound encrypted diagnostic reports and automatic expiry remain planned. |
| F-20 | Partial | 0.1.0a1 | Deployment configuration, host admin settings/check/test flows and revision-bound activation gates are implemented. Candidate tests validate without account/link/profile writes or operator-session replacement. Detailed stale-edit/rollback and all locked-field UI controls remain gaps. |
| F-21 | Partial | 0.1.0a1 | Native host sign-in/session/MFA and local logout are used. RP/back-channel logout, bounded SSO-session revocation and complete browser/loop tests remain planned. |
| F-22 | Partial | 0.1.0a1 | Deployment/environment emergency disable blocks ordinary/test SSO. Native local recovery stays enabled. Operators must invalidate transactions as part of disable deployment and rehearse host recovery. |
| F-23 | Partial | 0.1.0a1 | Native install/schema/auth/permission APIs and transaction cleanup. Disable invalidates transactions through provided maintenance actions. Existing-session revocation, uninstall preservation/export and rolling upgrade drills remain gaps. |
| F-24 | Supported | 0.1.0a1 | No offline scope or retained refresh/access/ID token. Ordinary admission requests openid email; Python provisioning adds profile. Codes and transient tokens are discarded after exchange. |
| F-25 | Partial | 0.1.0a1 | Encrypted transaction material, browser binding, 300-second expiry, unique state consumption and parallel tabs. Native host sessions rotate at sign-in. Full browser/concurrency/restore fault tests remain planned. |
| N-01 | Partial | 0.1.0a1 | Maintained JWT/cryptographic/host facilities, strict defaults and documented threat model. Independent security review and full conformance remain outstanding. |
| N-02 | Partial | 0.1.0a1 | HTTPS/TLS, public DNS/IP checks with connection pinning, no redirects/proxy inheritance, bounded bodies and read deadlines. DNS resolver total time and exhaustive IPv6/slow-response fault tests remain gaps. |
| N-03 | Partial | 0.1.0a1 | Minimal identity links and encrypted short-lived transactions, deployment-managed keys, no plugin token/claim logs. Reverse-proxy/host access-log redaction and backup deletion must be configured by the operator. |
| N-04 | Partial | 0.1.0a1 | Database uniqueness and atomic transaction consumption support shared workers. Failover, restore, rolling upgrades and availability objectives have not been validated. |
| N-05 | Partial | 0.1.0a1 | Bounded input/HTTP/state lifetime and scheduled cleanup. Deploy edge rate limits. Sustained abuse/load evidence and numeric capacity objectives remain planned. |
| N-06 | Partial | 0.1.0a1 | Native settings and labelled login controls, redacted errors and native audit facilities. WCAG 2.2 AA manual audit, tamper-evident records and full security metrics remain planned. |
| N-07 | Partial | 0.1.0a1 | Licence, install/recovery/security documentation, pinned dependencies/images/workflows, package checks, CI, Dependabot, CodeQL and vulnerability checks. Signed release provenance/SBOM and supported upgrade matrix are planned. |
| N-08 | Partial | 0.1.0a1 | Synthetic signed-token negative tests plus real host installation/account checks. No live provider login, browser conformance suite or independent review is claimed. |
| N-09 | Partial | 0.1.0a1 | This complete per-ID alpha assessment and dated evidence are published. Provider cache bounds, broader algorithm/surface matrices and all acceptance criteria remain incomplete. |
