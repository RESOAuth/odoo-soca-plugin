# Configuration and operations

All URLs must be canonical public HTTPS URLs. Request Host/forwarded headers never
select issuer trust or a callback. Configure the host's trusted reverse proxy and
serve its local administrator login over HTTPS before attempting SSO. The network
client accepts public DNS names only, rejects mixed public/private answers, pins the
validated address and preserves TLS SNI/hostname verification. Internal providers
need a separately reviewed network profile; there is no production TLS/SSRF bypass.

Configuration precedence is deployment values over native database/UI values, with
built-in defaults only when neither supplies a value. Emergency disable also checks
`SOCA_EMERGENCY_DISABLED=1` or `true` (case-insensitive). Signing and transaction
keys are absolute file references to owner-only regular files, outside application
data. Generate P-256 and Fernet keys using `demo/generate-secrets.py`; mount read-only
and grant ownership to the host process. Secret values never enter forms or metadata.

Public metadata defaults to hosted mode. Proxy mode uses
`https://dynamic-cimd.resoauth.cloud/cimd/%s`; replace exactly one path placeholder
with unpadded base64url of sorted-key compact UTF-8 JSON, excluding client_id. The
proxy must return exactly that public metadata plus the complete resulting URL as
client_id. Proxy URLs disclose all encoded metadata to browsers, providers and the
proxy. Hosted mode defaults to jwks_uri; proxy mode defaults to inline public jwks.
Set `inline_jwks` explicitly where provider policy requires a different choice.

Branding/legal fields are `client_name`, `client_uri`, `logo_uri`, `policy_uri` and
`tos_uri`. The application name/homepage defaults come from the host where exposed;
set explicit public HTTPS legal/logo URLs when there is no unambiguous host default.
Unavailable optional fields are omitted. Privacy policy and terms are different fields.

Settings understood by the protocol core are `issuer`, `origin`, `private_key_file`,
`enabled`, `metadata_mode` (hosted/proxy), `proxy`, `inline_jwks`, `client_name`,
`client_uri`, `logo_uri`, `policy_uri`, `tos_uri`, `allow_emails`, `deny_emails`,
`allow_domains`, `deny_domains`, `provision`, `userinfo`, `id_token_alg`,
`assertion_alg` (ES256 only), `assertion_audience` (issuer/token_endpoint),
`max_age`, `acr_values` and `required_amr`. Admission lists are arrays in deployment
JSON and one item per line in Frappe forms. Frappe adds `provision_role`; Odoo accepts
only `provision_group: base.group_portal`. All new-account provisioning defaults off.

Domains accept exact dotted DNS names and one leading wildcard, for example
`example.com` or `*.example.org`. A wildcard matches nested subdomains but excludes
the apex. Deny wins. Email/domain rules require trusted boolean email_verified=true.
Only a persisted issuer/subject link can select an existing account. Independently
verify ownership before local administrator approval; a verified email alone is
insufficient. Existing credentials, roles, names and privileges are preserved.

Candidate activation is a sequence: publish metadata while disabled, run a document
check, initiate an operator-bound real test login from the native settings UI, then
enable the profile. Document and login evidence are separate, tied to the complete
configuration/key/policy fingerprint. Enabling alone preserves evidence; covered
changes invalidate it. Candidate tests perform ordinary protocol/admission validation
but do not create/link/update an account or replace the operator session. They do not
record raw claims or tokens. There are no credentials or fixtures that can bypass the
real-test gate in production.

| Bound | Value / behaviour |
| --- | --- |
| Transaction lifetime | 300 seconds; encrypted verifier/nonce; one-use database state |
| Assertion lifetime | 60 seconds; random jti; issuer audience by default |
| ID-token clock skew | 30 seconds |
| ID-token maximum lifetime | 86,400 seconds; issued no earlier than transaction start minus skew |
| Fresh authentication | max_age 0..86,400 seconds when configured; provider acr/amr meanings require verification |
| Metadata body / URL | 4,096 bytes / 8,192 characters before document activation checks |
| Metadata/JWKS response | max 262,144 bytes; no redirects or compressed bodies |
| HTTPS deadlines | connect 3 seconds, per-read 3 seconds, body loop budget 10 seconds; DNS total remains a gap |
| Provider JWKS cache | none in Python, one fresh bounded fetch per callback; max 50 keys |
| Public document cache | max-age=60 seconds; provider/proxy/CDN cache bounds remain unconfirmed |
| Cleanup | native hourly task; expiry is checked even before physical deletion |
| Odoo internal credential | one use, hashed, browser-bound, expires after 30 seconds; no OAuth token retained |
| Key rotation overlap | not automated; no safe unattended overlap value is claimed |
| Session revocation | new logins check policy; existing-session propagation bound not implemented |
| Claim diagnostics | not captured; no diagnostic retention store |

Local recovery: retain a strong native administrator credential and host MFA. Keep the
host local login entry point available. Set deployment emergency disable, run native
transaction invalidation/disable maintenance, restart workers to apply deployment
changes and check both ordinary and test login rejection. Local logout works without
a provider call. Existing native sessions require host session revocation explicitly.
Removing an extension must never delete local users or grant new privileges. Export
approved identity associations before uninstalling; host schema removal can remove
plugin records. Permanent key/link deletion also needs scoped backup deletion and audit.

Do not perform routine signing-key replacement as a rotation substitute. With inline
proxy keys the client ID changes, which may change consent and pairwise subjects.
Treat that as an explicit migration, recheck documents and provider restrictions,
reapprove associations using verified new subjects and invalidate pending state.
Back up keys separately, and rehearse restore without restoring pending transactions.
