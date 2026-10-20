# Verification evidence

Result date: **2026-10-21**. Plugin **0.1.0a1**. Requirements revision:
`60ea4db827457b4a4a7b11d79e86b654612a75e1`.

The local security suite ran on Python **3.13.15** with **PyJWT 2.15.1**,
**cryptography 50.0.2** and **urllib3 2.8.0**: **78 tests passed**. These are signed
synthetic fixtures and mocked transport responses, not a live identity provider.
They cover strict domain rules, default/deny precedence, boolean verified email,
ES256 defaults, deterministic proxy/branding/legal metadata, unsafe proxy templates,
activation/evidence revisions, emergency test denial, encrypted state, browser copy/
expiry/parallel tabs, key permissions, JWT signature/issuer/audience/nonce/time/
algorithm substitution, optional UserInfo conflict versus outage, response issuer,
public URL/DNS and safe-return rejection.

Native host: official **Odoo 19.0-20261015**, Python **3.12**, PostgreSQL **16**, pinned custom image. A clean database install loads native ACLs, forms, login template, models and cleanup cron. **8 native post-install tests passed, 0 failures, 0 errors**: schema/defaults, email-only refusal, approved issuer/subject link, disabled-user refusal, portal provisioning/link creation, email collision refusal, forged evidence refusal and activation gating. The image includes a current compatible pyOpenSSL alongside the current cryptographic library; no host TLS verification is disabled.

Reproduction:

```sh
python -m pip install --require-hashes -r requirements-test.txt
python -m pytest -q
ruff check auth_soca tests
python -m build
python tests/check_package.py
pip-audit --require-hashes -r requirements.txt
bash demo/test-host.sh
```

Ruff passed; wheel/source distributions built; native host package assets/public-data
boundary checks passed. The pinned production Python dependency audit reported **no
known vulnerabilities** on this date. CI also emits a CycloneDX dependency SBOM.
Pinned workflow SHA references, Dependabot and CodeQL configurations are included.
GitHub check results are reported separately in the pull request and may run after
this local evidence snapshot. No signed public release has been made.

| Provider / metadata / surface | Synthetic document/protocol tests | Real provider login |
| --- | --- | --- |
| RESOAuth defaults / hosted / Odoo staff and portal | Passed fixtures; not a live provider document check | Not attempted, no credentials supplied |
| RESOAuth defaults / proxy / same surface | Passed deterministic document/safety fixtures | Not attempted, no credentials supplied |
| Other issuers/algorithms | Configuration exists for approved profiles; broader vectors not published | Not attempted |

No real RESOAuth/proxy login, browser session/MFA/assurance exercise, OIDC conformance
certification, independent audit, load/accessibility review or multi-worker fault/
backup restore claim is made. Automated key rotation, profile/role synchronisation,
provider logout, diagnostics and existing-session revocation remain outstanding.
The [full per-ID assessment](requirements-coverage.md) preserves those gaps.
