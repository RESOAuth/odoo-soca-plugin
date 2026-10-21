# SOCA for Odoo

An installable Odoo 19 server add-on providing OpenID Connect code sign-in,
PKCE S256, ES256 `private_key_jwt` and hosted or proxy Client ID Metadata Documents.
**Alpha 0.1.0a1: ordinary SSO defaults off.** The
[requirements assessment](docs/requirements-coverage.md) records outstanding work.

The native **Settings > SOCA** menu contains provider configuration, separate
public-document/candidate-test actions and independently approved issuer/subject
associations. Admission denies by default. Verified email never selects an existing
account. Optional atomic provisioning grants portal access only. Local credentials,
roles, administrator login and native MFA policy are preserved. The add-on uses a
30-second internal one-use credential to enter Odoo's native authentication pipeline,
without persisting OAuth access/refresh/ID tokens.

Install the `auth_soca` directory on your addons path, install the hashed Python
requirements in the server environment and initialise the add-on:

```sh
python -m pip install --require-hashes -r requirements.txt
odoo --database your_database --init auth_soca --stop-after-init
```

The tested host is **Odoo 19.0-20261015** (official 19.0 image), Python 3.12 and
PostgreSQL 16. Only Odoo 19 is currently supported. The package extends native host
authentication rather than the implicit-flow `auth_oauth` token store, preserving
code/PKCE and the protected-association boundary.

Generate owner-only keys with `python demo/generate-secrets.py`. The
[example deployment JSON](demo/config.example.json) scopes profiles by database.
Set `SOCA_CONFIG_FILE` to that deployment file and `SOCA_TRANSACTION_KEY_FILE` to the
separate Fernet key. Create a native `staff` provider profile with matching canonical
HTTPS origin/key references while disabled. Deployment JSON overrides the native
configuration JSON and exposes its effective sources/locks in the settings screen.
Keep a local administrator session and independent recovery credentials available.

Publish candidate metadata, run **Check public documents**, complete **Test candidate
login**, then enable the profile. The test returns to your local operator session
without creating, linking or updating an account. Changed policy, metadata, keys or
issuer invalidate the candidate evidence. The exact public routes are:

- `/soca/staff/metadata`
- `/soca/staff/jwks`
- `/soca/staff/callback`

All supported settings and operational bounds are documented in
[configuration and recovery](docs/operations.md). Headless setup/changes/checks use
Odoo's normal ORM shell, for example:

```python
profile = env['soca.profile'].search([('name', '=', 'staff')], limit=1)
profile.action_document_check()
profile.action_disable()
env.cr.commit()
```

For a disposable demo, copy `demo/config.example.json` to `demo/soca.json`, generate
keys, set `SOCA_DEMO_DB_PASSWORD`, then run `podman compose -f demo/compose.yml up --build`.
The backend binds localhost:8069. Use a trusted HTTPS reverse proxy and configure the
canonical origin before SSO. Proxy mode permits public CIMD for a local HTTPS backend;
encoded metadata is public and inline key changes also change its client ID.
`bash demo/test-host.sh` independently builds the pinned host, installs it into a
fresh PostgreSQL database and executes the native security/account tests.

```sh
python -m pip install --require-hashes -r requirements-test.txt
python -m pytest -q
ruff check auth_soca tests
python -m build
python tests/check_package.py
bash demo/test-host.sh
```

[Dated results](docs/verification.md) distinguish synthetic protocol fixtures and
native host tests. No live RESOAuth login is claimed. Automated key rotation,
HSM/KMS support, role mapping, diagnostics, provider logout, existing-session
revocation, comprehensive multi-worker failures and independent conformance review
remain gaps. This repository provides a reviewable alpha, not a production certification.

See [SECURITY.md](SECURITY.md), [threat model](docs/threat-model.md) and
[AGPL-3.0-only licence](LICENSE). Odoo integration follows its
[native HTTP/session API](https://www.odoo.com/documentation/19.0/developer/reference/backend/http.html)
and [authentication extension source](https://github.com/odoo/odoo/blob/19.0/addons/auth_oauth/models/res_users.py).
