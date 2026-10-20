# Threat model

The protected surface is interactive browser sign-in. API authorisation, delegated
access and offline tokens are outside this profile. The issuer and all metadata
endpoints must be explicitly trusted through deployment or an existing host admin.
Remote claims never establish issuer trust or ownership of an existing local account.

Assets are native sessions, account/permission records, persistent issuer/subject
associations, deployment signing/encryption keys and candidate activation evidence.
Attackers may copy callbacks, control an email address, replay state, induce provider
errors, tamper with metadata/JWKS or resolve a public hostname to private addresses.
Admission is evaluated on every sign-in using validated boolean email verification.
A verified email is never an account association. Privileged recovery users cannot
be provisioned or reactivated. Token algorithms are pinned independently of headers.

Transactions are encrypted, short-lived, bound to a browser and a complete effective
configuration fingerprint, then atomically consumed across workers before token
exchange. A failed login cannot resurrect consumed state. Candidate tests have no
account/link/profile/session side effects. Metadata and proxy URLs are public.

The host administrator, host process, database administrator and deployment secret
store remain trust boundaries. Native audit records are not tamper-evident against a
database administrator. Reverse proxies must strip untrusted forwarding headers,
redact callback queries, enforce HTTPS and rate-limit login routes. A database backup
must not be restored with live pending transactions or revoked associations.

Known gaps include automated key rotation, non-exportable keys, provider/session
revocation propagation, browser and independent security review, comprehensive
concurrency/fault testing, anti-abuse budgets and the full requirements matrix.
Use a staging environment and keep the ordinary login gate disabled until validated.
