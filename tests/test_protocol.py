import base64
import hashlib
import json
import time
from urllib.parse import parse_qs, urlsplit

import jwt
import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from soca_test_package.soca import core, transport
from soca_test_package.soca.errors import SocaError


@pytest.fixture
def key(tmp_path):
    private = ec.generate_private_key(ec.SECP256R1())
    path = tmp_path / "private.pem"
    path.write_bytes(private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    path.chmod(0o600)
    return private, str(path)


@pytest.fixture
def raw(key):
    return {"origin": "https://app.example.com", "private_key_file": key[1], "allow_domains": ["example.com", "*.example.org"]}


def config(raw):
    return core.Config.load("staff", raw, {"callback": "/soca/staff/callback", "metadata": "/soca/staff/metadata", "jwks": "/soca/staff/jwks"}, application_name="Example company", application_urls={"logo_uri": "https://app.example.com/logo.png", "policy_uri": "https://app.example.com/privacy", "tos_uri": "https://app.example.com/terms"})


@pytest.fixture
def cfg(raw):
    return config(raw)


@pytest.fixture
def discovery(cfg):
    return {"issuer": cfg.issuer, "authorization_endpoint": "https://auth.example.com/authorize", "token_endpoint": "https://auth.example.com/token", "jwks_uri": "https://auth.example.com/jwks", "userinfo_endpoint": "https://auth.example.com/userinfo", "response_types_supported": ["code"], "code_challenge_methods_supported": ["S256"], "token_endpoint_auth_methods_supported": ["private_key_jwt"], "token_endpoint_auth_signing_alg_values_supported": ["ES256"], "id_token_signing_alg_values_supported": ["ES256"], "authorization_response_iss_parameter_supported": True}


@pytest.fixture
def transaction(cfg, discovery, monkeypatch):
    monkeypatch.setattr(transport, "request_json", lambda *args, **kwargs: discovery)
    return core.start(cfg, "browser-one")


@pytest.fixture
def identity(cfg, transaction):
    return {"iss": cfg.issuer, "sub": "persistent-subject-001", "aud": cfg.client_id, "nonce": transaction[1]["nonce"], "iat": int(time.time()), "exp": int(time.time()) + 120, "email": "person@example.com", "email_verified": True}


def token(private, claims):
    return jwt.encode(claims, private, algorithm="ES256", headers={"kid": "provider-key"})


def provider_keys(private):
    public = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(private.public_key()))
    public.update(kid="provider-key", alg="ES256", use="sig")
    return {"keys": [public]}


@pytest.mark.parametrize("domain,rule,matched", [("example.com", "example.com", True), ("x.example.com", "example.com", False), ("a.example.com", "*.example.com", True), ("a.b.example.com", "*.example.com", True), ("example.com", "*.example.com", False), ("badexample.com", "*.example.com", False)])
def test_domain_matching(domain, rule, matched):
    assert core.domain_matches(domain, core.domain_rule(rule)) is matched


@pytest.mark.parametrize("rule", ["*example.com", "a.*.example.com", "*.*.example.com", "https://example.com", "a@example.com", "com", "localhost", "example..com", "example.com.", "-bad.example", "a"*64+".com", " example.com", "*.com", "example.123", "éxample.com"])
def test_invalid_domain_rules(rule):
    with pytest.raises(SocaError):
        core.domain_rule(rule)


def test_admission_default_deny(raw, identity):
    raw["allow_domains"] = []
    with pytest.raises(SocaError, match="admission_denied"):
        core.admission(config(raw), identity)


def test_deny_precedence(raw, identity):
    raw["deny_domains"] = ["example.com"]
    with pytest.raises(SocaError, match="admission_denied"):
        core.admission(config(raw), identity)


@pytest.mark.parametrize("verified", [False, "true", 1, None])
def test_boolean_email_verification(cfg, identity, verified):
    identity["email_verified"] = verified
    with pytest.raises(SocaError, match="verified_email_required"):
        core.admission(cfg, identity)


def test_es256_metadata_and_branding(cfg):
    doc = cfg.document()
    assert doc["client_id"] == cfg.metadata_url
    assert doc["token_endpoint_auth_signing_alg"] == doc["id_token_signed_response_alg"] == "ES256"
    assert doc["client_name"] == "Example company"
    assert doc["policy_uri"].endswith("/privacy")
    assert doc["tos_uri"].endswith("/terms")
    assert doc["jwks_uri"] == cfg.jwks_url
    assert not any(name in core.canonical(doc) for name in ("BEGIN PRIVATE", "allow_domains", "email_verified"))


def test_proxy_deterministic_encoding(raw):
    raw["metadata_mode"] = "proxy"
    first = config(raw)
    encoded = first.client_id.rsplit("/", 1)[1]
    document = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    assert "client_id" not in document
    assert document == first.metadata()
    assert document["jwks"]["keys"][0]["kty"] == "EC"
    assert first.client_id == config(dict(reversed(list(raw.items())))).client_id


@pytest.mark.parametrize("template", ["http://bad.example/%s", "https://%s.example.com/cimd", "https://%s.proxy.example.com/placeholder", "https://proxy.example/cimd/%s?x=%s", "https://proxy.example/cimd?x=%s", "https://proxy.example/no-placeholder"])
def test_proxy_safety(raw, template):
    raw.update(metadata_mode="proxy", proxy=template)
    with pytest.raises(SocaError):
        config(raw)


def test_activation_evidence(cfg):
    with pytest.raises(SocaError):
        cfg.require_available({})
    cfg.values["enabled"] = True
    cfg.require_available({"document": cfg.fingerprint, "login": cfg.fingerprint})
    with pytest.raises(SocaError):
        cfg.require_available({"document": cfg.fingerprint, "login": "stale"})


def test_enable_does_not_invalidate_candidate_evidence(cfg):
    fingerprint = cfg.fingerprint
    cfg.values["enabled"] = True
    assert cfg.fingerprint == fingerprint


@pytest.mark.parametrize("mode", ["hosted", "proxy"])
def test_same_path_key_replacement_invalidates_evidence_and_pending_transactions(raw, key, discovery, monkeypatch, mode):
    from pathlib import Path
    raw.update(metadata_mode=mode, inline_jwks=False, enabled=True)
    original = config(raw)
    evidence = {"document": original.fingerprint, "login": original.fingerprint}
    original.require_available(evidence)
    monkeypatch.setattr(transport, "request_json", lambda *args, **kwargs: discovery)
    pending = core.start(original, "browser-one")[1]
    replacement = ec.generate_private_key(ec.SECP256R1())
    Path(key[1]).write_bytes(replacement.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    changed = config(raw)
    assert changed.document() == original.document()  # jwks_uri/client ID remain stable.
    assert changed.fingerprint != original.fingerprint
    with pytest.raises(SocaError, match="activation_requires_document_and_live_test"):
        changed.require_available(evidence)
    with pytest.raises(SocaError, match="configuration_changed"):
        core.validate_transaction(changed, pending, "browser-one")
    revision = changed.fingerprint
    changed.values["enabled"] = False
    assert changed.fingerprint == revision


def test_emergency_disable_blocks_test(cfg, monkeypatch):
    monkeypatch.setenv("SOCA_EMERGENCY_DISABLED", "true")
    with pytest.raises(SocaError, match="emergency_disabled"):
        cfg.require_available({"document": cfg.fingerprint}, test=True)


def test_document_check_requires_exact_public_contents(cfg, discovery, monkeypatch):
    def fetch(url, **kwargs):
        return discovery if "well-known" in url else cfg.document() if url == cfg.client_id else {"keys": [cfg.public_key]}
    monkeypatch.setattr(transport, "request_json", fetch)
    assert core.document_check(cfg) == cfg.fingerprint
    monkeypatch.setattr(transport, "request_json", lambda *args, **kwargs: {"client_id": "wrong"})
    with pytest.raises(SocaError):
        core.document_check(cfg)


def test_metadata_budget(raw):
    raw.update(logo_uri="https://app.example.com/" + "a"*4100)
    with pytest.raises(SocaError, match="metadata_too_large"):
        config(raw)


def test_pkce_and_independent_secrets(transaction):
    state, payload, url = transaction
    query = parse_qs(urlsplit(url).query)
    assert state != payload["nonce"] != payload["verifier"]
    assert query["code_challenge_method"] == ["S256"]
    assert query["code_challenge"] == [core.b64(hashlib.sha256(payload["verifier"].encode()).digest())]
    assert payload["verifier"] not in url
    assert payload["browser"] not in url


def test_browser_copy_and_expiry(cfg, transaction):
    payload = transaction[1]
    core.validate_transaction(cfg, payload, "browser-one")
    with pytest.raises(SocaError, match="browser_mismatch"):
        core.validate_transaction(cfg, payload, "browser-two")
    payload["started"] -= 301
    with pytest.raises(SocaError, match="transaction_expired"):
        core.validate_transaction(cfg, payload, "browser-one")


def test_parallel_tabs(cfg, discovery, monkeypatch):
    monkeypatch.setattr(transport, "request_json", lambda *args, **kwargs: discovery)
    first = core.start(cfg, "same-browser")
    second = core.start(cfg, "same-browser")
    assert first[0] != second[0]
    assert first[1]["verifier"] != second[1]["verifier"]
    core.validate_transaction(cfg, first[1], "same-browser")
    core.validate_transaction(cfg, second[1], "same-browser")


def test_encrypted_transaction(transaction, tmp_path):
    keyfile = tmp_path / "fernet.key"
    keyfile.write_bytes(Fernet.generate_key())
    keyfile.chmod(0o600)
    sealed = core.seal(transaction[1], str(keyfile))
    assert transaction[1]["verifier"] not in sealed
    assert core.unseal(sealed, str(keyfile)) == transaction[1]
    with pytest.raises(SocaError):
        core.unseal(sealed[:-2] + "xx", str(keyfile))


def test_private_key_file_permissions(key):
    from pathlib import Path
    Path(key[1]).chmod(0o644)
    with pytest.raises(SocaError, match="secret_file_permissions"):
        core.secret_file(key[1])


def test_id_token_signature_and_claims(cfg, key, transaction, identity, monkeypatch):
    monkeypatch.setattr(transport, "request_json", lambda *args, **kwargs: provider_keys(key[0]))
    assert core.verify(cfg, transaction[1], token(key[0], identity))["sub"] == identity["sub"]


@pytest.mark.parametrize("field,value", [("iss", "https://wrong.example"), ("aud", "wrong-client"), ("nonce", "wrong-nonce"), ("sub", ""), ("azp", "wrong-client"), ("iat", True), ("exp", 1), ("iat", 1), ("nonce", "é")])
def test_reject_invalid_claims(cfg, key, transaction, identity, monkeypatch, field, value):
    monkeypatch.setattr(transport, "request_json", lambda *args, **kwargs: provider_keys(key[0]))
    identity[field] = value
    with pytest.raises(SocaError):
        core.verify(cfg, transaction[1], token(key[0], identity))


def test_wrong_signature(cfg, key, transaction, identity, monkeypatch):
    monkeypatch.setattr(transport, "request_json", lambda *args, **kwargs: provider_keys(key[0]))
    wrong = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(SocaError):
        core.verify(cfg, transaction[1], token(wrong, identity))


def test_algorithm_substitution(cfg, key, transaction, identity):
    signed = jwt.encode(identity, "symmetric-secret-for-negative-fixture", algorithm="HS256", headers={"kid": "provider-key"})
    with pytest.raises(SocaError):
        core.verify(cfg, transaction[1], signed)


def test_private_key_jwt_audience(cfg, discovery):
    assertion = core.assertion(cfg, discovery)
    claims = jwt.decode(assertion, cfg.private_key.public_key(), algorithms=["ES256"], audience=cfg.issuer)
    assert claims["iss"] == claims["sub"] == cfg.client_id
    assert claims["exp"] - claims["iat"] == 60
    assert jwt.get_unverified_header(assertion)["kid"] == cfg.public_key["kid"]


def test_userinfo_identity_conflict_aborts_optional_fetch(cfg, key, transaction, identity, monkeypatch):
    cfg.values["userinfo"] = True
    def fetch(url, **kwargs):
        if url.endswith("/token"):
            return {"id_token": token(key[0], identity), "access_token": "opaque-fixture", "token_type": "Bearer"}
        if url.endswith("/jwks"):
            return provider_keys(key[0])
        return {"sub": "someone-else"}
    monkeypatch.setattr(transport, "request_json", fetch)
    with pytest.raises(SocaError, match="userinfo_subject_conflict"):
        core.exchange(cfg, transaction[1], "one-use-code", cfg.issuer)


def test_optional_userinfo_outage_keeps_validated_identity(cfg, key, transaction, identity, monkeypatch):
    cfg.values["userinfo"] = True
    def fetch(url, **kwargs):
        if url.endswith("/token"):
            return {"id_token": token(key[0], identity), "access_token": "opaque-fixture", "token_type": "Bearer"}
        if url.endswith("/jwks"):
            return provider_keys(key[0])
        raise SocaError("http_failed")
    monkeypatch.setattr(transport, "request_json", fetch)
    assert core.exchange(cfg, transaction[1], "one-use-code", cfg.issuer)["sub"] == identity["sub"]


def test_response_issuer_mismatch_prevents_exchange(cfg, transaction):
    with pytest.raises(SocaError, match="response_issuer_mismatch"):
        core.exchange(cfg, transaction[1], "one-use-code", "https://wrong.example")


def test_provider_cimd_explicit_false(cfg, discovery, monkeypatch):
    discovery["client_id_metadata_document_supported"] = False
    monkeypatch.setattr(transport, "request_json", lambda *args, **kwargs: discovery)
    with pytest.raises(SocaError, match="cimd_explicitly_unsupported"):
        core.discover(cfg)


@pytest.mark.parametrize("url", ["http://app.example.com/", "https://127.0.0.1/x", "https://user:password@app.example.com", "https://app.example.com/#fragment", "https://app.example.com/../x", "https://app.example.com/%2e%2e/x", "https://localhost/x", "https://app.example.com/\\path"])
def test_invalid_network_urls(url):
    with pytest.raises(SocaError):
        transport.validate_url(url)


def test_mixed_dns_answers_rejected(monkeypatch):
    monkeypatch.setattr(transport.socket, "getaddrinfo", lambda *args, **kwargs: [(2, 1, 6, "", ("93.184.216.34", 443)), (2, 1, 6, "", ("127.0.0.1", 443))])
    with pytest.raises(SocaError, match="nonpublic_address"):
        transport.public_addresses("app.example.com", 443)


@pytest.mark.parametrize("value", ["//evil.example", "https://evil.example", "/\\evil", "/%2f%2fevil", "/line\nbreak"])
def test_safe_return(value):
    assert core.local_return(value) == "/"


def test_profile_text_rejects_credentials_like_structures():
    with pytest.raises(SocaError):
        core.profile_text({"name": {"admin": True}}, "name")


def test_missing_response_issuer_is_rejected(cfg, transaction):
    with pytest.raises(SocaError, match="response_issuer_mismatch"):
        core.exchange(cfg, transaction[1], "one-use-code")
