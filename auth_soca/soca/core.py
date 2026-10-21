"""Protocol core shared by the Frappe and Odoo SOCA distributions.

Transport derived from RESOAuth/wagtail-soca-plugin, AGPL-3.0-only.
Identity selection is deliberately left to protected issuer/subject host links.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

import jwt
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from . import transport
from .errors import SocaError

DEFAULT_PROXY = "https://dynamic-cimd.resoauth.cloud/cimd/%s"
MAX_METADATA = 4096
MAX_URL = 8192
TRANSACTION_SECONDS = 300
CLOCK_SKEW = 30
ALGORITHMS = ("ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "RS256", "EdDSA")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def secret_file(path):
    """Deployment secrets must be regular owner-readable files outside the database."""
    if not isinstance(path, str) or not Path(path).is_absolute():
        raise SocaError("secret_file_requires_absolute_path")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > 32768:
            raise SocaError("secret_file_permissions")
        return os.read(fd, 32769)
    finally:
        os.close(fd)


def domain_rule(value):
    if not isinstance(value, str) or value != value.strip() or not value.isascii():
        raise SocaError("invalid_domain_rule")
    value = value.lower()
    domain = value[2:] if value.startswith("*.") else value
    if len(domain) > 253 or "." not in domain or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in domain.split(".")
    ) or domain.split(".")[-1].isdigit():
        raise SocaError("invalid_domain_rule")
    return value


def email_address(value):
    if not isinstance(value, str) or len(value) > 254 or not value.isascii() or value.count("@") != 1:
        raise SocaError("invalid_email")
    local, domain = value.rsplit("@", 1)
    if not re.fullmatch(r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]{1,64}", local) or local.startswith(".") or local.endswith(".") or ".." in local:
        raise SocaError("invalid_email")
    if "*" in domain:
        raise SocaError("invalid_email")
    domain_rule(domain)
    return value.lower()


def domain_matches(domain, rule):
    return domain.endswith("." + rule[2:]) if rule.startswith("*.") else domain == rule


def local_return(value, default="/"):
    if not isinstance(value, str) or not value.startswith("/") or value.startswith("//") or re.search(r"[\\\x00-\x20\x7f]", value) or "%" in value or len(value) > 1024:
        return default
    parsed = urlsplit(value)
    return value if not parsed.scheme and not parsed.netloc else default


@dataclass(frozen=True)
class Config:
    profile: str
    issuer: str
    origin: str
    callback: str
    metadata_url: str
    jwks_url: str
    private_key: object = field(repr=False)
    public_key: dict
    values: dict = field(repr=False)
    allow_emails: tuple
    allow_domains: tuple
    deny_emails: tuple
    deny_domains: tuple
    proxy: str | None = None

    @classmethod
    def load(cls, name, raw, routes, *, application_name, application_urls=None):
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,39}", name):
            raise SocaError("invalid_profile")
        values = dict(raw)
        issuer = values.setdefault("issuer", "https://auth.resoauth.cloud")
        origin = values["origin"].rstrip("/")
        for url in (issuer, origin):
            parsed = transport.validate_url(url)
            if parsed.query:
                raise SocaError("url_query_not_allowed")
        if urlsplit(origin).path not in ("", "/"):
            # Path prefixes belong in route paths, never inferred from Host headers.
            raise SocaError("origin_requires_origin")
        for flag in ("enabled", "provision", "userinfo", "emergency_disabled"):
            if flag in values and type(values[flag]) is not bool:
                raise SocaError("invalid_boolean")
        for name_key in ("assertion_alg", "id_token_alg"):
            alg = values.setdefault(name_key, "ES256")
            if alg not in ALGORITHMS or alg == "EdDSA":
                # Fully specified EdDSA and ML-DSA are not available in this release.
                raise SocaError("unsupported_algorithm")
        if values.get("assertion_audience", "issuer") not in ("issuer", "token_endpoint"):
            raise SocaError("invalid_assertion_audience")
        key = serialization.load_pem_private_key(secret_file(values["private_key_file"]), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1) or values["assertion_alg"] != "ES256":
            raise SocaError("assertion_requires_es256_p256")
        public = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key.public_key()))
        public.update(kid=digest(canonical(public)), use="sig", alg="ES256")
        proxy = values.get("proxy", DEFAULT_PROXY) if values.get("metadata_mode", "hosted") == "proxy" else None
        if values.get("metadata_mode", "hosted") not in ("proxy", "hosted"):
            raise SocaError("invalid_metadata_mode")
        if proxy is not None:
            if not isinstance(proxy, str) or proxy.count("%s") != 1:
                raise SocaError("invalid_proxy")
            parsed = transport.validate_url(proxy.replace("%s", "e30"))
            original = urlsplit(proxy)
            if "%s" not in original.path or original.query or parsed.query:
                raise SocaError("invalid_proxy")
        rules = {}
        for rule_name in ("allow_emails", "deny_emails", "allow_domains", "deny_domains"):
            items = values.get(rule_name, [])
            if not isinstance(items, list) or len(items) > 500:
                raise SocaError("invalid_admission_rules")
            validator = domain_rule if rule_name.endswith("domains") else email_address
            rules[rule_name] = tuple(validator(item) for item in items)
        for key_name in ("acr_values", "required_amr"):
            if key_name in values and (not isinstance(values[key_name], list) or any(not isinstance(item, str) or not 1 <= len(item) <= 100 for item in values[key_name])):
                raise SocaError("invalid_assurance_policy")
        max_age = values.get("max_age")
        if max_age is not None and (type(max_age) is not int or not 0 <= max_age <= 86400):
            raise SocaError("invalid_max_age")
        values.setdefault("client_name", application_name)
        for key_name, url in (application_urls or {}).items():
            if url:
                values.setdefault(key_name, url)
        for key_name in ("client_uri", "logo_uri", "policy_uri", "tos_uri"):
            if values.get(key_name):
                transport.validate_url(values[key_name])
        values.setdefault("client_uri", origin + "/")
        if not isinstance(values["client_name"], str) or not 1 <= len(values["client_name"]) <= 200:
            raise SocaError("invalid_client_name")
        config = cls(name, issuer, origin, *(origin + routes[key] for key in ("callback", "metadata", "jwks")), key, public, values, **rules, proxy=proxy)
        for url in (config.callback, config.metadata_url, config.jwks_url, config.client_id):
            transport.validate_url(url)
        config.metadata()
        return config

    @property
    def client_id(self):
        if not self.proxy:
            return self.metadata_url
        encoded = b64(canonical(self.metadata()).encode("utf-8"))
        url = self.proxy.replace("%s", encoded)
        if len(url) > MAX_URL:
            raise SocaError("proxy_url_too_large")
        return url

    @property
    def fingerprint(self):
        # Includes policy, keys, canonical callback, UI revision and deployment settings.
        return digest(canonical({"issuer": self.issuer, "metadata": self.document(), "public_jwk": self.public_key, "values": {key: value for key, value in self.values.items() if key not in ("enabled", "emergency_disabled")}}))

    def metadata(self):
        value = {
            "client_name": self.values["client_name"], "client_uri": self.values["client_uri"],
            "redirect_uris": [self.callback], "grant_types": ["authorization_code"],
            "response_types": ["code"], "scope": "openid email" + (" profile" if self.values.get("provision") else ""), "application_type": "web",
            "token_endpoint_auth_method": "private_key_jwt", "token_endpoint_auth_signing_alg": "ES256",
            "id_token_signed_response_alg": self.values["id_token_alg"],
        }
        for key_name in ("logo_uri", "policy_uri", "tos_uri"):
            if self.values.get(key_name):
                value[key_name] = self.values[key_name]
        if self.values.get("inline_jwks", bool(self.proxy)):
            value["jwks"] = {"keys": [self.public_key]}
        else:
            value["jwks_uri"] = self.jwks_url
        if len(canonical(value).encode()) > MAX_METADATA:
            raise SocaError("metadata_too_large")
        return value

    def document(self):
        return {"client_id": self.client_id, **self.metadata()}

    def require_available(self, evidence, *, test=False):
        if self.values.get("emergency_disabled") or os.getenv("SOCA_EMERGENCY_DISABLED", "").lower() in ("1", "true", "yes"):
            raise SocaError("emergency_disabled")
        if not test and (self.values.get("enabled") is not True or evidence.get("document") != self.fingerprint or evidence.get("login") != self.fingerprint):
            raise SocaError("activation_requires_document_and_live_test")
        if test and evidence.get("document") != self.fingerprint:
            raise SocaError("document_check_required")


def discover(config):
    doc = transport.request_json(config.issuer.rstrip("/") + "/.well-known/openid-configuration")
    if doc.get("issuer") != config.issuer:
        raise SocaError("issuer_mismatch")
    for endpoint in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        transport.validate_url(doc.get(endpoint))
    if "userinfo_endpoint" in doc:
        transport.validate_url(doc["userinfo_endpoint"])
    for field_name, required in {
        "response_types_supported": "code", "code_challenge_methods_supported": "S256",
        "token_endpoint_auth_methods_supported": "private_key_jwt",
        "token_endpoint_auth_signing_alg_values_supported": "ES256",
        "id_token_signing_alg_values_supported": config.values["id_token_alg"],
    }.items():
        if not isinstance(doc.get(field_name), list) or required not in doc[field_name]:
            raise SocaError("provider_capability_" + field_name)
    if "client_id_metadata_document_supported" in doc and doc["client_id_metadata_document_supported"] is not True:
        raise SocaError("cimd_explicitly_unsupported")
    if "authorization_response_iss_parameter_supported" in doc and type(doc["authorization_response_iss_parameter_supported"]) is not bool:
        raise SocaError("invalid_response_issuer_capability")
    if set(parse_qs(urlsplit(doc["authorization_endpoint"]).query)).intersection({"client_id", "redirect_uri", "response_type", "state", "nonce", "scope", "code_challenge", "code_challenge_method"}):
        raise SocaError("reserved_authorization_parameters")
    return doc


def document_check(config):
    discover(config)
    if transport.request_json(config.client_id) != config.document():
        raise SocaError("public_document_mismatch")
    if "jwks_uri" in config.metadata() and transport.request_json(config.jwks_url) != {"keys": [config.public_key]}:
        raise SocaError("public_jwks_mismatch")
    return config.fingerprint


def start(config, browser, *, test_operator=None, return_to="/"):
    doc = discover(config)
    state = secrets.token_urlsafe(32)
    payload = {"browser": digest(browser), "revision": config.fingerprint, "issuer": config.issuer,
               "client_id": config.client_id, "callback": config.callback, "started": int(time.time()),
               "nonce": secrets.token_urlsafe(32), "verifier": secrets.token_urlsafe(48),
               "discovery": doc, "operator": test_operator, "return_to": local_return(return_to)}
    params = {"response_type": "code", "response_mode": "query", "scope": "openid email" + (" profile" if config.values.get("provision") else ""),
              "client_id": config.client_id, "redirect_uri": config.callback, "state": state,
              "nonce": payload["nonce"], "code_challenge": b64(hashlib.sha256(payload["verifier"].encode()).digest()),
              "code_challenge_method": "S256"}
    if config.values.get("max_age") is not None:
        params["max_age"] = config.values["max_age"]
    if config.values.get("acr_values"):
        params["acr_values"] = " ".join(config.values["acr_values"])
    endpoint = doc["authorization_endpoint"]
    return state, payload, endpoint + ("&" if "?" in endpoint else "?") + urlencode(params)


def seal(payload, key_file):
    return Fernet(secret_file(key_file).strip()).encrypt(canonical(payload).encode()).decode()


def unseal(ciphertext, key_file):
    try:
        return json.loads(Fernet(secret_file(key_file).strip()).decrypt(ciphertext.encode(), ttl=TRANSACTION_SECONDS))
    except (InvalidToken, ValueError, TypeError) as exc:
        raise SocaError("invalid_transaction") from exc


def validate_transaction(config, payload, browser, *, current_operator=None):
    now = int(time.time())
    if not isinstance(browser, str) or not browser or not hmac.compare_digest(payload.get("browser", ""), digest(browser)):
        raise SocaError("browser_mismatch")
    if any(payload.get(key) != expected for key, expected in {"revision": config.fingerprint, "issuer": config.issuer, "client_id": config.client_id, "callback": config.callback}.items()):
        raise SocaError("configuration_changed")
    if type(payload.get("started")) is not int or not 0 <= now - payload["started"] <= TRANSACTION_SECONDS:
        raise SocaError("transaction_expired")
    if payload.get("operator") is not None and payload["operator"] != current_operator:
        raise SocaError("test_operator_mismatch")


def assertion(config, discovery):
    now = int(time.time())
    audience = config.issuer if config.values.get("assertion_audience", "issuer") == "issuer" else discovery["token_endpoint"]
    return jwt.encode({"iss": config.client_id, "sub": config.client_id, "aud": audience, "iat": now, "exp": now + 60, "jti": secrets.token_urlsafe(32)}, config.private_key, algorithm="ES256", headers={"kid": config.public_key["kid"]})


def verify(config, payload, token, *, code="", access_token=""):
    alg = config.values["id_token_alg"]
    if not isinstance(token, str) or len(token) > 32768:
        raise SocaError("invalid_id_token")
    try:
        header = jwt.get_unverified_header(token)
        if header.get("alg") != alg or not isinstance(header.get("kid"), str) or not 1 <= len(header["kid"]) <= 200 or any(key in header for key in ("crit", "jku", "jwk", "x5u", "b64")):
            raise SocaError("invalid_jwt_header")
        keys = transport.request_json(payload["discovery"]["jwks_uri"]).get("keys")
        if not isinstance(keys, list) or not 1 <= len(keys) <= 50:
            raise SocaError("invalid_provider_keys")
        keys = [key for key in keys if isinstance(key, dict) and key.get("kid") == header["kid"]]
        if len(keys) != 1:
            raise SocaError("ambiguous_provider_key")
        key = keys[0]
        kind = "EC" if alg.startswith("ES") else "RSA"
        curve = {"ES256": "P-256", "ES384": "P-384", "ES512": "P-521"}.get(alg)
        if key.get("kty") != kind or key.get("alg", alg) != alg or key.get("use", "sig") != "sig" or any(name in key for name in ("d", "p", "q", "dp", "dq", "qi", "oth", "k")) or (curve and key.get("crv") != curve) or ("key_ops" in key and key["key_ops"] != ["verify"]):
            raise SocaError("invalid_provider_key")
        public = jwt.PyJWK.from_dict(key, algorithm=alg).key
        if kind == "RSA" and public.key_size < 2048:
            raise SocaError("weak_provider_key")
        claims = jwt.decode(token, public, algorithms=[alg], issuer=config.issuer, audience=config.client_id, leeway=CLOCK_SKEW, options={"require": ["iss", "sub", "aud", "exp", "iat", "nonce"]})
    except (jwt.PyJWTError, ValueError, TypeError, KeyError) as exc:
        raise SocaError("id_token_validation") from exc
    if not isinstance(claims["sub"], str) or not re.fullmatch(r"[\x20-\x7e]{1,255}", claims["sub"]):
        raise SocaError("invalid_subject")
    if not isinstance(claims["nonce"], str) or not claims["nonce"].isascii() or not hmac.compare_digest(claims["nonce"], payload["nonce"]):
        raise SocaError("nonce_mismatch")
    for name in ("iat", "exp", "nbf", "auth_time"):
        if name in claims and type(claims[name]) is not int:
            raise SocaError("invalid_claim_time")
    now = int(time.time())
    if claims["iat"] < payload["started"] - CLOCK_SKEW or not 0 < claims["exp"] - claims["iat"] <= 86400 or ("nbf" in claims and claims["nbf"] >= claims["exp"]):
        raise SocaError("invalid_token_lifetime")
    audience = claims["aud"]
    if not isinstance(audience, (list, str)) or not audience or (isinstance(audience, list) and (any(not isinstance(item, str) for item in audience) or (len(audience) > 1 and "azp" not in claims))) or claims.get("azp", config.client_id) != config.client_id:
        raise SocaError("invalid_authorised_party")
    max_age = config.values.get("max_age")
    if max_age is not None and (type(claims.get("auth_time")) is not int or not 0 <= now - claims["auth_time"] <= max_age + CLOCK_SKEW):
        raise SocaError("fresh_authentication_required")
    if config.values.get("acr_values") and claims.get("acr") not in config.values["acr_values"]:
        raise SocaError("assurance_level_required")
    if config.values.get("required_amr") and (not isinstance(claims.get("amr"), list) or any(item not in claims["amr"] for item in config.values["required_amr"])):
        raise SocaError("authentication_method_required")
    bits = 384 if alg.endswith("384") else 512 if alg.endswith("512") else 256
    for name, value in (("at_hash", access_token), ("c_hash", code)):
        if name in claims:
            expected = b64(hashlib.new("sha" + str(bits), value.encode("ascii")).digest()[:bits // 16])
            if not value or not isinstance(claims[name], str) or not claims[name].isascii() or not hmac.compare_digest(claims[name], expected):
                raise SocaError("token_hash_mismatch")
    return claims


def exchange(config, payload, code, response_issuer=None):
    if not isinstance(code, str) or not re.fullmatch(r"[\x21-\x7e]{1,4096}", code):
        raise SocaError("invalid_authorisation_code")
    doc = payload["discovery"]
    if response_issuer != config.issuer:
        raise SocaError("response_issuer_mismatch")
    response = transport.request_json(doc["token_endpoint"], form={"grant_type": "authorization_code", "code": code, "redirect_uri": config.callback, "client_id": config.client_id, "code_verifier": payload["verifier"], "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", "client_assertion": assertion(config, doc)})
    if "error" in response:
        raise SocaError("token_endpoint_error")
    access = response.get("access_token", "")
    if not isinstance(access, str) or not access.isascii() or len(access) > 16384:
        raise SocaError("invalid_access_token")
    claims = verify(config, payload, response.get("id_token"), code=code, access_token=access)
    if config.values.get("userinfo") and access and doc.get("userinfo_endpoint"):
        if str(response.get("token_type", "")).lower() != "bearer":
            raise SocaError("invalid_token_type")
        try:
            info = transport.request_json(doc["userinfo_endpoint"], bearer=access)
        except SocaError:
            # Only transport failure is optional. Returned identity conflicts always abort.
            info = None
        if info is not None:
            if info.get("sub") != claims["sub"]:
                raise SocaError("userinfo_subject_conflict")
            for key in ("email", "email_verified", "iss"):
                if key in claims and key in info and (type(claims[key]) is not type(info[key]) or claims[key] != info[key]):
                    raise SocaError("userinfo_identity_conflict")
            for key in ("email", "email_verified", "given_name", "family_name", "name", "preferred_username"):
                if key not in claims and key in info:
                    claims[key] = info[key]
    return claims


def admission(config, claims):
    if claims.get("email_verified") is not True:
        raise SocaError("verified_email_required")
    email = email_address(claims.get("email"))
    domain = email.rsplit("@", 1)[1]
    if email in config.deny_emails or any(domain_matches(domain, rule) for rule in config.deny_domains):
        raise SocaError("admission_denied")
    if email not in config.allow_emails and not any(domain_matches(domain, rule) for rule in config.allow_domains):
        raise SocaError("admission_denied")
    return email


def profile_text(claims, field_name, fallback=""):
    value = claims.get(field_name, fallback)
    if not isinstance(value, str) or len(value) > 140 or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise SocaError("invalid_profile_claim")
    return value.strip()
