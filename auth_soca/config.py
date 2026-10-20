import json
import os
from pathlib import Path

from .soca.core import Config
from .soca.errors import SocaError


def deployment(env):
    path = os.getenv("SOCA_CONFIG_FILE")
    if not path:
        return {}
    value = json.loads(Path(path).read_text())
    return value.get("databases", {}).get(env.cr.dbname, {})


def load(profile):
    name = profile.name
    values = json.loads(profile.configuration or "{}")
    if not isinstance(values, dict):
        raise SocaError("configuration_requires_object")
    values.update(deployment(profile.env).get("profiles", {}).get(name, {}))
    values["enabled"] = profile.enabled
    # A deployment enable/disable lock always overrides UI/database values.
    override = deployment(profile.env).get("profiles", {}).get(name, {})
    if "enabled" in override:
        values["enabled"] = override["enabled"]
    values["emergency_disabled"] = deployment(profile.env).get("emergency_disabled", False)
    company = profile.env.company
    application_urls = {}
    if company.website and company.website.startswith("https://"):
        application_urls["client_uri"] = company.website
    routes = {key: "/soca/" + name + "/" + key for key in ("metadata", "jwks", "callback")}
    return Config.load(name, values, routes, application_name=company.name, application_urls=application_urls)


def key_file(env):
    path = os.getenv("SOCA_TRANSACTION_KEY_FILE") or deployment(env).get("transaction_key_file")
    if not path:
        raise SocaError("transaction_key_file_required")
    return path


def evidence(profile):
    return {"document": profile.document_evidence, "login": profile.login_evidence}
