import re
import secrets
from datetime import timedelta

from odoo import http, fields
from odoo.http import request
from odoo.modules.registry import Registry
from werkzeug.exceptions import Forbidden

from .. import config
from ..soca import core
from ..soca.errors import SocaError


def profile_named(name):
    if not re.fullmatch(r"[a-z][a-z0-9_-]{0,39}", name):
        raise SocaError("invalid_profile")
    profile = request.env["soca.profile"].sudo().search([("name", "=", name)], limit=1)
    if not profile:
        raise SocaError("unknown_profile")
    return profile


def secure_request():
    if not request.httprequest.is_secure:
        raise SocaError("https_required")


def operator():
    if not request.env.is_system():
        raise Forbidden("Local administrator access required")
    return request.env.user.id


def document(value):
    return request.make_response(core.canonical(value), headers=[("Content-Type", "application/json"), ("Cache-Control", "public, max-age=60"), ("X-Content-Type-Options", "nosniff")])


class Soca(http.Controller):
    @http.route("/soca/<name>/metadata", type="http", auth="public", methods=["GET"], readonly=True)
    def metadata(self, name):
        return document(config.load(profile_named(name)).document())

    @http.route("/soca/<name>/jwks", type="http", auth="public", methods=["GET"], readonly=True)
    def jwks(self, name):
        return document({"keys": [config.load(profile_named(name)).public_key]})

    @http.route("/soca/<name>/test", type="http", auth="user", methods=["GET"], readonly=False)
    def test(self, name):
        # This GET starts a reversible, operator-bound candidate transaction only.
        return self._begin(name, test_operator=operator())

    @http.route("/soca/<name>/login", type="http", auth="public", methods=["GET"], readonly=False)
    def login(self, name, **kwargs):
        try:
            return self._begin(name)
        except (SocaError, ValueError, OSError):
            return request.redirect("/web/login?soca_error=1", 303)

    def _begin(self, name, test_operator=None):
        secure_request()
        profile = profile_named(name)
        candidate = config.load(profile)
        candidate.require_available(config.evidence(profile), test=test_operator is not None)
        binding = request.session.get("soca_browser")
        if not binding:
            binding = request.session["soca_browser"] = secrets.token_urlsafe(32)
        state, payload, url = core.start(candidate, binding, test_operator=test_operator)
        request.env["soca.transaction"].sudo().create({"state_hash": core.digest(state), "profile_id": profile.id, "ciphertext": core.seal(payload, config.key_file(request.env)), "expires_at": fields.Datetime.now() + timedelta(seconds=300)})
        return request.redirect(url, 303, local=False)

    @http.route("/soca/<name>/callback", type="http", auth="public", methods=["GET"], readonly=False)
    def callback(self, name, state="", code="", iss=None, error=None, **kwargs):
        try:
            secure_request()
            if not re.fullmatch(r"[A-Za-z0-9_-]{43}", state):
                raise SocaError("invalid_state")
            profile = profile_named(name)
            # Consume in an independent committed DB transaction across workers.
            with Registry(request.db).cursor() as cr:
                cr.execute("DELETE FROM soca_transaction WHERE state_hash=%s AND profile_id=%s AND expires_at > NOW() RETURNING ciphertext", [core.digest(state), profile.id])
                row = cr.fetchone()
                cr.commit()
            if not row:
                raise SocaError("unknown_transaction")
            payload = core.unseal(row[0], config.key_file(request.env))
            candidate = config.load(profile)
            candidate.require_available(config.evidence(profile), test=payload.get("operator") is not None)
            core.validate_transaction(candidate, payload, request.session.get("soca_browser", ""), current_operator=request.env.user.id)
            if error:
                raise SocaError("provider_cancelled")
            claims = core.exchange(candidate, payload, code, iss)
            core.admission(candidate, claims)
            if payload.get("operator") is not None:
                operator()
                profile._record_evidence(login=candidate.fingerprint)
                return request.redirect("/odoo", 303)
            user = request.env["soca.identity"]._resolve(candidate, claims)
            token = secrets.token_urlsafe(32)
            request.env["soca.ticket"].sudo().create({"token_hash": core.digest(token), "browser_hash": core.digest(request.session["soca_browser"]), "user_id": user.id, "expires_at": fields.Datetime.now() + timedelta(seconds=30)})
            # Host authenticate opens its own cursor. Commit atomic user+link+ticket first.
            request.env.cr.commit()
            request.session.authenticate(request.env, {"login": user.login, "type": "soca_ticket", "token": token})
            # Native Odoo authentication preserves local MFA policy and rotates session ID.
            return request.redirect("/my" if user.share else "/odoo", 303)
        except (SocaError, ValueError, OSError):
            request.env.cr.rollback()
            return request.redirect("/web/login?soca_error=1", 303)
