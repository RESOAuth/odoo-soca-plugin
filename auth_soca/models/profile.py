import json

from odoo import api, fields, models
from odoo.exceptions import AccessError, ValidationError

from .. import config
from ..soca import core


class SocaProfile(models.Model):
    _name = "soca.profile"
    _description = "SOCA provider profile"

    name = fields.Char(required=True, index=True)
    enabled = fields.Boolean(default=False)
    configuration = fields.Text(required=True, default=lambda self: json.dumps({"origin": "https://app.example.com", "issuer": "https://auth.resoauth.cloud", "metadata_mode": "hosted", "private_key_file": "/run/secrets/soca-signing.pem", "allow_domains": [], "deny_domains": [], "provision": False}, indent=2))
    document_evidence = fields.Char(readonly=True, copy=False)
    login_evidence = fields.Char(readonly=True, copy=False)
    effective_status = fields.Text(compute="_compute_effective_status")
    _unique_name = models.Constraint("unique(name)", "SOCA profile names must be unique")

    def _compute_effective_status(self):
        for profile in self:
            try:
                candidate = config.load(profile)
                profile.effective_status = core.canonical({"client_id": candidate.client_id, "revision": candidate.fingerprint, "document_checked": profile.document_evidence == candidate.fingerprint, "live_test_passed": profile.login_evidence == candidate.fingerprint, "deployment_locks": list(config.deployment(profile.env).get("profiles", {}).get(profile.name, {})), "precedence": "deployment file > database", "emergency_disabled": candidate.values.get("emergency_disabled", False)})
            except Exception:
                profile.effective_status = "Candidate configuration invalid. Check HTTPS URLs and deployment secret references."

    @api.model_create_multi
    def create(self, vals_list):
        if any(vals.get("document_evidence") or vals.get("login_evidence") for vals in vals_list):
            raise AccessError("SOCA evidence is recorded only by document checks and candidate tests")
        profiles = super().create(vals_list)
        for profile in profiles:
            candidate = config.load(profile)
            if profile.enabled:
                candidate.require_available(config.evidence(profile))
        return profiles

    def write(self, vals):
        if any(key in vals for key in ("document_evidence", "login_evidence")):
            raise AccessError("SOCA evidence is recorded only by document checks and candidate tests")
        old = {profile.id: config.load(profile).fingerprint for profile in self}
        result = super().write(vals)
        for profile in self:
            candidate = config.load(profile)
            if old[profile.id] != candidate.fingerprint:
                profile._record_evidence(document=False, login=False)
                self.env["soca.transaction"].sudo().search([("profile_id", "=", profile.id)]).unlink()
            if candidate.values.get("enabled"):
                candidate.require_available(config.evidence(profile))
        return result

    def _record_evidence(self, **values):
        # Private method is not callable through Odoo's public RPC dispatcher.
        fields_to_write = {key + "_evidence": value for key, value in values.items()}
        return super().write(fields_to_write)

    def action_document_check(self):
        if not self.env.is_system():
            raise AccessError("System administrator access required")
        self.ensure_one()
        candidate = config.load(self)
        if candidate.values.get("emergency_disabled"):
            raise ValidationError("SOCA is emergency disabled")
        proof = core.document_check(candidate)
        self._record_evidence(document=proof, login=False)
        return {"type": "ir.actions.client", "tag": "display_notification", "params": {"title": "SOCA documents checked", "message": "A real candidate test login is required before activation.", "sticky": False}}

    def action_test_login(self):
        self.ensure_one()
        return {"type": "ir.actions.act_url", "url": "/soca/" + self.name + "/test", "target": "self"}

    def action_disable(self):
        self.write({"enabled": False})
        self.env["soca.transaction"].sudo().search([("profile_id", "in", self.ids)]).unlink()

    def unlink(self):
        self.env["soca.transaction"].sudo().search([("profile_id", "in", self.ids)]).unlink()
        return super().unlink()
