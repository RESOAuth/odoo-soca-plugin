import hashlib
from odoo import api, fields, models
from odoo.exceptions import AccessError, ValidationError

from ..soca import core
from ..soca.errors import SocaError
from ..soca.transport import validate_url


class SocaIdentity(models.Model):
    _name = "soca.identity"
    _description = "Approved SOCA issuer and subject association"
    _rec_name = "subject"

    issuer = fields.Char(required=True, index=True, copy=False)
    subject = fields.Char(required=True, index=True, copy=False)
    user_id = fields.Many2one("res.users", required=True, ondelete="restrict", copy=False)
    approval_reason = fields.Text(required=True)
    _unique_identity = models.Constraint("unique(issuer, subject)", "An issuer and subject can only be linked once")

    @api.model_create_multi
    def create(self, vals_list):
        if not self.env.su and not self.env.is_system():
            raise AccessError("Administrator approval required")
        for vals in vals_list:
            validate_url(vals["issuer"])
            if not isinstance(vals["subject"], str) or not 1 <= len(vals["subject"]) <= 255 or not vals.get("approval_reason"):
                raise ValidationError("Exact subject and an approval reason required")
            self._eligible(self.env["res.users"].sudo().browse(vals["user_id"]))
        result = super().create(vals_list)
        for link in result:
            self.env["ir.logging"].sudo().create({"name": "SOCA association approved", "type": "server", "dbname": self.env.cr.dbname, "level": "INFO", "message": "Identity association approved by local administrator", "path": "auth_soca", "func": "create", "line": "0"})
        return result

    def write(self, vals):
        if any(key in vals for key in ("issuer", "subject", "user_id")):
            raise ValidationError("Unlink and explicitly approve a new association for identity migrations")
        return super().write(vals)

    def _eligible(self, user):
        if len(user) != 1 or not user.active or user.id <= 2 or user.has_group("base.group_system"):
            raise SocaError("account_ineligible")
        return user

    def _resolve(self, candidate, claims):
        email = core.admission(candidate, claims)
        # PostgreSQL transaction-scoped lock serialises concurrent creation of the same identity.
        lock = int.from_bytes(hashlib.sha256((candidate.issuer + "\0" + claims["sub"]).encode()).digest()[:8], "big", signed=True)
        self.env.cr.execute("SELECT pg_advisory_xact_lock(%s)", [lock])
        links = self.sudo().search([("issuer", "=", candidate.issuer), ("subject", "=", claims["sub"])], limit=2)
        if len(links) == 1:
            return self._eligible(links.user_id)
        if len(links) > 1:
            raise SocaError("ambiguous_identity")
        if not candidate.values.get("provision"):
            raise SocaError("approved_link_required")
        if candidate.values.get("provision_group", "base.group_portal") != "base.group_portal":
            raise SocaError("portal_provisioning_only")
        if self.env["res.users"].sudo().with_context(active_test=False).search_count([("login", "=", email)]):
            raise SocaError("existing_account_requires_approved_link")
        with self.env.cr.savepoint():
            user = self.env["res.users"].sudo().with_context(no_reset_password=True).create({"name": core.profile_text(claims, "name", "SOCA member"), "login": email, "email": email, "active": True, "group_ids": [(6, 0, [self.env.ref("base.group_portal").id])]})
            self.sudo().create({"issuer": candidate.issuer, "subject": claims["sub"], "user_id": user.id, "approval_reason": "Atomic opt-in portal provisioning after SOCA admission"})
            return self._eligible(user)
