import re
from odoo import models
from odoo.exceptions import AccessDenied
from odoo.http import request

from ..soca.core import digest


class ResUsers(models.Model):
    _inherit = "res.users"

    def _check_credentials(self, credential, env):
        try:
            return super()._check_credentials(credential, env)
        except AccessDenied:
            if credential.get("type") != "soca_ticket" or not request or not env.get("interactive", False):
                raise
            token = credential.get("token", "")
            binding = request.session.get("soca_browser", "")
            if not re.fullmatch(r"[A-Za-z0-9_-]{43}", token) or not binding or not self.env.user.active:
                raise AccessDenied()
            self.env.cr.execute("DELETE FROM soca_ticket WHERE token_hash=%s AND browser_hash=%s AND user_id=%s AND expires_at > NOW() RETURNING id", [digest(token), digest(binding), self.env.uid])
            if not self.env.cr.fetchone():
                raise AccessDenied()
            return {"uid": self.env.uid, "auth_method": "soca", "mfa": "default"}
