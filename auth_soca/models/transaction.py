from odoo import api, fields, models


class SocaTransaction(models.Model):
    _name = "soca.transaction"
    _description = "Encrypted single-use SOCA transaction"

    state_hash = fields.Char(required=True, index=True)
    profile_id = fields.Many2one("soca.profile", required=True, ondelete="cascade")
    ciphertext = fields.Text(required=True)
    expires_at = fields.Datetime(required=True)
    _unique_state = models.Constraint("unique(state_hash)", "Transaction state must be unique")

    @api.model
    def _cleanup(self):
        self.sudo().search([("expires_at", "<", fields.Datetime.now())]).unlink()
        self.env["soca.ticket"].sudo().search([("expires_at", "<", fields.Datetime.now())]).unlink()


class SocaTicket(models.Model):
    _name = "soca.ticket"
    _description = "One-use internal SOCA credential"

    token_hash = fields.Char(required=True, index=True)
    browser_hash = fields.Char(required=True)
    user_id = fields.Many2one("res.users", required=True, ondelete="cascade")
    expires_at = fields.Datetime(required=True)
    _unique_token = models.Constraint("unique(token_hash)", "Credential tickets must be unique")
