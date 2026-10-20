import json
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from odoo.tests.common import TransactionCase, tagged

from .. import config
from ..soca.errors import SocaError


@tagged("post_install", "-at_install")
class TestSocaHost(TransactionCase):
    def setUp(self):
        super().setUp()
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        key = ec.generate_private_key(ec.SECP256R1())
        path = Path(self.directory.name) / "private.pem"
        path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        path.chmod(0o600)
        self.profile = self.env["soca.profile"].create({"name": "test", "configuration": json.dumps({"origin": "https://odoo.example.com", "private_key_file": str(path), "allow_domains": ["example.com"]})})
        self.user = self.env["res.users"].with_context(no_reset_password=True).create({"name": "Portal test", "login": "host-test@example.com", "email": "host-test@example.com", "group_ids": [(6, 0, [self.env.ref("base.group_portal").id])]})
        self.claims = {"sub": "subject-host", "email": "host-test@example.com", "email_verified": True}

    def test_native_schema_and_defaults(self):
        candidate = config.load(self.profile)
        self.assertFalse(self.profile.enabled)
        self.assertEqual(candidate.document()["token_endpoint_auth_signing_alg"], "ES256")
        self.assertEqual(candidate.callback, "https://odoo.example.com/soca/test/callback")

    def test_unlinked_verified_email_is_not_selected(self):
        with self.assertRaises(SocaError):
            self.env["soca.identity"]._resolve(config.load(self.profile), self.claims)

    def test_approved_identity_resolves_exact_user(self):
        candidate = config.load(self.profile)
        self.env["soca.identity"].create({"issuer": candidate.issuer, "subject": self.claims["sub"], "user_id": self.user.id, "approval_reason": "Ownership independently verified in a host integration fixture"})
        self.assertEqual(self.env["soca.identity"]._resolve(candidate, self.claims), self.user)

    def test_disabled_user_is_rejected(self):
        candidate = config.load(self.profile)
        self.env["soca.identity"].create({"issuer": candidate.issuer, "subject": self.claims["sub"], "user_id": self.user.id, "approval_reason": "Host fixture"})
        self.user.active = False
        with self.assertRaises(SocaError):
            self.env["soca.identity"]._resolve(candidate, self.claims)

    def test_provisioning_collision_does_not_relink_email(self):
        candidate = config.load(self.profile)
        candidate.values["provision"] = True
        with self.assertRaises(SocaError):
            self.env["soca.identity"]._resolve(candidate, self.claims)
        self.assertFalse(self.env["soca.identity"].search([("subject", "=", self.claims["sub"])]))

    def test_atomic_portal_provisioning_and_link(self):
        candidate = config.load(self.profile)
        candidate.values["provision"] = True
        self.claims["email"] = "new-portal@example.com"
        user = self.env["soca.identity"]._resolve(candidate, self.claims)
        self.assertTrue(user.share)
        self.assertFalse(user.has_group("base.group_system"))
        self.assertEqual(self.env["soca.identity"].search([("issuer", "=", candidate.issuer), ("subject", "=", self.claims["sub"])]).user_id, user)

    def test_evidence_cannot_be_forged_by_form(self):
        from odoo.exceptions import AccessError
        with self.assertRaises(AccessError):
            self.profile.write({"login_evidence": "forged"})

    def test_activation_requires_real_evidence(self):
        with self.assertRaises(SocaError):
            self.profile.write({"enabled": True})
