{
    "name": "SOCA OpenID Connect",
    "version": "19.0.0.1.0",
    "category": "Authentication",
    "summary": "OIDC code, PKCE and asymmetric CIMD authentication",
    "author": "RESOAuth",
    "website": "https://github.com/RESOAuth/odoo-soca-plugin",
    "license": "AGPL-3",
    "depends": ["base", "web", "portal"],
    "external_dependencies": {"python": ["jwt", "cryptography", "urllib3"]},
    "data": ["security/ir.model.access.csv", "views/soca_views.xml", "views/login.xml", "data/cron.xml"],
    "installable": True,
    "application": False,
}
