"""
Custom Authentik settings — loaded by authentik.root.settings via
_update_settings("data.user_settings").

Adds the CapAuth Django app (PGP passwordless stage) to INSTALLED_APPS.
"""

# TENANT_APPS are added to INSTALLED_APPS and included in migrations.
TENANT_APPS = [
    "capauth.apps.CapauthConfig",
]
