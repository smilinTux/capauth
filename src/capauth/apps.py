"""Django AppConfig for CapAuth when used as an Authentik custom stage.

Only relevant when capauth is installed in an Authentik environment and
added to INSTALLED_APPS. Ignored when running the standalone CapAuth service or CLI.
"""

from __future__ import annotations

try:
    from django.apps import AppConfig
except ImportError:
    AppConfig = None  # type: ignore[misc, assignment]


if AppConfig is not None:

    class CapauthConfig(AppConfig):
        """Django app config for the CapAuth Authentik stage and key registry."""

        default_auto_field = "django.db.models.BigAutoField"
        name = "capauth"
        label = "capauth"
        verbose_name = "CapAuth"
