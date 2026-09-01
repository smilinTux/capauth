"""Top-level CapAuth URL routes — discovered by Authentik's API URL builder.

Authentik's ``authentik/api/v3/urls.py`` iterates every installed app and does
``import_module(f"{app.name}.urls")``, then registers anything in that module's
``api_urlpatterns`` list onto its DefaultRouter. Because the CapAuth Django app
registers with ``name = "capauth"`` (see ``capauth.apps.CapauthConfig``), Authentik
imports **this** module (``capauth.urls``) — NOT ``capauth.authentik.urls``.

Defining ``api_urlpatterns`` here is therefore what wires the CapAuth stage into
the admin/API at ``/api/v3/stages/capauth/`` (so the stage can be listed, created,
and bound to flows via the UI/API). The ViewSet itself lives in
``capauth.authentik.api`` next to the stage model.

Each entry is ``(prefix, ViewSet[, basename])`` and is passed straight to
``router.register(*entry)``.

Import is guarded so the module stays importable in plain CapAuth (CLI/service)
environments where neither Django nor Authentik is installed — in that case it
exposes an empty ``api_urlpatterns`` and a no-op ``urlpatterns``.
"""

from __future__ import annotations

try:
    from .authentik.api import CapAuthStageViewSet

    # Mounted by Authentik's API router at /api/v3/<prefix>/
    api_urlpatterns = [
        ("stages/capauth", CapAuthStageViewSet, "capauthstage"),
    ]
except Exception:  # pragma: no cover - non-Authentik environments
    api_urlpatterns = []

# Some Authentik code paths also import an app's ``urlpatterns`` (page routes).
# CapAuth has no page routes, so expose an empty list to stay safe.
urlpatterns: list = []
