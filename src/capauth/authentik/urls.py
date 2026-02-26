"""URL routes for CapAuth Authentik stage API.

Include in Authentik's main URL config so CapAuth stages can be managed and bound to flows.

Example (in Authentik's root urls.py or equivalent):
    path("api/v3/stages/capauth/", include("capauth.authentik.urls")),
"""

from __future__ import annotations

try:
    from rest_framework.routers import DefaultRouter

    from .api import CapAuthStageViewSet

    router = DefaultRouter()
    router.register(r"", CapAuthStageViewSet, basename="capauth-stage")
    urlpatterns = router.urls
except ImportError:
    urlpatterns = []
