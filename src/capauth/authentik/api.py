"""CapAuth stage API: serializer and ViewSet for Authentik admin/API.

Register this ViewSet with Authentik's router so CapAuth stages can be created
and bound to flows via the API and admin UI.
"""

from __future__ import annotations

try:
    from rest_framework.viewsets import ModelViewSet

    from authentik.core.api.used_by import UsedByMixin
    from authentik.flows.api.stages import StageSerializer

    from .stage import CapAuthStage

    _API_AVAILABLE = True
except ImportError:
    _API_AVAILABLE = False


if _API_AVAILABLE:

    class CapAuthStageSerializer(StageSerializer):
        """Serializer for CapAuthStage (admin + API)."""

        class Meta:
            model = CapAuthStage
            fields = StageSerializer.Meta.fields + [
                "service_id",
                "require_enrollment_approval",
                "nonce_ttl_seconds",
            ]

    class CapAuthStageViewSet(UsedByMixin, ModelViewSet):
        """ViewSet for CapAuthStage so it appears in Authentik's stage list and can be bound to flows."""

        queryset = CapAuthStage.objects.all()
        serializer_class = CapAuthStageSerializer
        filterset_fields = ["service_id", "require_enrollment_approval"]
        search_fields = ["name", "service_id"]
        ordering = ["name"]
