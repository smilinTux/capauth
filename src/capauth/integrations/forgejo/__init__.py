"""CapAuth — Forgejo passwordless PGP authentication integration.

Forgejo supports OIDC natively.  This integration makes CapAuth act as an
OIDC provider so Forgejo users can log in by signing a challenge with their
PGP private key — no passwords involved.

Components
----------
auth_flow      : PGP challenge-response OIDC authorization code flow.
oidc_provider  : FastAPI router exposing OIDC-compatible endpoints for Forgejo.
forgejo_api    : Forgejo REST API client for user/token management.
config         : Configuration dataclass with env-var loading.
cli            : ``capauth forgejo`` CLI subcommands.
"""

from .config import ForgejoConfig
from .auth_flow import ForgejoAuthFlow
from .forgejo_api import ForgejoAPIClient

__all__ = ["ForgejoConfig", "ForgejoAuthFlow", "ForgejoAPIClient"]
