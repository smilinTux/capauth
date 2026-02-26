#!/usr/bin/env bash
set -euo pipefail

# Build an Authentik server image with the CapAuth custom stage installed.
#
# Usage:
#   IMAGE=ghcr.io/your-org/authentik-capauth:2025.12.3 ./scripts/build_authentik_capauth_image.sh
# or:
#   ./scripts/build_authentik_capauth_image.sh
#     (defaults to ghcr.io/smilintux/authentik-capauth:2025.12.3)

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

IMAGE="${IMAGE:-ghcr.io/smilintux/authentik-capauth:2025.12.3}"

echo "Building Authentik+CapAuth image: $IMAGE"
docker build -f Dockerfile.authentik-capauth -t "$IMAGE" .

echo
echo "Image built: $IMAGE"
echo "Next steps:"
echo "  1) Push the image to your registry, for example:"
echo "       docker push $IMAGE"
echo "  2) Update your sksso-prod Authentik service to use this image."
echo "  3) Run: python manage.py migrate capauth"
echo "  4) Ensure the frontend CapAuth stage is wired in your Authentik web build."

