"""CapAuth Verification Service — standalone FastAPI server.

Exposes the CapAuth challenge-response protocol as HTTP endpoints
so any application (Nextcloud, Forgejo, Immich, custom apps) can
add passwordless PGP authentication by calling this service.
"""
