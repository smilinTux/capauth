"""CapAuth Authentik integration.

Custom authentication stage for Authentik that implements the CapAuth
zero-knowledge passwordless protocol. Drop this into an Authentik instance
as a custom stage to enable PGP-based authentication with client-asserted claims.

No user PII is stored. The Authentik user record contains only the PGP fingerprint.
All display fields (name, email, avatar, groups) are populated fresh from client
claims at each login and flow into the OIDC token — then discarded.
"""
