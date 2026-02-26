"""CapAuth Verification Service — standalone server launcher.

Usage:
    capauth-service                    # Start on 0.0.0.0:8420
    capauth-service --port 9000        # Custom port
    CAPAUTH_SERVICE_ID=myserver capauth-service  # Custom service ID

Environment variables:
    CAPAUTH_SERVICE_ID       — Service identifier (default: capauth.local)
    CAPAUTH_SERVER_KEY_ARMOR — Server's PGP private key for signing challenges
    CAPAUTH_SERVER_KEY_PASSPHRASE — Passphrase for the server key
    CAPAUTH_REQUIRE_APPROVAL — Require admin approval for new keys (true/false)
    CAPAUTH_DB_PATH          — SQLite database path (default: ~/.capauth/service/keys.db)
    CAPAUTH_ADMIN_TOKEN      — Bearer token for admin API access
    CAPAUTH_BASE_URL         — Public base URL for OIDC discovery
"""

from __future__ import annotations

import click


@click.command()
@click.option("--host", default="0.0.0.0", help="Bind address.")
@click.option("--port", default=8420, type=int, help="Listen port.")
@click.option("--reload", "do_reload", is_flag=True, help="Auto-reload on code changes.")
def main(host: str, port: int, do_reload: bool) -> None:
    """Start the CapAuth Verification Service.

    Passwordless PGP authentication for Nextcloud, Forgejo, and any app.
    """
    try:
        import uvicorn
    except ImportError:
        click.echo("Error: uvicorn not installed. Run: pip install capauth[service]")
        raise SystemExit(1)

    click.echo(f"CapAuth Verification Service starting on {host}:{port}")
    click.echo("Endpoints:")
    click.echo(f"  POST http://{host}:{port}/capauth/v1/challenge")
    click.echo(f"  POST http://{host}:{port}/capauth/v1/verify")
    click.echo(f"  GET  http://{host}:{port}/capauth/v1/status")
    click.echo(f"  GET  http://{host}:{port}/.well-known/openid-configuration")

    uvicorn.run(
        "capauth.service.app:app",
        host=host,
        port=port,
        reload=do_reload,
        log_level="info",
    )


if __name__ == "__main__":
    main()
