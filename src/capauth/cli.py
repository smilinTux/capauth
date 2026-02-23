"""CapAuth CLI — sovereign identity from your terminal.

Usage:
    capauth init --name "Chef" --email "admin@smilintux.org"
    capauth profile show
    capauth profile verify
    capauth verify --pubkey peer.pub.asc
    capauth export-pubkey
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .exceptions import CapAuthError
from .models import Algorithm, CryptoBackendType, EntityType

if TYPE_CHECKING:
    from .models import SovereignProfile

console = Console()


@click.group()
@click.version_option(__version__, prog_name="capauth")
@click.option(
    "--home",
    "capauth_home",
    envvar="CAPAUTH_HOME",
    default=None,
    type=click.Path(),
    help="CapAuth home directory (default: ~/.capauth/).",
)
@click.pass_context
def main(ctx: click.Context, capauth_home: Optional[str]) -> None:
    """CapAuth -- Capability-based Authentication.

    OAuth is dead. Long live sovereignty.
    """
    ctx.ensure_object(dict)
    ctx.obj["home"] = Path(capauth_home) if capauth_home else None


@main.command()
@click.option("--name", "-n", required=True, prompt="Your name", help="Display name.")
@click.option(
    "--email", "-e", required=True, prompt="Your email", help="Email or AI identifier."
)
@click.option(
    "--passphrase",
    "-p",
    prompt=True,
    hide_input=True,
    confirmation_prompt=True,
    help="Passphrase to protect your private key.",
)
@click.option(
    "--type",
    "entity_type",
    type=click.Choice(["human", "ai", "organization"], case_sensitive=False),
    default="human",
    help="Entity type (default: human).",
)
@click.option(
    "--algorithm",
    type=click.Choice(["ed25519", "rsa4096"], case_sensitive=False),
    default="rsa4096",
    help="Key algorithm (default: rsa4096).",
)
@click.option(
    "--backend",
    type=click.Choice(["pgpy", "gnupg"], case_sensitive=False),
    default="pgpy",
    help="Crypto backend (default: pgpy).",
)
@click.pass_context
def init(
    ctx: click.Context,
    name: str,
    email: str,
    passphrase: str,
    entity_type: str,
    algorithm: str,
    backend: str,
) -> None:
    """Create your sovereign profile.

    Generates a PGP keypair and initializes your CapAuth identity.
    Your keys and profile live on YOUR machine, under YOUR control.
    """
    from .profile import init_profile

    base = ctx.obj.get("home")
    algo = Algorithm.ED25519 if algorithm == "ed25519" else Algorithm.RSA4096
    etype = EntityType(entity_type)
    btype = CryptoBackendType(backend)

    try:
        console.print(f"\n[bold cyan]Generating {algorithm.upper()} keypair...[/]")
        profile = init_profile(
            name=name,
            email=email,
            passphrase=passphrase,
            entity_type=etype,
            algorithm=algo,
            backend_type=btype,
            base_dir=base,
        )
        _render_profile(profile)
        console.print(
            Panel(
                "[bold green]Sovereign profile created.[/]\n\n"
                f"Your identity lives at: [cyan]{profile.storage.primary}/identity/[/]\n"
                "Your PGP fingerprint is your global identity.\n"
                "No corporation. No middleman. [bold]You are sovereign.[/]",
                title="Welcome to CapAuth",
                border_style="green",
            )
        )
    except CapAuthError as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise SystemExit(1)


@main.group()
def profile() -> None:
    """Manage your sovereign profile."""


@profile.command("show")
@click.pass_context
def profile_show(ctx: click.Context) -> None:
    """Display your sovereign profile."""
    from .profile import load_profile

    base = ctx.obj.get("home")

    try:
        p = load_profile(base)
        _render_profile(p)
    except CapAuthError as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise SystemExit(1)


@profile.command("verify")
@click.pass_context
def profile_verify(ctx: click.Context) -> None:
    """Verify your profile's PGP signature integrity."""
    from .profile import load_profile, verify_profile_signature

    base = ctx.obj.get("home")

    try:
        p = load_profile(base)
        valid = verify_profile_signature(p, base)
        if valid:
            console.print("[bold green]Profile signature is VALID.[/]")
        else:
            console.print("[bold red]Profile signature is INVALID or missing.[/]")
            raise SystemExit(1)
    except CapAuthError as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise SystemExit(1)


@main.command("export-pubkey")
@click.option(
    "--output", "-o", type=click.Path(), default=None, help="Write to file instead of stdout."
)
@click.pass_context
def export_pubkey(ctx: click.Context, output: Optional[str]) -> None:
    """Export your ASCII-armored public key.

    Share this with peers so they can verify your identity
    and send you encrypted data.
    """
    from .profile import export_public_key

    base = ctx.obj.get("home")

    try:
        armor = export_public_key(base)
        if output:
            Path(output).write_text(armor, encoding="utf-8")
            console.print(f"[green]Public key written to {output}[/]")
        else:
            click.echo(armor)
    except CapAuthError as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise SystemExit(1)


@main.command("verify")
@click.option(
    "--pubkey",
    required=True,
    type=click.Path(exists=True),
    help="Path to the peer's public key (.asc).",
)
@click.option(
    "--passphrase",
    "-p",
    prompt=True,
    hide_input=True,
    help="Your private key passphrase.",
)
@click.pass_context
def verify_peer(ctx: click.Context, pubkey: str, passphrase: str) -> None:
    """Run a challenge-response identity verification with a peer.

    Generates a challenge, signs it locally, and verifies the
    round-trip to confirm that you hold the matching private key.
    This is a local self-test / demo of the verification flow.
    """
    from .identity import create_challenge, respond_to_challenge, verify_challenge
    from .profile import export_public_key, load_profile

    base = ctx.obj.get("home")

    try:
        p = load_profile(base)
        my_pub = export_public_key(base)
        peer_pub = Path(pubkey).read_text(encoding="utf-8")

        from .crypto import get_backend

        backend = get_backend(p.crypto_backend)
        peer_fp = backend.fingerprint_from_armor(peer_pub)

        console.print(f"[cyan]Challenging peer {peer_fp[:16]}...[/]")
        challenge = create_challenge(p.key_info.fingerprint, peer_fp)

        priv_armor = Path(p.key_info.private_key_path).read_text(encoding="utf-8")
        response = respond_to_challenge(
            challenge, priv_armor, passphrase, p.crypto_backend
        )

        verified = verify_challenge(challenge, response, my_pub, p.crypto_backend)

        if verified:
            console.print(
                Panel(
                    f"[bold green]Identity VERIFIED[/]\n"
                    f"Fingerprint: [cyan]{peer_fp}[/]\n"
                    f"Challenge ID: {challenge.challenge_id}",
                    title="Verification Passed",
                    border_style="green",
                )
            )
        else:
            console.print("[bold red]Verification FAILED — signature invalid.[/]")
            raise SystemExit(1)
    except CapAuthError as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise SystemExit(1)


def _render_profile(p: "SovereignProfile") -> None:
    """Pretty-print a sovereign profile using Rich.

    Args:
        p: The profile to render.
    """
    table = Table(title="Sovereign Profile", show_header=False, border_style="cyan")
    table.add_column("Field", style="bold")
    table.add_column("Value")

    table.add_row("Profile ID", p.profile_id)
    table.add_row("Name", p.entity.name)
    table.add_row("Email", p.entity.email or "—")
    table.add_row("Handle", p.entity.handle or "—")
    table.add_row("Type", p.entity.entity_type.value)
    table.add_row("Fingerprint", p.key_info.fingerprint)
    table.add_row("Algorithm", p.key_info.algorithm.value)
    table.add_row("Backend", p.crypto_backend.value)
    table.add_row("Storage", p.storage.primary)
    table.add_row("Created", p.created.isoformat())
    table.add_row("Signed", "Yes" if p.signature else "No")

    console.print(table)
