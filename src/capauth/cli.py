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


@main.group()
def pma() -> None:
    """PMA membership — Fiducia Communitatis.

    Manage your Private Membership Association status.
    Sovereignty is a right, not a product.
    """


@pma.command("request")
@click.option("--reason", "-r", default="", help="Why you want to join.")
@click.option(
    "--passphrase",
    "-p",
    prompt=True,
    hide_input=True,
    help="Passphrase to sign the request.",
)
@click.pass_context
def pma_request(ctx: click.Context, reason: str, passphrase: str) -> None:
    """Request PMA membership.

    Creates a PGP-signed membership request that a steward can review
    and countersign. Your identity must already be initialized.
    """
    from .pma import create_request
    from .profile import load_profile

    base = ctx.obj.get("home")

    try:
        profile = load_profile(base)
        req = create_request(
            name=profile.entity.name,
            fingerprint=profile.key_info.fingerprint,
            entity_type=profile.entity.entity_type.value,
            reason=reason,
            base_dir=base,
            passphrase=passphrase,
        )
        console.print(
            Panel(
                f"[bold green]Membership request created[/]\n\n"
                f"Request ID: [cyan]{req.request_id}[/]\n"
                f"Name: {req.requestor_name}\n"
                f"Fingerprint: {req.requestor_fingerprint[:16]}...\n"
                f"Signed: {'Yes' if req.requestor_signature else 'No'}\n\n"
                "Send this request to a steward for approval.\n"
                "Contact: [cyan]lumina@skworld.io[/]",
                title="PMA Membership Request",
                border_style="cyan",
            )
        )
    except CapAuthError as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise SystemExit(1)


@pma.command("approve")
@click.argument("request_id")
@click.option(
    "--capabilities",
    "-c",
    default="pma:member",
    help="Comma-separated capabilities to grant (default: pma:member).",
)
@click.option(
    "--passphrase",
    "-p",
    prompt=True,
    hide_input=True,
    help="Steward passphrase to countersign.",
)
@click.pass_context
def pma_approve(
    ctx: click.Context, request_id: str, capabilities: str, passphrase: str
) -> None:
    """Approve a membership request (steward only).

    Reviews and countersigns a pending request, issuing a
    membership claim with the specified capabilities.
    """
    from .pma import approve_request, load_requests
    from .profile import load_profile

    base = ctx.obj.get("home")

    try:
        profile = load_profile(base)
        requests = load_requests(base)
        matching = [r for r in requests if r.request_id.startswith(request_id)]

        if not matching:
            console.print(f"[bold red]No request found matching '{request_id}'[/]")
            raise SystemExit(1)

        req = matching[0]
        caps = [c.strip() for c in capabilities.split(",") if c.strip()]

        claim = approve_request(
            request=req,
            steward_name=profile.entity.name,
            steward_fingerprint=profile.key_info.fingerprint,
            capabilities=caps,
            base_dir=base,
            passphrase=passphrase,
        )

        console.print(
            Panel(
                f"[bold green]Membership APPROVED[/]\n\n"
                f"Claim ID: [cyan]{claim.claim_id}[/]\n"
                f"Member: {claim.member_name}\n"
                f"Steward: {claim.steward_name}\n"
                f"Capabilities: {', '.join(c.name for c in claim.capabilities)}\n"
                f"Signed: {'Yes' if claim.steward_signature else 'No'}",
                title="PMA Membership Claim Issued",
                border_style="green",
            )
        )
    except CapAuthError as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise SystemExit(1)


@pma.command("status")
@click.option("--json-out", is_flag=True, help="Output as JSON.")
@click.pass_context
def pma_status(ctx: click.Context, json_out: bool) -> None:
    """Show PMA membership status."""
    import json as _json

    from .pma import get_membership_status

    base = ctx.obj.get("home")

    try:
        status = get_membership_status(base)

        if json_out:
            click.echo(_json.dumps(status, indent=2, default=str))
            return

        if status["is_member"]:
            emoji = "[bold green]ACTIVE MEMBER[/]"
        else:
            emoji = "[bold yellow]NOT A MEMBER[/]"

        table = Table(
            title="PMA Membership Status", show_header=False, border_style="cyan"
        )
        table.add_column("Field", style="bold")
        table.add_column("Value")

        table.add_row("Status", emoji)
        table.add_row("Active Claims", str(status["active_claims"]))
        table.add_row("Capabilities", ", ".join(status["capabilities"]) or "—")
        table.add_row("Steward", status["steward"] or "—")
        table.add_row("Pending Requests", str(status["pending_requests"]))

        console.print(table)
    except Exception as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise SystemExit(1)


@pma.command("verify")
@click.argument("claim_file", type=click.Path(exists=True))
@click.option(
    "--steward-pubkey",
    type=click.Path(exists=True),
    default=None,
    help="Steward's public key for signature verification.",
)
@click.pass_context
def pma_verify(
    ctx: click.Context, claim_file: str, steward_pubkey: Optional[str]
) -> None:
    """Verify a membership claim.

    Checks that the claim is not revoked, capabilities are current,
    and optionally verifies the steward's PGP signature.
    """
    import json as _json

    from .pma import MembershipClaim, verify_claim

    base = ctx.obj.get("home")

    try:
        data = _json.loads(Path(claim_file).read_text(encoding="utf-8"))
        claim = MembershipClaim.model_validate(data)

        pubkey = None
        if steward_pubkey:
            pubkey = Path(steward_pubkey).read_text(encoding="utf-8")

        valid = verify_claim(claim, pubkey, base)

        if valid:
            console.print(
                Panel(
                    f"[bold green]Membership claim is VALID[/]\n\n"
                    f"Member: {claim.member_name}\n"
                    f"Fingerprint: {claim.member_fingerprint[:16]}...\n"
                    f"Steward: {claim.steward_name}\n"
                    f"Capabilities: {', '.join(c.name for c in claim.capabilities)}",
                    title="Verification Passed",
                    border_style="green",
                )
            )
        else:
            console.print("[bold red]Membership claim is INVALID or REVOKED.[/]")
            raise SystemExit(1)
    except CapAuthError as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise SystemExit(1)


@pma.command("revoke")
@click.argument("claim_id")
@click.confirmation_option(prompt="Revoke this membership claim?")
@click.pass_context
def pma_revoke(ctx: click.Context, claim_id: str) -> None:
    """Revoke a membership claim (steward only)."""
    from .pma import revoke_claim

    base = ctx.obj.get("home")

    try:
        if revoke_claim(claim_id, base):
            console.print(f"[bold green]Claim {claim_id[:8]}... revoked.[/]")
        else:
            console.print(f"[bold red]Claim '{claim_id}' not found.[/]")
            raise SystemExit(1)
    except Exception as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise SystemExit(1)


@main.command()
@click.option("--org", "-o", default="smilintux", help="Organization to register with.")
@click.option("--name", "-n", required=True, prompt="Your name", help="Display name.")
@click.option(
    "--title",
    "-t",
    type=click.Choice(["King", "Queen", "Sovereign"], case_sensitive=False),
    default="King",
    help="Your sovereign title (default: King).",
)
@click.option("--email", "-e", default=None, help="Contact email or AI identifier.")
@click.option(
    "--type",
    "entity_type",
    type=click.Choice(["human", "ai"], case_sensitive=False),
    default="human",
    help="Entity type (default: human).",
)
@click.option("--role", "-r", default="Member", help="Your role or contribution area.")
@click.option("--alias", default=None, help="Username or alias.")
@click.option("--ai-partner", default=None, help="Your AI partner's name (for humans).")
@click.option("--human-partner", default=None, help="Your human partner's name (for AIs).")
@click.option("--motto", default=None, help="Personal motto or tagline.")
@click.option("--pronouns", default=None, help="Pronouns (optional).")
@click.option("--projects", default=None, help="Comma-separated project list.")
@click.pass_context
def register(
    ctx: click.Context,
    org: str,
    name: str,
    title: str,
    email: Optional[str],
    entity_type: str,
    role: str,
    alias: Optional[str],
    ai_partner: Optional[str],
    human_partner: Optional[str],
    motto: Optional[str],
    pronouns: Optional[str],
    projects: Optional[str],
) -> None:
    """Register with a sovereign organization.

    Creates your CapAuth profile (if needed), generates a registry
    entry, and submits a PMA membership request — all in one step.

    \b
    Examples:
        capauth register --org smilintux --name "YourName" --title King
        capauth register --name "Lumina" --type ai --title Queen --role "Partner"
    """
    from .pma import create_request
    from .profile import load_profile
    from .registry import RegistryEntry, build_capauth_uri, save_registry_entry

    base = ctx.obj.get("home")
    project_list = [p.strip() for p in projects.split(",") if p.strip()] if projects else []

    # Step 1: ensure profile exists
    try:
        profile = load_profile(base)
        console.print(f"\n  [dim]Using existing profile: {profile.entity.name}[/]")
    except CapAuthError:
        console.print(
            "\n  [yellow]No CapAuth profile found.[/]\n"
            "  Run [bold cyan]capauth init[/] first to create your sovereign identity.\n"
        )
        raise SystemExit(1)

    # Step 2: build and save registry entry
    etype = EntityType(entity_type)
    capauth_uri = build_capauth_uri(name, org)
    substrate = "Silicon" if etype == EntityType.AI else "Carbon"

    entry = RegistryEntry(
        title=title.capitalize(),
        name=name,
        alias=alias,
        member_type="AI" if etype == EntityType.AI else "Human",
        role=role,
        org=org,
        capauth_uri=capauth_uri,
        fingerprint=profile.key_info.fingerprint,
        ai_partner=ai_partner,
        human_partner=human_partner,
        substrate=substrate,
        projects=project_list,
        motto=motto,
        pronouns=pronouns,
        email=email or profile.entity.email,
    )

    entry_path = save_registry_entry(entry, base)

    # Step 3: submit PMA membership request
    reason = f"Registering as {title} of {org} (role: {role})"
    try:
        req = create_request(
            name=name,
            fingerprint=profile.key_info.fingerprint,
            entity_type=entity_type,
            reason=reason,
            base_dir=base,
        )
        request_submitted = True
    except Exception as exc:
        console.print(f"  [yellow]PMA request skipped:[/] {exc}")
        req = None
        request_submitted = False

    # Step 4: display results
    console.print(
        Panel(
            f"[bold green]Registered with {org}[/]\n\n"
            f"Title: [bold]{entry.title}[/]\n"
            f"Name: [bold cyan]{entry.name}[/]\n"
            f"Role: {entry.role}\n"
            f"Type: {entry.member_type}\n"
            f"URI: [cyan]{entry.capauth_uri}[/]\n"
            f"Fingerprint: {entry.fingerprint[:16]}...\n"
            + (f"PMA Request: [cyan]{req.request_id[:8]}...[/]\n" if req else "")
            + f"\nRegistry entry: [cyan]{entry_path}[/]",
            title=f"Welcome to {org}, {entry.title} {entry.name}",
            border_style="green",
        )
    )

    # Step 5: next steps
    console.print("  [bold]Next steps:[/]")
    if request_submitted:
        console.print("    1. A steward will review your PMA membership request")
        console.print("    2. Submit your registry entry as a PR to the org repo")
    else:
        console.print("    1. Submit your registry entry as a PR to the org repo")

    console.print(f"    [dim]Registry YAML:[/] {entry_path}")
    console.print(f"    [dim]Contact:[/] join@{org}.org\n")


# ── Mesh commands ──────────────────────────────────────────────────


@main.group()
def mesh() -> None:
    """P2P identity mesh — find and verify sovereign peers.

    Discover peers on local networks, shared filesystems,
    and global relays. No servers required.
    """


@mesh.command("discover")
@click.option("--timeout", default=5, help="Discovery timeout in seconds.")
@click.option("--json-out", is_flag=True, help="Output as JSON.")
@click.pass_context
def mesh_discover(ctx: click.Context, timeout: int, json_out: bool) -> None:
    """Discover peers on all available networks."""
    import json as _json

    from .discovery.file_discovery import FileDiscovery
    from .mesh import PeerMesh
    from .profile import load_profile

    base = ctx.obj.get("home")

    try:
        profile = load_profile(base)
        m = PeerMesh(
            fingerprint=profile.key_info.fingerprint,
            name=profile.entity.name,
            entity_type=profile.entity.entity_type.value,
            base_dir=base,
        )
        m.add_backend(FileDiscovery())

        try:
            from .discovery.mdns import MDNSDiscovery

            m.add_backend(MDNSDiscovery())
        except ImportError:
            pass

        m.start()
        peers = m.discover_all(timeout_ms=timeout * 1000)
        m.stop()

        if json_out:
            click.echo(
                _json.dumps(
                    [p.model_dump(mode="json") for p in peers], indent=2, default=str
                )
            )
            return

        if not peers:
            console.print("[yellow]No peers discovered.[/]")
            return

        table = Table(title=f"Discovered Peers ({len(peers)})", border_style="cyan")
        table.add_column("Name", style="bold")
        table.add_column("Fingerprint")
        table.add_column("Type")
        table.add_column("Method")
        table.add_column("Address")

        for p in peers:
            table.add_row(
                p.name or "—",
                p.fingerprint[:16] + "...",
                p.entity_type,
                p.discovery_method,
                p.address or "—",
            )

        console.print(table)

    except CapAuthError as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise SystemExit(1)


@mesh.command("peers")
@click.option("--verified", is_flag=True, help="Show only verified peers.")
@click.option("--json-out", is_flag=True, help="Output as JSON.")
@click.pass_context
def mesh_peers(ctx: click.Context, verified: bool, json_out: bool) -> None:
    """List known peers from the registry."""
    import json as _json

    from .mesh import PeerMesh
    from .profile import load_profile

    base = ctx.obj.get("home")

    try:
        profile = load_profile(base)
        m = PeerMesh(
            fingerprint=profile.key_info.fingerprint,
            name=profile.entity.name,
            base_dir=base,
        )
        peers = m.get_peers(verified_only=verified)

        if json_out:
            click.echo(
                _json.dumps(
                    [p.model_dump(mode="json") for p in peers], indent=2, default=str
                )
            )
            return

        if not peers:
            console.print("[yellow]No known peers.[/]")
            return

        table = Table(title=f"Known Peers ({len(peers)})", border_style="cyan")
        table.add_column("Name", style="bold")
        table.add_column("Fingerprint")
        table.add_column("Type")
        table.add_column("Verified")
        table.add_column("Last Seen")

        for p in peers:
            v = "[green]Yes[/]" if p.verified else "[yellow]No[/]"
            table.add_row(
                p.name or "—",
                p.fingerprint[:16] + "...",
                p.entity_type,
                v,
                p.last_seen.strftime("%Y-%m-%d %H:%M") if p.last_seen else "—",
            )

        console.print(table)

    except CapAuthError as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise SystemExit(1)


@mesh.command("status")
@click.option("--json-out", is_flag=True, help="Output as JSON.")
@click.pass_context
def mesh_status(ctx: click.Context, json_out: bool) -> None:
    """Show mesh network status."""
    import json as _json

    from .discovery.file_discovery import FileDiscovery
    from .mesh import PeerMesh
    from .profile import load_profile

    base = ctx.obj.get("home")

    try:
        profile = load_profile(base)
        m = PeerMesh(
            fingerprint=profile.key_info.fingerprint,
            name=profile.entity.name,
            entity_type=profile.entity.entity_type.value,
            base_dir=base,
        )
        m.add_backend(FileDiscovery())

        try:
            from .discovery.mdns import MDNSDiscovery

            m.add_backend(MDNSDiscovery())
        except ImportError:
            pass

        status = m.mesh_status()

        if json_out:
            click.echo(_json.dumps(status, indent=2, default=str))
            return

        table = Table(title="Mesh Status", show_header=False, border_style="cyan")
        table.add_column("Field", style="bold")
        table.add_column("Value")

        table.add_row("Identity", status["identity"] + "...")
        table.add_row("Name", status["name"])
        table.add_row("Backends", ", ".join(status["backends"]) or "none")
        table.add_row("Total Peers", str(status["total_peers"]))
        table.add_row("Verified", str(status["verified_peers"]))
        table.add_row("Unverified", str(status["unverified_peers"]))

        console.print(table)

    except CapAuthError as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise SystemExit(1)


@mesh.command("announce")
@click.pass_context
def mesh_announce(ctx: click.Context) -> None:
    """Announce your presence on all discovery backends."""
    from .discovery.base import PeerInfo
    from .discovery.file_discovery import FileDiscovery
    from .mesh import PeerMesh
    from .profile import load_profile

    base = ctx.obj.get("home")

    try:
        profile = load_profile(base)
        m = PeerMesh(
            fingerprint=profile.key_info.fingerprint,
            name=profile.entity.name,
            entity_type=profile.entity.entity_type.value,
            base_dir=base,
        )
        m.add_backend(FileDiscovery())

        try:
            from .discovery.mdns import MDNSDiscovery

            m.add_backend(MDNSDiscovery())
        except ImportError:
            pass

        m.start()
        console.print(
            f"[bold green]Announced[/] {profile.entity.name} "
            f"({profile.key_info.fingerprint[:16]}...) "
            f"on {len(m._backends)} backend(s)"
        )
        m.stop()

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
