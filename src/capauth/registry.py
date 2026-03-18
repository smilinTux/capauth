"""
Registry management for organization membership.

A registry entry is a YAML document describing a member of a
sovereign organization. It contains the member's name, title, role,
CapAuth URI, and optional metadata like AI partner or motto.

Registry entries are stored locally at ~/.capauth/registry/ and can
be submitted to an organization's Git repository as a pull request.
"""

from __future__ import annotations

import logging
from datetime import date
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field

DEFAULT_CAPAUTH_DIR = Path.home() / ".capauth"

logger = logging.getLogger("capauth.registry")

REGISTRY_DIR = "registry"


class RegistryEntry(BaseModel):
    """A member's entry in an organization's registry.

    Mirrors the YAML format used in smilinTux's join.md:
    title, name, type, joined date, role, capauth_uri, etc.

    Attributes:
        title: Sovereign title (King, Queen, Sovereign).
        name: Display name.
        alias: Optional alias or username.
        member_type: "Human" or "AI".
        joined: Date of registration.
        role: Role or contribution area.
        org: Organization slug (e.g. "smilintux").
        capauth_uri: CapAuth URI (name@org.tld).
        fingerprint: PGP fingerprint for verification.
        ai_partner: Name of AI partner (for humans).
        human_partner: Name of human partner (for AIs).
        substrate: "Carbon" or "Silicon".
        projects: List of project contributions.
        motto: Personal motto or tagline.
        pronouns: Optional pronouns.
        email: Contact email.
        publish_to_skworld: Whether to publish DID to skworld.io (default: True).
            Set to False to opt out of public DID publishing while keeping
            local identity and mesh-private DID documents.
    """

    title: str = "King"
    name: str
    alias: Optional[str] = None
    member_type: str = "Human"
    joined: str = Field(default_factory=lambda: date.today().isoformat())
    role: str = "Member"
    org: str = "smilintux"
    capauth_uri: str = ""
    fingerprint: str = ""
    ai_partner: Optional[str] = None
    human_partner: Optional[str] = None
    substrate: str = "Carbon"
    projects: list[str] = Field(default_factory=list)
    motto: Optional[str] = None
    pronouns: Optional[str] = None
    email: Optional[str] = None
    publish_to_skworld: bool = True

    def to_yaml(self) -> str:
        """Serialize the entry to YAML matching the kingdom registry format.

        Returns:
            YAML string with frontmatter delimiters.
        """
        data: dict = {"title": self.title, "name": self.name}

        if self.alias:
            data["alias"] = self.alias
        if self.member_type != "Human":
            data["type"] = self.member_type
            data["substrate"] = self.substrate

        data["joined"] = self.joined
        data["role"] = self.role
        data["capauth_uri"] = self.capauth_uri

        if self.fingerprint:
            data["fingerprint"] = self.fingerprint
        if self.ai_partner:
            data["ai_partner"] = self.ai_partner
        if self.human_partner:
            data["human_partner"] = self.human_partner
        if self.projects:
            data["projects"] = self.projects
        if self.pronouns:
            data["pronouns"] = self.pronouns
        if self.motto:
            data["motto"] = self.motto
        if not self.publish_to_skworld:
            data["publish_to_skworld"] = False

        return "---\n" + yaml.dump(data, default_flow_style=False, sort_keys=False) + "---\n"


# Reason: maps org slugs to their domain for capauth_uri generation
ORG_DOMAINS: dict[str, str] = {
    "smilintux": "smilintux.org",
    "skworld": "skworld.io",
}


def build_capauth_uri(name: str, org: str) -> str:
    """Build a capauth URI from a name and organization.

    Args:
        name: Member's display name.
        org: Organization slug.

    Returns:
        URI like "capauth:name@smilintux.org".
    """
    slug = name.lower().replace(" ", "-")
    domain = ORG_DOMAINS.get(org, f"{org}.org")
    return f"capauth:{slug}@{domain}"


def save_registry_entry(
    entry: RegistryEntry,
    base_dir: Optional[Path] = None,
) -> Path:
    """Write a registry entry to the local registry directory.

    Args:
        entry: The registry entry to save.
        base_dir: CapAuth home directory.

    Returns:
        Path to the written YAML file.
    """
    base = base_dir or DEFAULT_CAPAUTH_DIR
    registry_dir = base / REGISTRY_DIR
    registry_dir.mkdir(parents=True, exist_ok=True)

    slug = entry.name.lower().replace(" ", "-")
    filename = f"{entry.org}-{slug}.yml"
    path = registry_dir / filename

    path.write_text(entry.to_yaml(), encoding="utf-8")
    logger.info("Saved registry entry for %s at %s", entry.name, path)
    return path


def load_registry_entries(
    base_dir: Optional[Path] = None,
    org: Optional[str] = None,
) -> list[RegistryEntry]:
    """Load registry entries from disk.

    Args:
        base_dir: CapAuth home directory.
        org: Filter by organization slug.

    Returns:
        List of RegistryEntry objects.
    """
    base = base_dir or DEFAULT_CAPAUTH_DIR
    registry_dir = base / REGISTRY_DIR

    if not registry_dir.exists():
        return []

    entries: list[RegistryEntry] = []
    pattern = f"{org}-*.yml" if org else "*.yml"

    for f in sorted(registry_dir.glob(pattern)):
        try:
            raw = f.read_text(encoding="utf-8")
            cleaned = raw.strip().strip("-").strip()
            data = yaml.safe_load(cleaned)
            if data:
                entries.append(RegistryEntry.model_validate(data))
        except Exception as exc:
            logger.warning("Failed to load registry entry %s: %s", f, exc)

    return entries
