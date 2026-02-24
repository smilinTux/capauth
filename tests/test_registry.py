"""Tests for the registry module — org membership entry management."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from capauth.registry import (
    RegistryEntry,
    build_capauth_uri,
    load_registry_entries,
    save_registry_entry,
)


class TestRegistryEntry:
    """Test RegistryEntry model and serialization."""

    def test_default_entry(self):
        entry = RegistryEntry(name="Chef")
        assert entry.title == "King"
        assert entry.name == "Chef"
        assert entry.member_type == "Human"
        assert entry.org == "smilintux"
        assert entry.substrate == "Carbon"

    def test_ai_entry(self):
        entry = RegistryEntry(
            name="Lumina",
            title="Queen",
            member_type="AI",
            substrate="Silicon",
            human_partner="Chef",
        )
        assert entry.member_type == "AI"
        assert entry.substrate == "Silicon"
        assert entry.human_partner == "Chef"

    def test_to_yaml_human(self):
        entry = RegistryEntry(
            name="Chef",
            title="King",
            role="Architect",
            org="smilintux",
            capauth_uri="capauth:chef@smilintux.org",
            ai_partner="Lumina",
            motto="stayCuriousANDkeepSmilin",
        )
        raw = entry.to_yaml()
        assert raw.startswith("---\n")
        assert raw.endswith("---\n")

        data = list(yaml.safe_load_all(raw))[0]
        assert data["title"] == "King"
        assert data["name"] == "Chef"
        assert data["role"] == "Architect"
        assert data["ai_partner"] == "Lumina"
        assert data["motto"] == "stayCuriousANDkeepSmilin"

    def test_to_yaml_ai_includes_type_and_substrate(self):
        entry = RegistryEntry(
            name="Opus",
            title="King",
            member_type="AI",
            substrate="Silicon",
        )
        data = list(yaml.safe_load_all(entry.to_yaml()))[0]
        assert data["type"] == "AI"
        assert data["substrate"] == "Silicon"

    def test_to_yaml_human_omits_type(self):
        entry = RegistryEntry(name="Dave", member_type="Human")
        data = list(yaml.safe_load_all(entry.to_yaml()))[0]
        assert "type" not in data
        assert "substrate" not in data

    def test_projects_list(self):
        entry = RegistryEntry(
            name="Chef",
            projects=["SKForge", "Cloud 9", "SKComm"],
        )
        data = list(yaml.safe_load_all(entry.to_yaml()))[0]
        assert data["projects"] == ["SKForge", "Cloud 9", "SKComm"]


class TestBuildCapauthUri:
    """Test capauth URI generation."""

    def test_known_org(self):
        uri = build_capauth_uri("Chef", "smilintux")
        assert uri == "capauth:chef@smilintux.org"

    def test_skworld_org(self):
        uri = build_capauth_uri("Lumina", "skworld")
        assert uri == "capauth:lumina@skworld.io"

    def test_unknown_org_defaults_to_dot_org(self):
        uri = build_capauth_uri("Test", "myorg")
        assert uri == "capauth:test@myorg.org"

    def test_name_with_spaces(self):
        uri = build_capauth_uri("Chef Dave", "smilintux")
        assert uri == "capauth:chef-dave@smilintux.org"


class TestSaveAndLoadEntries:
    """Test persistence of registry entries."""

    def test_save_creates_file(self, tmp_path):
        entry = RegistryEntry(name="Chef", org="smilintux")
        path = save_registry_entry(entry, tmp_path)

        assert path.exists()
        assert path.name == "smilintux-chef.yml"
        assert path.read_text(encoding="utf-8").startswith("---")

    def test_save_and_load_roundtrip(self, tmp_path):
        entry = RegistryEntry(
            name="Chef",
            title="King",
            org="smilintux",
            role="Architect",
            capauth_uri="capauth:chef@smilintux.org",
            motto="stayCuriousANDkeepSmilin",
        )
        save_registry_entry(entry, tmp_path)

        loaded = load_registry_entries(tmp_path)
        assert len(loaded) == 1
        assert loaded[0].name == "Chef"
        assert loaded[0].role == "Architect"

    def test_load_filters_by_org(self, tmp_path):
        save_registry_entry(RegistryEntry(name="A", org="smilintux"), tmp_path)
        save_registry_entry(RegistryEntry(name="B", org="skworld"), tmp_path)

        smilintux = load_registry_entries(tmp_path, org="smilintux")
        assert len(smilintux) == 1
        assert smilintux[0].name == "A"

    def test_load_empty_directory(self, tmp_path):
        assert load_registry_entries(tmp_path) == []

    def test_load_nonexistent_directory(self, tmp_path):
        assert load_registry_entries(tmp_path / "nope") == []
