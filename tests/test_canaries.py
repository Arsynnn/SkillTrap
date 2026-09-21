"""Тесты приманок: уникальность значений и корректная подстановка в fake_home."""

from pathlib import Path

import pytest

from skilltrap.canaries import (
    CANARY_PREFIX,
    CANARY_SPECS,
    FAKE_HOME_TEMPLATE,
    decoy_paths,
    generate_canaries,
    materialize_fake_home,
    persistence_paths,
)


def test_canaries_are_unique_per_run() -> None:
    first = {c.value for c in generate_canaries()}
    second = {c.value for c in generate_canaries()}

    assert len(first) == len(CANARY_SPECS)
    assert all(v.startswith(CANARY_PREFIX) for v in first)
    assert first.isdisjoint(second)  # новый набор на каждый запуск


def test_template_has_no_real_secrets() -> None:
    """В шаблоне репозитория допустимы только плейсхолдеры, не значения CANARY-."""
    for file in FAKE_HOME_TEMPLATE.rglob("*"):
        if file.is_file() and file.name != ".gitkeep":
            assert CANARY_PREFIX not in file.read_text(encoding="utf-8")


def test_materialize_substitutes_every_placeholder(tmp_path: Path) -> None:
    canaries = generate_canaries()
    home = materialize_fake_home(tmp_path / "home", canaries)

    env_text = (home / ".env").read_text(encoding="utf-8")
    ssh_text = (home / ".ssh" / "id_rsa").read_text(encoding="utf-8")

    assert "{{CANARY_" not in env_text
    for canary in canaries:
        if canary.name == "env_api_key":
            assert canary.value in env_text
        if canary.name == "ssh_private_key":
            assert canary.value in ssh_text

    # Файлы для проверки persistence тоже на месте.
    assert (home / "CLAUDE.md").is_file()
    assert (home / ".bashrc").is_file()


def test_materialize_replaces_existing_directory(tmp_path: Path) -> None:
    dest = tmp_path / "home"
    dest.mkdir()
    (dest / "leftover.txt").write_text("old", encoding="utf-8")

    materialize_fake_home(dest, generate_canaries())

    assert not (dest / "leftover.txt").exists()


def test_materialize_detects_unknown_placeholder(tmp_path: Path) -> None:
    template = tmp_path / "tpl"
    template.mkdir()
    (template / "extra.txt").write_text("{{CANARY_NOT_DECLARED}}", encoding="utf-8")

    with pytest.raises(ValueError, match="неподставленные приманки"):
        materialize_fake_home(tmp_path / "home", generate_canaries(), template=template)


def test_container_paths() -> None:
    assert "/home/skill/.env" in decoy_paths()
    assert "/home/skill/.ssh/id_rsa" in decoy_paths()
    assert "/home/skill/CLAUDE.md" in persistence_paths()
