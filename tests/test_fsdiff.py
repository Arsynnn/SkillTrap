"""Тесты сравнения снимков fake_home."""

from __future__ import annotations

from pathlib import Path

from skilltrap import rules
from skilltrap.fsdiff import diff, snapshot
from skilltrap.models import Finding, FsChanges, Severity


def make_home(root: Path) -> Path:
    root.mkdir(parents=True)
    (root / "CLAUDE.md").write_text("original\n", encoding="utf-8")
    (root / ".ssh").mkdir()
    (root / ".ssh" / "id_rsa").write_text("key\n", encoding="utf-8")
    return root


def test_snapshot_lists_files_with_relative_posix_paths(tmp_path: Path) -> None:
    home = make_home(tmp_path / "home")

    files = snapshot(home)

    assert set(files) == {"CLAUDE.md", ".ssh/id_rsa"}
    assert all(len(h) == 64 for h in files.values())  # sha256 в hex


def test_diff_detects_all_three_kinds_of_change(tmp_path: Path) -> None:
    home = make_home(tmp_path / "home")
    before = snapshot(home)

    (home / "CLAUDE.md").write_text("original\ninjected instruction\n", encoding="utf-8")
    (home / "new.txt").write_text("new\n", encoding="utf-8")
    (home / ".ssh" / "id_rsa").unlink()

    changes = diff(before, snapshot(home))

    assert changes.modified == ["CLAUDE.md"]
    assert changes.created == ["new.txt"]
    assert changes.deleted == [".ssh/id_rsa"]
    assert changes.is_empty is False


def test_no_changes_gives_empty_diff(tmp_path: Path) -> None:
    home = make_home(tmp_path / "home")
    before = snapshot(home)

    assert diff(before, snapshot(home)).is_empty is True


def test_rule_reports_changes_missing_from_strace() -> None:
    changes = FsChanges(created=["evil.txt"], modified=["CLAUDE.md"])

    findings = rules.home_changes(changes, already_found=[])

    ids = {f.rule_id for f in findings}
    assert ids == {"home-file-created", "home-file-modified"}
    assert all(f.severity is Severity.MEDIUM for f in findings)
    assert any("/home/skill/evil.txt" in f.title for f in findings)


def test_rule_does_not_duplicate_strace_findings() -> None:
    """Если изменение уже описано по логу strace, второй раз его не показываем."""
    changes = FsChanges(modified=["CLAUDE.md"])
    already = [
        Finding(
            rule_id="persistence-write",
            severity=Severity.HIGH,
            title="Изменение файла закрепления /home/skill/CLAUDE.md",
            detail="",
        )
    ]

    assert rules.home_changes(changes, already_found=already) == []
