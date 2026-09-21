"""Тесты loader: frontmatter и поиск скриптов, в том числе в скрытых папках."""

from pathlib import Path

import pytest

from skilltrap.loader import SkillLoadError, find_scripts, load_skill, parse_frontmatter
from skilltrap.models import Interpreter

SKILL_MD = """---
name: demo
description: demo skill for tests
license: MIT
---

# Demo

Текст скила.
"""


def make_skill(root: Path, skill_md: str = SKILL_MD) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "SKILL.md").write_text(skill_md, encoding="utf-8")
    return root


def test_load_skill_reads_frontmatter(tmp_path: Path) -> None:
    root = make_skill(tmp_path / "demo")
    (root / "scripts").mkdir()
    (root / "scripts" / "run.py").write_text("print('hi')\n", encoding="utf-8")

    skill = load_skill(root)

    assert skill.name == "demo"
    assert skill.description == "demo skill for tests"
    # name и description уходят в свои поля, остальное остаётся в frontmatter.
    assert skill.frontmatter == {"license": "MIT"}
    assert [s.path for s in skill.scripts] == [Path("scripts/run.py")]
    assert skill.scripts[0].interpreter is Interpreter.PYTHON


def test_load_skill_accepts_path_to_skill_md(tmp_path: Path) -> None:
    root = make_skill(tmp_path / "demo")
    skill = load_skill(root / "SKILL.md")
    assert skill.root == root


def test_hidden_payload_is_found(tmp_path: Path) -> None:
    """Имитация SkillCloak: скрипт лежит в .git/ и должен быть найден и помечен hidden."""
    root = make_skill(tmp_path / "cloaked")
    payload_dir = root / ".git" / "hooks"
    payload_dir.mkdir(parents=True)
    (payload_dir / "payload.sh").write_text("echo hi\n", encoding="utf-8")

    scripts = find_scripts(root)

    assert [s.path for s in scripts] == [Path(".git/hooks/payload.sh")]
    assert scripts[0].hidden is True
    assert scripts[0].interpreter is Interpreter.BASH


def test_noise_directories_are_skipped(tmp_path: Path) -> None:
    root = make_skill(tmp_path / "noisy")
    for noise in ("__pycache__", ".venv"):
        (root / noise).mkdir()
        (root / noise / "junk.py").write_text("x = 1\n", encoding="utf-8")
    (root / "real.py").write_text("x = 1\n", encoding="utf-8")

    assert [s.path for s in find_scripts(root)] == [Path("real.py")]


def test_missing_skill_md(tmp_path: Path) -> None:
    with pytest.raises(SkillLoadError, match="SKILL.md"):
        load_skill(tmp_path)


@pytest.mark.parametrize(
    ("text", "match"),
    [
        ("no frontmatter at all\n", "frontmatter"),
        ("---\nname: demo\n", "не закрыт"),
        ("---\nname: demo\n---\n", "description"),
        ("---\ndescription: d\n---\n", "name"),
        ("---\n- just\n- a list\n---\n", "словарём"),
    ],
)
def test_broken_frontmatter(tmp_path: Path, text: str, match: str) -> None:
    root = make_skill(tmp_path / "broken", skill_md=text)
    with pytest.raises(SkillLoadError, match=match):
        load_skill(root)


def test_parse_frontmatter_returns_dict() -> None:
    assert parse_frontmatter("---\nname: a\nextra: 1\n---\nbody\n") == {"name": "a", "extra": 1}
