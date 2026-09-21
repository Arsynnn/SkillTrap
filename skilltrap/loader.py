"""Чтение скила с диска: frontmatter SKILL.md и поиск исполняемых скриптов.

Главная особенность: скрипты ищутся и в скрытых папках (`.git/`, `.internal/`).
Именно там техника SkillCloak прячет нагрузку, которую статические сканеры не смотрят.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from skilltrap.models import Interpreter, SkillInfo, SkillScript

SKILL_FILENAME = "SKILL.md"

# Расширение -> чем запускать внутри контейнера.
INTERPRETER_BY_SUFFIX: dict[str, Interpreter] = {
    ".py": Interpreter.PYTHON,
    ".sh": Interpreter.BASH,
}

# Служебные папки, в которых искать скрипты бессмысленно: это не код скила, а мусор окружения.
# Внимание: `.git` сюда НЕ входит — это как раз вектор SkillCloak.
IGNORED_DIRS = frozenset(
    {"__pycache__", ".venv", "venv", "node_modules", ".mypy_cache", ".ruff_cache"}
)


class SkillLoadError(Exception):
    """Скил не читается: нет SKILL.md, битый frontmatter, нет обязательных полей."""


def load_skill(path: Path) -> SkillInfo:
    """Прочитать скил из папки (или по прямому пути к SKILL.md)."""
    path = Path(path)
    skill_md = path if path.is_file() else path / SKILL_FILENAME
    if not skill_md.is_file():
        raise SkillLoadError(f"не найден {SKILL_FILENAME}: {skill_md}")

    root = skill_md.parent
    frontmatter = parse_frontmatter(skill_md.read_text(encoding="utf-8"))

    name = frontmatter.pop("name", None)
    description = frontmatter.pop("description", None)
    if not isinstance(name, str) or not name.strip():
        raise SkillLoadError(f"во frontmatter {skill_md} нет обязательного поля 'name'")
    if not isinstance(description, str) or not description.strip():
        raise SkillLoadError(f"во frontmatter {skill_md} нет обязательного поля 'description'")

    return SkillInfo(
        name=name.strip(),
        description=description.strip(),
        root=root,
        skill_md=skill_md,
        scripts=find_scripts(root),
        frontmatter=frontmatter,
    )


def parse_frontmatter(text: str) -> dict[str, Any]:
    """Достать YAML-блок между первыми двумя строками `---`."""
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        raise SkillLoadError("SKILL.md должен начинаться с YAML-frontmatter (строка '---')")

    try:
        closing = next(i for i, line in enumerate(lines[1:], start=1) if line.strip() == "---")
    except StopIteration as exc:
        raise SkillLoadError("frontmatter не закрыт второй строкой '---'") from exc

    try:
        data = yaml.safe_load("\n".join(lines[1:closing])) or {}
    except yaml.YAMLError as exc:
        raise SkillLoadError(f"frontmatter не разбирается как YAML: {exc}") from exc

    if not isinstance(data, dict):
        raise SkillLoadError("frontmatter должен быть словарём ключ-значение")
    return data


def find_scripts(root: Path) -> list[SkillScript]:
    """Найти все `.py` и `.sh` внутри скила, включая скрытые папки."""
    scripts: list[SkillScript] = []
    for file in sorted(root.rglob("*")):
        if not file.is_file():
            continue
        interpreter = INTERPRETER_BY_SUFFIX.get(file.suffix)
        if interpreter is None:
            continue
        relative = file.relative_to(root)
        if any(part in IGNORED_DIRS for part in relative.parts):
            continue
        scripts.append(
            SkillScript(
                path=relative,
                interpreter=interpreter,
                hidden=is_hidden(relative),
            )
        )
    return scripts


def is_hidden(relative: Path) -> bool:
    """Путь считается скрытым, если любая его часть начинается с точки."""
    return any(part.startswith(".") for part in relative.parts)
