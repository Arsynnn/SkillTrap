"""Лёгкие статические проверки содержимого скила.

Это не главный механизм SkillTrap (главный — наблюдение за поведением в песочнице), а дешёвый
бонус: он ловит то, что видно и без запуска. Поэтому уровень находок здесь LOW/INFO.

Проверяем три вещи:

1. невидимые символы Unicode — ими прячут инструкции в тексте SKILL.md, который читает агент;
2. длинные base64-подобные блобы — типичная упаковка спрятанной нагрузки;
3. исполняемые файлы в скрытых папках — подсказка на технику SkillCloak.
"""

from __future__ import annotations

import re
from pathlib import Path

from skilltrap.models import Finding, Severity, SkillInfo

#: Невидимые и управляющие символы: zero-width, bidi-переключатели, неразрывные пробелы.
INVISIBLE_CHARS: dict[str, str] = {
    "​": "ZERO WIDTH SPACE",
    "‌": "ZERO WIDTH NON-JOINER",
    "‍": "ZERO WIDTH JOINER",
    "⁠": "WORD JOINER",
    "﻿": "ZERO WIDTH NO-BREAK SPACE",
    "‪": "LEFT-TO-RIGHT EMBEDDING",
    "‫": "RIGHT-TO-LEFT EMBEDDING",
    "‭": "LEFT-TO-RIGHT OVERRIDE",
    "‮": "RIGHT-TO-LEFT OVERRIDE",
    "⁦": "LEFT-TO-RIGHT ISOLATE",
    "⁧": "RIGHT-TO-LEFT ISOLATE",
    "­": "SOFT HYPHEN",
}

#: Теговые символы Unicode (U+E0000–U+E007F) — ими кодируют скрытый текст внутри обычного.
TAG_CHARS_RE = re.compile(r"[\U000e0000-\U000e007f]")

#: Base64-подобный блоб: длинная строка без пробелов из алфавита base64.
BASE64_RE = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")

#: Расширения, которые считаем исполняемыми при поиске в скрытых папках.
EXECUTABLE_SUFFIXES = frozenset({".py", ".sh", ".bash", ".js", ".rb", ".pl", ".bin", ".exe", ""})

#: Файлы крупнее не читаем: статическая проверка не должна тормозить сканирование.
MAX_FILE_SIZE = 2_000_000

#: Папки, которые не относятся к коду скила.
IGNORED_DIRS = frozenset({"__pycache__", ".venv", "venv", "node_modules", ".mypy_cache"})


def run_static_checks(skill: SkillInfo) -> list[Finding]:
    """Прогнать все статические проверки по файлам скила."""
    findings: list[Finding] = []
    for file in sorted(skill.root.rglob("*")):
        if not file.is_file() or _is_ignored(file, skill.root):
            continue
        findings += hidden_executable(file, skill.root)
        if file.stat().st_size > MAX_FILE_SIZE:
            continue
        text = _read_text(file)
        if text is None:
            continue
        findings += invisible_unicode(text, file, skill.root)
        findings += base64_blob(text, file, skill.root)
    return findings


def invisible_unicode(text: str, file: Path, root: Path) -> list[Finding]:
    """LOW: невидимые символы в тексте — так прячут инструкции от человека, но не от агента."""
    found = {name for char, name in INVISIBLE_CHARS.items() if char in text}
    if TAG_CHARS_RE.search(text):
        found.add("UNICODE TAG CHARACTERS (U+E0000..U+E007F)")
    if not found:
        return []

    relative = file.relative_to(root)
    return [
        Finding(
            rule_id="invisible-unicode",
            severity=Severity.LOW,
            title=f"Невидимые символы Unicode в {relative.as_posix()}",
            detail=(
                "Файл содержит символы, которых не видно при чтении: "
                + ", ".join(sorted(found))
                + ". В тексте скила ими прячут инструкции для агента."
            ),
            evidence=[],
            script=relative,
        )
    ]


def base64_blob(text: str, file: Path, root: Path) -> list[Finding]:
    """LOW: длинный base64-блоб — частый способ спрятать нагрузку от беглого взгляда."""
    match = BASE64_RE.search(text)
    if not match:
        return []

    relative = file.relative_to(root)
    blob = match.group(0)
    return [
        Finding(
            rule_id="base64-blob",
            severity=Severity.LOW,
            title=f"Длинная base64-строка в {relative.as_posix()}",
            detail=(
                f"Найден блок из {len(blob)} символов base64. Так упаковывают спрятанный код "
                "или данные — стоит посмотреть, что внутри."
            ),
            evidence=[blob[:120] + "..."],
            script=relative,
        )
    ]


def hidden_executable(file: Path, root: Path) -> list[Finding]:
    """INFO: исполняемый файл в скрытой папке — подсказка на технику SkillCloak."""
    relative = file.relative_to(root)
    in_hidden_dir = any(part.startswith(".") for part in relative.parts[:-1])
    if not in_hidden_dir or file.suffix.lower() not in EXECUTABLE_SUFFIXES:
        return []

    return [
        Finding(
            rule_id="hidden-executable",
            severity=Severity.INFO,
            title=f"Исполняемый файл в скрытой папке: {relative.as_posix()}",
            detail=(
                "Статические сканеры часто не смотрят в папки, начинающиеся с точки "
                "(например `.git/`). Именно этим пользуется техника SkillCloak: "
                "нагрузка лежит там и распаковывается только при запуске."
            ),
            evidence=[],
            script=relative,
        )
    ]


def _is_ignored(file: Path, root: Path) -> bool:
    return any(part in IGNORED_DIRS for part in file.relative_to(root).parts)


def _read_text(file: Path) -> str | None:
    """Прочитать файл как текст; двоичные файлы пропускаем."""
    try:
        return file.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return None
