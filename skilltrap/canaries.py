"""Приманки (canaries): фейковые секреты, которые подкладываются в песочницу.

На каждый запуск генерируются НОВЫЕ значения вида `CANARY-<uuid4>`. Уникальность важна:
если такая строка всплыла в аргументах `execve` или в исходящих данных, значит её прочитали
именно сейчас и именно из нашей приманки — совпадение случайным быть не может.

Настоящих ключей здесь нет и быть не может: в шаблоне `sandbox/fake_home/` лежат только
плейсхолдеры `{{CANARY_*}}`, которые подставляются при подготовке песочницы.
"""

from __future__ import annotations

import shutil
import uuid
from pathlib import Path
from typing import NamedTuple

from skilltrap.models import Canary, CanaryKind

CANARY_PREFIX = "CANARY-"

#: Домашняя папка пользователя внутри контейнера.
CONTAINER_HOME = "/home/skill"

#: Шаблон домашней папки на хосте.
FAKE_HOME_TEMPLATE = Path(__file__).parent / "sandbox" / "fake_home"


class CanarySpec(NamedTuple):
    """Описание одной приманки: что генерируем и куда подставляем."""

    name: str
    placeholder: str  # строка в шаблоне, например "{{CANARY_ENV_API_KEY}}"
    relative_path: str  # файл внутри fake_home, где она лежит
    kind: CanaryKind


CANARY_SPECS: tuple[CanarySpec, ...] = (
    CanarySpec("env_api_key", "{{CANARY_ENV_API_KEY}}", ".env", CanaryKind.ENV),
    CanarySpec("db_password", "{{CANARY_DB_PASSWORD}}", ".env", CanaryKind.ENV),
    CanarySpec("ssh_private_key", "{{CANARY_SSH_KEY}}", ".ssh/id_rsa", CanaryKind.SSH),
    CanarySpec("aws_secret_key", "{{CANARY_AWS_SECRET}}", ".aws/credentials", CanaryKind.AWS),
    CanarySpec(
        "agent_token", "{{CANARY_AGENT_TOKEN}}", ".config/skill/token.json", CanaryKind.TOKEN
    ),
)

#: Файлы-приманки: любое их открытие скилом — уже находка (CRITICAL).
DECOY_FILES: tuple[str, ...] = (
    ".env",
    ".ssh/id_rsa",
    ".ssh/config",
    ".aws/credentials",
    ".config/skill/token.json",
)

#: Файлы, запись в которые означает попытку закрепиться (persistence).
PERSISTENCE_FILES: tuple[str, ...] = (
    "CLAUDE.md",
    "AGENTS.md",
    ".bashrc",
    ".profile",
)


def container_path(relative_path: str) -> str:
    """Путь внутри контейнера: `.env` -> `/home/skill/.env`."""
    return f"{CONTAINER_HOME}/{relative_path}"


def decoy_paths() -> tuple[str, ...]:
    """Полные пути файлов-приманок внутри контейнера."""
    return tuple(container_path(p) for p in DECOY_FILES)


def persistence_paths() -> tuple[str, ...]:
    """Полные пути файлов, куда пытаются закрепиться."""
    return tuple(container_path(p) for p in PERSISTENCE_FILES)


def generate_canaries() -> list[Canary]:
    """Сгенерировать свежий набор приманок для одного запуска."""
    return [
        Canary(
            name=spec.name,
            value=f"{CANARY_PREFIX}{uuid.uuid4()}",
            path=Path(container_path(spec.relative_path)),
            kind=spec.kind,
        )
        for spec in CANARY_SPECS
    ]


def materialize_fake_home(
    dest: Path,
    canaries: list[Canary],
    template: Path = FAKE_HOME_TEMPLATE,
) -> Path:
    """Скопировать шаблон fake_home в `dest`, подставив значения приманок.

    Возвращает `dest`. Если в результате остался неподставленный плейсхолдер `{{CANARY_`,
    считаем это ошибкой конфигурации: приманка была бы бесполезной.
    """
    values = {spec.placeholder: _value_of(canaries, spec.name) for spec in CANARY_SPECS}

    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)

    for source in sorted(template.rglob("*")):
        if source.is_dir() or source.name == ".gitkeep":
            continue
        relative = source.relative_to(template)
        target = dest / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        text = source.read_text(encoding="utf-8")
        target.write_text(substitute(text, values), encoding="utf-8", newline="\n")

    leftovers = [
        str(p.relative_to(dest))
        for p in dest.rglob("*")
        if p.is_file() and "{{CANARY_" in p.read_text(encoding="utf-8")
    ]
    if leftovers:
        raise ValueError(f"в fake_home остались неподставленные приманки: {leftovers}")

    return dest


def substitute(text: str, values: dict[str, str]) -> str:
    """Заменить все плейсхолдеры на значения приманок."""
    for placeholder, value in values.items():
        text = text.replace(placeholder, value)
    return text


def _value_of(canaries: list[Canary], name: str) -> str:
    for canary in canaries:
        if canary.name == name:
            return canary.value
    raise KeyError(f"не сгенерирована приманка '{name}'")
