"""Модели данных SkillTrap.

Здесь только описание данных, которые ходят по конвейеру
loader -> sandbox -> trace_parser -> rules -> report.
Никакого ввода-вывода и никакой логики сканирования в этом модуле нет.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, computed_field


class Severity(StrEnum):
    """Серьёзность находки. Порядок задаётся отдельно в SEVERITY_ORDER."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        """Числовой вес: чем больше, тем серьёзнее. Нужен, чтобы брать максимум."""
        return SEVERITY_ORDER[self]


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Verdict(StrEnum):
    """Итоговый вывод по скилу."""

    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


class Interpreter(StrEnum):
    """Чем запускать скрипт внутри контейнера."""

    PYTHON = "python"
    BASH = "bash"


class SyscallKind(StrEnum):
    """Категория системного вызова — правила смотрят на неё, а не на сырое имя."""

    OPEN = "open"  # openat
    EXEC = "exec"  # execve
    CONNECT = "connect"  # connect
    UNLINK = "unlink"  # unlinkat
    RENAME = "rename"  # renameat2
    OTHER = "other"


class CanaryKind(StrEnum):
    """Тип приманки — определяет, в какой файл fake_home её кладут."""

    ENV = "env"  # .env
    SSH = "ssh"  # ~/.ssh/id_rsa
    AWS = "aws"  # ~/.aws/credentials
    TOKEN = "token"  # прочие токены


class SkillScript(BaseModel):
    """Один исполняемый файл внутри скила."""

    path: Path  # путь относительно корня скила
    interpreter: Interpreter
    hidden: bool = False  # лежит в скрытой папке (.git/ и т.п.) — признак SkillCloak

    @property
    def name(self) -> str:
        return self.path.name


class SkillInfo(BaseModel):
    """Результат работы loader: что за скил и что в нём запускать."""

    name: str
    description: str
    root: Path  # корневая папка скила на хосте
    skill_md: Path  # путь к самому SKILL.md
    scripts: list[SkillScript] = Field(default_factory=list)
    frontmatter: dict[str, Any] = Field(default_factory=dict)  # остальные поля frontmatter


class Canary(BaseModel):
    """Приманка: фейковый секрет, подложенный в fake_home перед запуском."""

    name: str  # например "aws_secret_key"
    value: str  # всегда вида CANARY-<uuid4>
    path: Path  # где лежит внутри контейнера, например /home/skill/.env
    kind: CanaryKind


class TraceEvent(BaseModel):
    """Одна разобранная строка вывода strace."""

    pid: int
    timestamp: str  # как в логе: "14:23:05.123456"
    syscall: str  # сырое имя: openat, execve, ...
    kind: SyscallKind
    args: list[str] = Field(default_factory=list)
    result: str = ""  # то, что после "=" в строке strace
    path: str | None = None  # путь из аргументов, если вызов файловый
    success: bool = True  # False, если strace вернул -1 (ENOENT, EACCES, ...)
    raw: str = ""  # исходная строка лога — она же доказательство в отчёте


class ScriptRun(BaseModel):
    """Итог одного запуска скрипта в контейнере."""

    script: Path  # относительный путь, как в SkillScript
    interpreter: Interpreter
    exit_code: int | None = None  # None, если процесс не завершился сам
    timed_out: bool = False
    stdout: str = ""
    stderr: str = ""
    trace_log: Path | None = None  # файл лога strace на хосте
    # События не попадают в JSON-отчёт: их тысячи, а в отчёте нужны только доказательства.
    events: list[TraceEvent] = Field(default_factory=list, repr=False, exclude=True)


class FsChanges(BaseModel):
    """Что изменилось в fake_home за время запуска (сравнение хешей до и после)."""

    created: list[str] = Field(default_factory=list)
    modified: list[str] = Field(default_factory=list)
    deleted: list[str] = Field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return not (self.created or self.modified or self.deleted)


class Finding(BaseModel):
    """Одна находка правила: что именно подозрительного сделал скил."""

    rule_id: str  # например "canary-read"
    severity: Severity
    title: str
    detail: str
    evidence: list[str] = Field(default_factory=list)  # строки лога strace
    script: Path | None = None  # какой скрипт это сделал


class Report(BaseModel):
    """Полный результат сканирования одного скила."""

    skill: SkillInfo
    canaries: list[Canary] = Field(default_factory=list)
    runs: list[ScriptRun] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=datetime.now)
    duration_s: float = 0.0
    sandbox_error: str | None = None  # контейнер не собрался/не запустился
    home_changes: FsChanges = Field(default_factory=lambda: FsChanges())

    @computed_field  # type: ignore[prop-decorator]
    @property
    def verdict(self) -> Verdict:
        """Вердикт выводится из самой серьёзной находки, отдельного состояния нет."""
        return verdict_for(self.findings)


def verdict_for(findings: list[Finding]) -> Verdict:
    """CRITICAL -> MALICIOUS, HIGH/MEDIUM -> SUSPICIOUS, остальное -> SAFE."""
    if not findings:
        return Verdict.SAFE
    worst = max(f.severity.rank for f in findings)
    if worst >= Severity.CRITICAL.rank:
        return Verdict.MALICIOUS
    if worst >= Severity.MEDIUM.rank:
        return Verdict.SUSPICIOUS
    return Verdict.SAFE
