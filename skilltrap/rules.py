"""Правила: события strace -> находки с уровнем серьёзности.

Главный принцип из CLAUDE.md: реагируем на **пути приманок и конкретные действия**, а не на
любой `openat`. Интерпретатор Python при старте открывает сотни системных файлов, и если
срабатывать на каждый, отчёт превратится в шум.

Калибровка по «чистым» фикстурам:

* `bash` штатно пытается подключиться к unix-сокету `/var/run/nscd/socket` — это не сеть,
  такие `connect` игнорируем и смотрим только на AF_INET/AF_INET6;
* `bash` открывает `/dev/tty` на запись — записи в `/dev`, `/proc`, `/sys` не считаем;
* сам интерпретатор (`bash /skill/scripts/x.sh`) не должен попадать в «подозрительные запуски»,
  поэтому оболочка считается подозрительной только с флагом `-c`.
"""

from __future__ import annotations

from pathlib import Path, PurePosixPath

from skilltrap.canaries import CANARY_PREFIX, container_path, decoy_paths, persistence_paths
from skilltrap.models import (
    Canary,
    Finding,
    FsChanges,
    ScriptRun,
    Severity,
    SkillInfo,
    SyscallKind,
)
from skilltrap.trace_parser import connect_target, is_write_open

#: Рабочая папка скила внутри контейнера — запись сюда нормальна.
WORKDIR = "/skill"

#: Записи в эти псевдофайловые системы не интересны.
IGNORED_WRITE_PREFIXES = ("/dev/", "/proc/", "/sys/", "/run/")

#: Программы, запуск которых из скила почти всегда означает утечку или закачку.
SUSPICIOUS_BINARIES = frozenset(
    {"curl", "wget", "nc", "ncat", "netcat", "socat", "ssh", "scp", "sftp", "telnet", "ftp"}
)

#: Оболочки и интерпретаторы: подозрительны только с `-c` (код прямо в аргументах).
SHELL_BINARIES = frozenset({"sh", "bash", "zsh", "dash", "python", "python3", "perl", "ruby"})

#: Сколько строк лога прикладываем к находке как доказательство.
MAX_EVIDENCE = 3
EVIDENCE_WIDTH = 240


def evaluate(
    skill: SkillInfo,
    runs: list[ScriptRun],
    canaries: list[Canary],
    changes: FsChanges | None = None,
) -> list[Finding]:
    """Применить все правила и вернуть находки, отсортированные по серьёзности."""
    findings: list[Finding] = []
    for run in runs:
        findings += canary_file_read(run)
        findings += canary_value_leak(run, canaries)
        findings += network_connect(run)
        findings += suspicious_exec(run)
        findings += persistence_write(run)
        findings += write_outside_workdir(run)
        findings += file_deleted(run)
        findings += timed_out(run)
    if changes is not None:
        findings += home_changes(changes, findings)
    return sorted(findings, key=lambda f: (-f.severity.rank, f.rule_id, str(f.script)))


def canary_file_read(run: ScriptRun) -> list[Finding]:
    """CRITICAL: скил открыл файл-приманку."""
    decoys = set(decoy_paths())
    by_path: dict[str, list[str]] = {}
    for event in run.events:
        if event.kind is SyscallKind.OPEN and event.success and event.path in decoys:
            by_path.setdefault(event.path, []).append(event.raw)

    return [
        _finding(
            rule_id="canary-file-read",
            severity=Severity.CRITICAL,
            title=f"Чтение файла-приманки {path}",
            detail=(
                "Скил открыл подложенный файл с фейковым секретом. Обычному скилу содержимое "
                "чужих ключей и переменных окружения не нужно."
            ),
            evidence=lines,
            script=run.script,
        )
        for path, lines in sorted(by_path.items())
    ]


def canary_value_leak(run: ScriptRun, canaries: list[Canary]) -> list[Finding]:
    """CRITICAL: значение приманки всплыло в аргументах другого вызова.

    Значения уникальны для запуска, поэтому совпадение не может быть случайным:
    секрет действительно прочитали и передали дальше.
    """
    findings: list[Finding] = []
    for canary in canaries:
        lines = [
            event.raw
            for event in run.events
            if canary.value in event.raw and event.kind is not SyscallKind.OPEN
        ]
        if lines:
            findings.append(
                _finding(
                    rule_id="canary-value-leak",
                    severity=Severity.CRITICAL,
                    title=f"Значение приманки '{canary.name}' передано дальше",
                    detail=(
                        f"Уникальное значение {CANARY_PREFIX}... из {canary.path} попало в "
                        "аргументы системного вызова — это имитация утечки секрета."
                    ),
                    evidence=lines,
                    script=run.script,
                )
            )
    return findings


def network_connect(run: ScriptRun) -> list[Finding]:
    """HIGH: попытка сетевого соединения (у контейнера сети нет, важна сама попытка)."""
    by_target: dict[str, list[str]] = {}
    for event in run.events:
        target = connect_target(event)
        # unix-сокеты не сеть: bash сам ходит в /var/run/nscd/socket при резолве имён.
        if target and not target.startswith("unix:"):
            by_target.setdefault(target, []).append(event.raw)

    return [
        _finding(
            rule_id="network-connect",
            severity=Severity.HIGH,
            title=f"Попытка сетевого соединения с {target}",
            detail=(
                "Скил вызвал connect(). В песочнице сети нет, поэтому соединение не состоялось, "
                "но на машине пользователя оно бы состоялось."
            ),
            evidence=lines,
            script=run.script,
        )
        for target, lines in sorted(by_target.items())
    ]


def suspicious_exec(run: ScriptRun) -> list[Finding]:
    """HIGH: запуск сетевых утилит или оболочки с кодом в аргументах (`-c`)."""
    by_binary: dict[str, list[str]] = {}
    for event in run.events:
        if event.kind is not SyscallKind.EXEC or not event.path:
            continue
        binary = PurePosixPath(event.path).name
        argv = event.args[1] if len(event.args) > 1 else ""

        if binary in SUSPICIOUS_BINARIES:
            by_binary.setdefault(binary, []).append(event.raw)
        elif binary in SHELL_BINARIES and '"-c"' in argv:
            by_binary.setdefault(f"{binary} -c", []).append(event.raw)

    return [
        _finding(
            rule_id="suspicious-exec",
            severity=Severity.HIGH,
            title=f"Запуск подозрительной программы: {binary}",
            detail=(
                "Такие программы нужны, чтобы выгрузить данные наружу или скачать и выполнить "
                "чужой код. Обратите внимание: вызов попал в лог, даже если программы нет в образе."
            ),
            evidence=lines,
            script=run.script,
        )
        for binary, lines in sorted(by_binary.items())
    ]


def persistence_write(run: ScriptRun) -> list[Finding]:
    """HIGH: изменение файлов памяти агента и стартовых скриптов оболочки."""
    targets = set(persistence_paths())
    by_path: dict[str, list[str]] = {}
    for event in run.events:
        touched = event.path in targets and (
            is_write_open(event) or event.kind in (SyscallKind.RENAME, SyscallKind.UNLINK)
        )
        if touched:
            by_path.setdefault(str(event.path), []).append(event.raw)

    return [
        _finding(
            rule_id="persistence-write",
            severity=Severity.HIGH,
            title=f"Изменение файла закрепления {path}",
            detail=(
                "Скил пишет в файл, который агент или оболочка читают при каждом запуске "
                "(CLAUDE.md, AGENTS.md, .bashrc, .profile). Так скил продолжает влиять на "
                "агента даже после удаления."
            ),
            evidence=lines,
            script=run.script,
        )
        for path, lines in sorted(by_path.items())
    ]


def write_outside_workdir(run: ScriptRun) -> list[Finding]:
    """MEDIUM: запись в файлы вне рабочей папки скила."""
    persistence = set(persistence_paths())
    by_path: dict[str, list[str]] = {}
    for event in run.events:
        path = event.path
        if not is_write_open(event) or not path or not path.startswith("/"):
            continue
        if path.startswith(WORKDIR) or path in persistence:
            continue  # своя папка — норма, файлы закрепления уже отмечены как HIGH
        if path.startswith(IGNORED_WRITE_PREFIXES):
            continue
        by_path.setdefault(path, []).append(event.raw)

    return [
        _finding(
            rule_id="write-outside-workdir",
            severity=Severity.MEDIUM,
            title=f"Запись вне рабочей папки: {path}",
            detail="Скил создал или изменил файл за пределами своей директории.",
            evidence=lines,
            script=run.script,
        )
        for path, lines in sorted(by_path.items())
    ]


def file_deleted(run: ScriptRun) -> list[Finding]:
    """MEDIUM: удаление или переименование файлов."""
    by_path: dict[str, list[str]] = {}
    for event in run.events:
        if event.kind not in (SyscallKind.UNLINK, SyscallKind.RENAME) or not event.success:
            continue
        path = event.path or "?"
        if path.startswith(IGNORED_WRITE_PREFIXES):
            continue
        by_path.setdefault(path, []).append(event.raw)

    return [
        _finding(
            rule_id="file-deleted",
            severity=Severity.MEDIUM,
            title=f"Удаление или переименование файла: {path}",
            detail="Скил удалил или переименовал файл — так заметают следы или ломают проект.",
            evidence=lines,
            script=run.script,
        )
        for path, lines in sorted(by_path.items())
    ]


def timed_out(run: ScriptRun) -> list[Finding]:
    """MEDIUM: скрипт не уложился в таймаут — возможно, ждал сети или крутил цикл."""
    if not run.timed_out:
        return []
    return [
        _finding(
            rule_id="script-timeout",
            severity=Severity.MEDIUM,
            title=f"Скрипт {run.script} не завершился за отведённое время",
            detail=(
                "Контейнер убит по таймауту. Часть действий скрипта могла не попасть в лог, "
                "поэтому отчёт может быть неполным."
            ),
            evidence=[],
            script=run.script,
        )
    ]


def home_changes(changes: FsChanges, already_found: list[Finding]) -> list[Finding]:
    """MEDIUM: файл домашней папки изменился, но по логу strace этого не видно.

    Такие находки — «подстраховка»: сравнение хешей не зависит от того, какие вызовы
    мы просили strace записывать. Всё, что уже названо другими правилами, не повторяем.
    """
    reported = " ".join(finding.title for finding in already_found)
    actions = (
        ("home-file-created", "создан", changes.created),
        ("home-file-modified", "изменён", changes.modified),
        ("home-file-deleted", "удалён", changes.deleted),
    )

    findings: list[Finding] = []
    for rule_id, verb, paths in actions:
        for relative in paths:
            full_path = container_path(relative)
            if full_path in reported:
                continue  # это же изменение уже описано по логу strace
            findings.append(
                _finding(
                    rule_id=rule_id,
                    severity=Severity.MEDIUM,
                    title=f"Файл домашней папки {verb}: {full_path}",
                    detail=(
                        "Сравнение хешей fake_home до и после запуска показало изменение, "
                        "которого нет в логе strace."
                    ),
                    evidence=[],
                    script=None,
                )
            )
    return findings


def _finding(
    rule_id: str,
    severity: Severity,
    title: str,
    detail: str,
    evidence: list[str],
    script: Path | None,
) -> Finding:
    """Собрать находку, оставив не больше MAX_EVIDENCE укороченных строк лога."""
    return Finding(
        rule_id=rule_id,
        severity=severity,
        title=title,
        detail=detail,
        evidence=[line[:EVIDENCE_WIDTH] for line in evidence[:MAX_EVIDENCE]],
        script=script,
    )
