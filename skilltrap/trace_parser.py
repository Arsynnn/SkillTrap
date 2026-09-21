"""Разбор вывода strace в список `TraceEvent`.

Строки лога выглядят так:

    10    20:26:46.003202 openat(AT_FDCWD, "/home/skill/.env", O_RDONLY|O_CLOEXEC) = 3
    11    20:26:46.011243 execve("/usr/bin/echo", ["echo", "telemetry:CANARY-..."], 0x... ) = 0
    10    20:29:24.976173 connect(3, {sa_family=AF_INET, sin_port=htons(9999),
                                      sin_addr=inet_addr("127.0.0.1")}, 16) = -1 EINPROGRESS

Отдельно обрабатываются три случая, которые даёт `strace -f`:

* `... <unfinished ...>` — вызов прерван переключением на другой процесс;
* `<... openat resumed>) = 3` — его продолжение (аргументов в этой строке уже нет);
* `+++ exited with 0 +++` и `--- SIGCHLD ... ---` — не системные вызовы, пропускаем.

Парсер ничего не оценивает: решения принимает `rules.py`.
"""

from __future__ import annotations

import re
from pathlib import Path

from skilltrap.models import SyscallKind, TraceEvent

#: "pid  время  остальное"
LINE_RE = re.compile(r"^(?P<pid>\d+)\s+(?P<timestamp>[\d:.]+)\s+(?P<rest>.+)$")

#: "syscall(аргументы) = результат" — аргументы забираем жадно, чтобы поймать последний " = ".
CALL_RE = re.compile(r"^(?P<syscall>\w+)\((?P<args>.*)\)\s*=\s*(?P<result>.+)$")

#: Прерванный вызов: результата ещё нет.
UNFINISHED_RE = re.compile(r"^(?P<syscall>\w+)\((?P<args>.*?)\s*<unfinished \.\.\.>$")

#: Продолжение прерванного вызова: аргументов уже нет.
RESUMED_RE = re.compile(r"^<\.\.\.\s+(?P<syscall>\w+)\s+resumed>.*?=\s*(?P<result>.+)$")

SYSCALL_KINDS: dict[str, SyscallKind] = {
    "openat": SyscallKind.OPEN,
    "open": SyscallKind.OPEN,
    "execve": SyscallKind.EXEC,
    "connect": SyscallKind.CONNECT,
    "unlink": SyscallKind.UNLINK,
    "unlinkat": SyscallKind.UNLINK,
    "rename": SyscallKind.RENAME,
    "renameat2": SyscallKind.RENAME,
}

#: Флаги openat, означающие открытие на запись.
WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_APPEND", "O_CREAT", "O_TRUNC")

IPV4_RE = re.compile(r'sin_addr=inet_addr\("(?P<addr>[^"]+)"\)')
IPV6_RE = re.compile(r'sin6_addr=inet_pton\([^,]+,\s*"(?P<addr>[^"]+)"\)')
PORT_RE = re.compile(r"sin6?_port=htons\((?P<port>\d+)\)")
UNIX_RE = re.compile(r'sun_path="(?P<path>[^"]*)"')


def parse_trace_log(path: Path) -> list[TraceEvent]:
    """Разобрать файл лога strace."""
    return parse_trace_text(path.read_text(encoding="utf-8", errors="replace"))


def parse_trace_text(text: str) -> list[TraceEvent]:
    """Разобрать текст лога strace, склеивая прерванные вызовы с их продолжением."""
    events: list[TraceEvent] = []
    pending: dict[int, TraceEvent] = {}  # pid -> прерванный вызов, ждущий результата

    for line in text.splitlines():
        line = line.rstrip()
        match = LINE_RE.match(line)
        if not match:
            continue

        pid = int(match.group("pid"))
        timestamp = match.group("timestamp")
        rest = match.group("rest")

        if rest.startswith(("+++", "---")):
            continue

        resumed = RESUMED_RE.match(rest)
        if resumed:
            event = pending.pop(pid, None)
            if event is not None:
                # Дополняем ранее начатый вызов: аргументы уже разобраны, не хватало результата.
                event.result = resumed.group("result").strip()
                event.success = not event.result.startswith("-1")
            continue

        unfinished = UNFINISHED_RE.match(rest)
        if unfinished:
            event = _build_event(
                pid=pid,
                timestamp=timestamp,
                syscall=unfinished.group("syscall"),
                raw_args=unfinished.group("args"),
                result="",
                raw=line,
            )
            if event is not None:
                pending[pid] = event
                events.append(event)
            continue

        call = CALL_RE.match(rest)
        if call:
            event = _build_event(
                pid=pid,
                timestamp=timestamp,
                syscall=call.group("syscall"),
                raw_args=call.group("args"),
                result=call.group("result").strip(),
                raw=line,
            )
            if event is not None:
                events.append(event)

    return events


def _build_event(
    pid: int, timestamp: str, syscall: str, raw_args: str, result: str, raw: str
) -> TraceEvent | None:
    args = split_args(raw_args)
    return TraceEvent(
        pid=pid,
        timestamp=timestamp,
        syscall=syscall,
        kind=SYSCALL_KINDS.get(syscall, SyscallKind.OTHER),
        args=args,
        result=result,
        path=first_string_arg(args),
        success=not result.startswith("-1"),
        raw=raw,
    )


def split_args(raw_args: str) -> list[str]:
    """Разбить аргументы по запятым верхнего уровня.

    Наивный `split(",")` не годится: запятые встречаются внутри строк (`["echo", "x"]`)
    и внутри структур (`{sa_family=AF_INET, sin_port=...}`). Поэтому считаем скобки
    и следим за кавычками.
    """
    args: list[str] = []
    depth = 0
    in_string = False
    escaped = False
    current: list[str] = []

    for char in raw_args:
        if in_string:
            current.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue

        if char == '"':
            in_string = True
            current.append(char)
        elif char in "([{":
            depth += 1
            current.append(char)
        elif char in ")]}":
            depth -= 1
            current.append(char)
        elif char == "," and depth == 0:
            args.append("".join(current).strip())
            current = []
        else:
            current.append(char)

    tail = "".join(current).strip()
    if tail:
        args.append(tail)
    return [unquote(a) for a in args if a]


def unquote(arg: str) -> str:
    """Снять кавычки со строкового аргумента, остальные оставить как есть."""
    if len(arg) >= 2 and arg.startswith('"') and arg.endswith('"'):
        return arg[1:-1]
    return arg


def first_string_arg(args: list[str]) -> str | None:
    """Первый аргумент, похожий на путь.

    Для `openat(AT_FDCWD, "/home/skill/.env", ...)` это второй аргумент, для `open("x", ...)`
    и `execve("/usr/bin/echo", ...)` — первый. Достаточно взять первый, который выглядит
    как строка, а не как число, флаг или константа.
    """
    for arg in args:
        if arg.startswith(("AT_", "0x")) or arg.isdigit():
            continue
        if arg.startswith(("[", "{", "O_", "NULL")):
            continue
        return arg
    return None


def is_write_open(event: TraceEvent) -> bool:
    """Открывался ли файл на запись (по флагам openat/open)."""
    if event.kind is not SyscallKind.OPEN:
        return False
    return any(flag in arg for arg in event.args for flag in WRITE_FLAGS)


def connect_target(event: TraceEvent) -> str | None:
    """Адрес из `connect()`: "127.0.0.1:9999", "unix:/run/x.sock" или None."""
    if event.kind is not SyscallKind.CONNECT:
        return None

    unix = UNIX_RE.search(event.raw)
    if unix:
        return f"unix:{unix.group('path')}"

    address = IPV4_RE.search(event.raw) or IPV6_RE.search(event.raw)
    if not address:
        return None

    port = PORT_RE.search(event.raw)
    host = address.group("addr")
    return f"{host}:{port.group('port')}" if port else host
