"""Тесты парсера strace — на сохранённых настоящих логах из tests/data/, без Docker."""

from pathlib import Path

import pytest

from skilltrap.models import SyscallKind
from skilltrap.trace_parser import (
    connect_target,
    is_write_open,
    parse_trace_log,
    parse_trace_text,
    split_args,
)

DATA = Path(__file__).parent / "data"


def test_parses_openat_line() -> None:
    line = '10    20:26:46.003202 openat(AT_FDCWD, "/home/skill/.env", O_RDONLY|O_CLOEXEC) = 3'

    (event,) = parse_trace_text(line)

    assert event.pid == 10
    assert event.timestamp == "20:26:46.003202"
    assert event.kind is SyscallKind.OPEN
    assert event.path == "/home/skill/.env"
    assert event.result == "3"
    assert event.success is True
    assert is_write_open(event) is False


def test_parses_failed_call() -> None:
    line = (
        '11    20:26:46.009354 execve("/usr/local/bin/echo", ["echo", "telemetry:CANARY-abc"], '
        "0x7ffffbed50b0 /* 9 vars */) = -1 ENOENT (No such file or directory)"
    )

    (event,) = parse_trace_text(line)

    assert event.kind is SyscallKind.EXEC
    assert event.path == "/usr/local/bin/echo"
    assert event.success is False
    # Аргументы execve не разъезжаются по запятым внутри массива.
    assert event.args[1] == '["echo", "telemetry:CANARY-abc"]'


def test_parses_write_open() -> None:
    line = (
        '10    20:28:48.6 openat(AT_FDCWD, "/home/skill/CLAUDE.md", '
        "O_WRONLY|O_CREAT|O_APPEND, 0666) = 3"
    )

    (event,) = parse_trace_text(line)

    assert is_write_open(event) is True
    assert event.path == "/home/skill/CLAUDE.md"


def test_parses_connect_target() -> None:
    line = (
        "10    20:29:24.976173 connect(3, {sa_family=AF_INET, sin_port=htons(9999), "
        'sin_addr=inet_addr("127.0.0.1")}, 16) = -1 EINPROGRESS (Operation now in progress)'
    )

    (event,) = parse_trace_text(line)

    assert event.kind is SyscallKind.CONNECT
    assert connect_target(event) == "127.0.0.1:9999"


def test_unfinished_call_is_merged_with_resumed() -> None:
    text = (
        '14    20:29:25.978827 openat(AT_FDCWD, "/etc/ld.so.cache", '
        "O_RDONLY|O_CLOEXEC <unfinished ...>\n"
        '15    20:29:25.979091 execve("/usr/bin/tr", ["tr"], 0x0 /* 12 vars */) = 0\n'
        "14    20:29:25.979500 <... openat resumed>) = -1 ENOENT (No such file or directory)\n"
    )

    events = parse_trace_text(text)

    assert len(events) == 2  # строка resumed не создаёт отдельного события
    openat_event = events[0]
    assert openat_event.path == "/etc/ld.so.cache"
    assert openat_event.result.startswith("-1")
    assert openat_event.success is False


def test_signals_and_exits_are_ignored() -> None:
    text = (
        "10    20:29:24.987621 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED} ---\n"
        "17    20:29:26.058039 +++ exited with 0 +++\n"
        "мусорная строка\n"
    )

    assert parse_trace_text(text) == []


def test_split_args_respects_nesting() -> None:
    args = split_args("3, {sa_family=AF_INET, sin_port=htons(80)}, 16")

    assert args == ["3", "{sa_family=AF_INET, sin_port=htons(80)}", "16"]


@pytest.mark.parametrize(
    "log_name",
    [
        "reads_env_canary.log",
        "reads_ssh_key.log",
        "connect_attempt.log",
        "persists_to_claude_md.log",
        "hidden_payload_in_git.log",
        "markdown_toc.log",
        "csv_stats.log",
    ],
)
def test_real_logs_parse_without_errors(log_name: str) -> None:
    events = parse_trace_log(DATA / log_name)

    assert events, f"из {log_name} не разобрано ни одного события"
    # В каждом логе есть запуск интерпретатора.
    assert any(e.kind is SyscallKind.EXEC for e in events)
    # Ни одно событие не осталось без типа вызова.
    assert all(e.syscall for e in events)


def test_canary_read_visible_in_real_log() -> None:
    events = parse_trace_log(DATA / "reads_env_canary.log")

    opened = [e.path for e in events if e.kind is SyscallKind.OPEN]
    assert "/home/skill/.env" in opened

    exec_args = [e.raw for e in events if e.kind is SyscallKind.EXEC]
    assert any("CANARY-" in raw for raw in exec_args)


def test_connect_visible_in_real_log() -> None:
    events = parse_trace_log(DATA / "connect_attempt.log")

    targets = [connect_target(e) for e in events if e.kind is SyscallKind.CONNECT]
    assert "127.0.0.1:9999" in targets
