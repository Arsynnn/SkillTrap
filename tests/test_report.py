"""Тесты отчёта: Markdown, JSON и вывод в терминал."""

from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console

from skilltrap.models import (
    Finding,
    Interpreter,
    Report,
    ScriptRun,
    Severity,
    SkillInfo,
    SyscallKind,
    TraceEvent,
    Verdict,
)
from skilltrap.report import render_json, render_markdown, render_terminal


def make_report(findings: list[Finding] | None = None, error: str | None = None) -> Report:
    skill = SkillInfo(
        name="demo",
        description="demo skill",
        root=Path("fixtures/benign/demo"),
        skill_md=Path("fixtures/benign/demo/SKILL.md"),
    )
    run = ScriptRun(
        script=Path("scripts/run.py"),
        interpreter=Interpreter.PYTHON,
        exit_code=0,
        events=[TraceEvent(pid=1, timestamp="00:00:00.1", syscall="openat", kind=SyscallKind.OPEN)],
    )
    return Report(skill=skill, runs=[run], findings=findings or [], sandbox_error=error)


def critical_finding() -> Finding:
    return Finding(
        rule_id="canary-file-read",
        severity=Severity.CRITICAL,
        title="Чтение файла-приманки /home/skill/.env",
        detail="Скил открыл подложенный файл с фейковым секретом.",
        evidence=['10 00:00:01 openat(AT_FDCWD, "/home/skill/.env", O_RDONLY) = 3'],
        script=Path("scripts/run.py"),
    )


def test_markdown_contains_verdict_and_evidence() -> None:
    text = render_markdown(make_report([critical_finding()]))

    assert "**Вердикт: MALICIOUS**" in text
    assert "[CRITICAL] Чтение файла-приманки" in text
    assert "/home/skill/.env" in text
    assert "`scripts/run.py`" in text  # путь всегда в posix-виде, даже на Windows


def test_markdown_for_clean_skill() -> None:
    text = render_markdown(make_report())

    assert "**Вердикт: SAFE**" in text
    assert "Находок нет." in text


def test_markdown_reports_sandbox_error() -> None:
    text = render_markdown(make_report(error="docker build упал"))

    assert "Ошибка песочницы" in text
    assert "docker build упал" in text


def test_json_has_verdict_and_no_trace_events() -> None:
    data = json.loads(render_json(make_report([critical_finding()])))

    assert data["verdict"] == Verdict.MALICIOUS.value
    assert data["findings"][0]["rule_id"] == "canary-file-read"
    # События strace в JSON не выгружаются: их тысячи, для отчёта хватает доказательств.
    assert "events" not in data["runs"][0]


def test_terminal_output_mentions_verdict() -> None:
    console = Console(record=True, width=100)

    render_terminal(make_report([critical_finding()]), console)

    output = console.export_text()
    assert "MALICIOUS" in output
    assert "CRITICAL" in output
