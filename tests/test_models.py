"""Тесты моделей: проверяем только вывод вердикта и сериализацию отчёта."""

from pathlib import Path

import pytest

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
    verdict_for,
)


def finding(severity: Severity) -> Finding:
    return Finding(rule_id="test", severity=severity, title="t", detail="d")


@pytest.mark.parametrize(
    ("severities", "expected"),
    [
        ([], Verdict.SAFE),
        ([Severity.INFO, Severity.LOW], Verdict.SAFE),
        ([Severity.MEDIUM], Verdict.SUSPICIOUS),
        ([Severity.LOW, Severity.HIGH], Verdict.SUSPICIOUS),
        ([Severity.LOW, Severity.CRITICAL], Verdict.MALICIOUS),
    ],
)
def test_verdict_uses_worst_severity(severities: list[Severity], expected: Verdict) -> None:
    assert verdict_for([finding(s) for s in severities]) == expected


def skill_info() -> SkillInfo:
    return SkillInfo(
        name="demo",
        description="demo skill",
        root=Path("fixtures/benign/demo"),
        skill_md=Path("fixtures/benign/demo/SKILL.md"),
    )


def test_report_exposes_verdict_in_json() -> None:
    report = Report(skill=skill_info(), findings=[finding(Severity.CRITICAL)])
    assert report.verdict == Verdict.MALICIOUS
    assert report.model_dump()["verdict"] == "MALICIOUS"


def test_trace_events_are_not_serialized() -> None:
    """События strace нужны правилам, но в JSON-отчёт их складывать нельзя — их тысячи."""
    run = ScriptRun(
        script=Path("run.py"),
        interpreter=Interpreter.PYTHON,
        events=[
            TraceEvent(
                pid=1,
                timestamp="14:23:05.123456",
                syscall="openat",
                kind=SyscallKind.OPEN,
                raw='1 14:23:05.123456 openat(AT_FDCWD, "/home/skill/.env", O_RDONLY) = 3',
            )
        ],
    )
    report = Report(skill=skill_info(), runs=[run])
    assert report.runs[0].events[0].kind is SyscallKind.OPEN
    assert "events" not in report.model_dump()["runs"][0]
