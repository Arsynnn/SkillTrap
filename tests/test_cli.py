"""Тесты CLI: коды выхода и форматы вывода. Docker не запускается — конвейер подменён."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from skilltrap import cli
from skilltrap.models import Finding, Report, Severity, SkillInfo, Verdict

runner = CliRunner()


def fake_report(findings: list[Finding] | None = None, error: str | None = None) -> Report:
    skill = SkillInfo(
        name="demo",
        description="demo",
        root=Path("fixtures/benign/demo"),
        skill_md=Path("fixtures/benign/demo/SKILL.md"),
    )
    return Report(skill=skill, findings=findings or [], sandbox_error=error)


@pytest.fixture(autouse=True)
def stub_docker(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "docker_available", lambda: True)


def stub_scan(monkeypatch: pytest.MonkeyPatch, report: Report) -> None:
    monkeypatch.setattr(cli, "scan_skill", lambda *args, **kwargs: report)


@pytest.mark.parametrize(
    ("severity", "expected_verdict", "expected_code"),
    [
        (None, Verdict.SAFE, 0),
        (Severity.HIGH, Verdict.SUSPICIOUS, 1),
        (Severity.CRITICAL, Verdict.MALICIOUS, 2),
    ],
)
def test_exit_code_follows_verdict(
    monkeypatch: pytest.MonkeyPatch,
    severity: Severity | None,
    expected_verdict: Verdict,
    expected_code: int,
) -> None:
    """Код выхода нужен для CI: 0 — чисто, 1 — подозрительно, 2 — вредоносно."""
    findings = (
        [] if severity is None else [Finding(rule_id="r", severity=severity, title="t", detail="d")]
    )
    report = fake_report(findings)
    assert report.verdict is expected_verdict
    stub_scan(monkeypatch, report)

    result = runner.invoke(cli.app, ["scan", "fixtures/benign/demo"])

    assert result.exit_code == expected_code


def test_json_format_is_machine_readable(monkeypatch: pytest.MonkeyPatch) -> None:
    stub_scan(monkeypatch, fake_report())

    result = runner.invoke(cli.app, ["scan", "fixtures/benign/demo", "--format", "json"])

    data = json.loads(result.stdout)
    assert data["verdict"] == "SAFE"


def test_output_file_is_written(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    stub_scan(monkeypatch, fake_report())
    target = tmp_path / "report.md"

    runner.invoke(
        cli.app, ["scan", "fixtures/benign/demo", "--format", "markdown", "-o", str(target)]
    )

    assert "**Вердикт: SAFE**" in target.read_text(encoding="utf-8")


def test_sandbox_error_gives_exit_code_3(monkeypatch: pytest.MonkeyPatch) -> None:
    stub_scan(monkeypatch, fake_report(error="образ не собрался"))

    result = runner.invoke(cli.app, ["scan", "fixtures/benign/demo"])

    assert result.exit_code == 3


def test_missing_docker_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "docker_available", lambda: False)

    result = runner.invoke(cli.app, ["scan", "fixtures/benign/demo"])

    assert result.exit_code == 3
    assert "Docker" in result.stdout


def test_broken_skill_is_reported(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Скил без SKILL.md — это ошибка ввода, а не находка."""
    result = runner.invoke(cli.app, ["scan", str(tmp_path)])

    assert result.exit_code == 3
    assert "скил" in result.stdout.lower()
