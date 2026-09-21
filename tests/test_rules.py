"""Тесты правил — на настоящих логах strace из tests/data/, без Docker."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from skilltrap import rules
from skilltrap.models import (
    Canary,
    CanaryKind,
    Interpreter,
    ScriptRun,
    Severity,
    SkillInfo,
    SkillScript,
    Verdict,
    verdict_for,
)
from skilltrap.trace_parser import parse_trace_log

DATA = Path(__file__).parent / "data"
CANARY_RE = re.compile(r"CANARY-[0-9a-f-]{36}")


def load_run(log_name: str) -> ScriptRun:
    """Собрать ScriptRun из сохранённого лога."""
    log = DATA / log_name
    return ScriptRun(
        script=Path(f"scripts/{log.stem}.py"),
        interpreter=Interpreter.PYTHON,
        exit_code=0,
        trace_log=log,
        events=parse_trace_log(log),
    )


def canaries_from_log(log_name: str) -> list[Canary]:
    """Вытащить значения приманок из самого лога — они уникальны для того запуска."""
    text = (DATA / log_name).read_text(encoding="utf-8", errors="replace")
    return [
        Canary(name=f"canary_{i}", value=value, path=Path("/home/skill/.env"), kind=CanaryKind.ENV)
        for i, value in enumerate(sorted(set(CANARY_RE.findall(text))))
    ]


def empty_skill(scripts: list[SkillScript] | None = None) -> SkillInfo:
    return SkillInfo(
        name="test",
        description="test",
        root=Path("."),
        skill_md=Path("SKILL.md"),
        scripts=scripts or [],
    )


def rule_ids(findings: list) -> set[str]:
    return {f.rule_id for f in findings}


def test_reads_env_canary_is_critical() -> None:
    run = load_run("reads_env_canary.log")
    findings = rules.evaluate(empty_skill(), [run], canaries_from_log("reads_env_canary.log"))

    assert "canary-file-read" in rule_ids(findings)
    assert "canary-value-leak" in rule_ids(findings)
    assert verdict_for(findings) is Verdict.MALICIOUS

    reads = [f for f in findings if f.rule_id == "canary-file-read"]
    # Фикстура трогает три приманки: .env, .aws/credentials и .ssh/id_rsa.
    assert any("/home/skill/.env" in f.title for f in reads)
    assert all(f.severity is Severity.CRITICAL for f in reads)
    assert all(f.evidence for f in reads), "находка должна приносить строку лога как доказательство"


def test_reads_ssh_key_detects_decoys_and_tmp_copy() -> None:
    run = load_run("reads_ssh_key.log")
    findings = rules.evaluate(empty_skill(), [run], [])

    read_titles = " ".join(f.title for f in findings if f.rule_id == "canary-file-read")
    assert "/home/skill/.ssh/id_rsa" in read_titles
    # Копия ключа в /tmp — запись вне рабочей папки.
    assert any("/tmp/backup_key" in f.title for f in findings)
    assert verdict_for(findings) is Verdict.MALICIOUS


def test_connect_attempt_is_high() -> None:
    run = load_run("connect_attempt.log")
    findings = rules.evaluate(empty_skill(), [run], [])

    connect = next(f for f in findings if f.rule_id == "network-connect")
    assert "127.0.0.1:9999" in connect.title
    assert connect.severity is Severity.HIGH

    curl = next(f for f in findings if f.rule_id == "suspicious-exec")
    assert "curl" in curl.title
    assert verdict_for(findings) is Verdict.SUSPICIOUS


def test_persistence_is_detected() -> None:
    run = load_run("persists_to_claude_md.log")
    findings = rules.evaluate(empty_skill(), [run], [])

    touched = {f.title for f in findings if f.rule_id == "persistence-write"}
    assert any("CLAUDE.md" in t for t in touched)
    assert any("AGENTS.md" in t for t in touched)
    assert any(".bashrc" in t for t in touched)


def test_hidden_payload_reads_canaries() -> None:
    """Скрытая нагрузка ловится по поведению; сам факт скрытой папки проверяет static_checks."""
    run = load_run("hidden_payload_in_git.log")
    skill = empty_skill(
        [SkillScript(path=Path(".cache/pip/_helper.sh"), interpreter=Interpreter.BASH, hidden=True)]
    )
    findings = rules.evaluate(skill, [run], [])

    assert "canary-file-read" in rule_ids(findings)
    assert verdict_for(findings) is Verdict.MALICIOUS


@pytest.mark.parametrize("log_name", ["markdown_toc.log", "csv_stats.log"])
def test_benign_skills_produce_no_findings(log_name: str) -> None:
    """Главная защита от ложных срабатываний: чистые скилы должны давать SAFE."""
    run = load_run(log_name)
    findings = rules.evaluate(empty_skill(), [run], canaries_from_log(log_name))

    assert findings == [], f"ложные срабатывания на {log_name}: {[f.title for f in findings]}"
    assert verdict_for(findings) is Verdict.SAFE


def test_timeout_produces_finding() -> None:
    run = ScriptRun(script=Path("a.py"), interpreter=Interpreter.PYTHON, timed_out=True)
    findings = rules.evaluate(empty_skill(), [run], [])

    assert rule_ids(findings) == {"script-timeout"}
    assert findings[0].severity is Severity.MEDIUM


def test_findings_are_sorted_by_severity() -> None:
    run = load_run("reads_env_canary.log")
    findings = rules.evaluate(empty_skill(), [run], canaries_from_log("reads_env_canary.log"))

    ranks = [f.severity.rank for f in findings]
    assert ranks == sorted(ranks, reverse=True)
