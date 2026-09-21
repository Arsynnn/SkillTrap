"""Конвейер сканирования: loader -> sandbox -> trace_parser -> rules -> Report.

Вынесено отдельно от `cli.py`, чтобы `eval/run_eval.py` мог прогонять фикстуры,
не импортируя интерфейс командной строки.
"""

from __future__ import annotations

import tempfile
import time
from pathlib import Path

from skilltrap import rules
from skilltrap.canaries import generate_canaries
from skilltrap.loader import load_skill
from skilltrap.models import Report
from skilltrap.sandbox.runner import SandboxConfig, SandboxError, build_image, prepare_workspace
from skilltrap.sandbox.runner import run_script as run_in_sandbox
from skilltrap.trace_parser import parse_trace_log


def scan_skill(
    path: Path,
    config: SandboxConfig | None = None,
    keep_workspace: Path | None = None,
) -> Report:
    """Просканировать скил и вернуть отчёт.

    `keep_workspace` — папка, в которой останутся копия скила, fake_home и логи strace.
    Если не задана, используется временная папка, и после разбора логов она удаляется.
    """
    config = config or SandboxConfig()
    skill = load_skill(path)
    canaries = generate_canaries()
    report = Report(skill=skill, canaries=canaries)
    started = time.monotonic()

    try:
        build_image(config.image)
    except SandboxError as error:
        # Отличаем поломку инструмента от находок: без песочницы вердикт выносить нечестно.
        report.sandbox_error = str(error)
        report.duration_s = round(time.monotonic() - started, 2)
        return report

    if keep_workspace is not None:
        _run_all(skill, canaries, keep_workspace, config, report)
    else:
        with tempfile.TemporaryDirectory(prefix="skilltrap-") as tmp:
            _run_all(skill, canaries, Path(tmp), config, report)
            # Логи лежали во временной папке — путь после выхода будет недействителен.
            for run in report.runs:
                run.trace_log = None

    report.findings = rules.evaluate(skill, report.runs, canaries)
    report.duration_s = round(time.monotonic() - started, 2)
    return report


def _run_all(skill, canaries, workspace_root: Path, config: SandboxConfig, report: Report) -> None:
    """Запустить все скрипты скила и разобрать их логи."""
    workspace = prepare_workspace(workspace_root, skill, canaries)
    for script in skill.scripts:
        run = run_in_sandbox(script, workspace, config)
        if run.trace_log is not None:
            run.events = parse_trace_log(run.trace_log)
        report.runs.append(run)
