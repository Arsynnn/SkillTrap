"""Отчёт: вывод в терминал (rich), Markdown и JSON."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from skilltrap.models import Report, Severity, Verdict

VERDICT_COLORS: dict[Verdict, str] = {
    Verdict.SAFE: "green",
    Verdict.SUSPICIOUS: "yellow",
    Verdict.MALICIOUS: "red",
}

SEVERITY_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

VERDICT_HINTS: dict[Verdict, str] = {
    Verdict.SAFE: "Подозрительного поведения не замечено.",
    Verdict.SUSPICIOUS: "Есть подозрительные действия — стоит посмотреть код скила вручную.",
    Verdict.MALICIOUS: "Скил трогает секреты или выносит их наружу. Устанавливать не стоит.",
}


def render_terminal(report: Report, console: Console | None = None) -> None:
    """Напечатать отчёт в терминал."""
    console = console or Console()
    verdict = report.verdict
    color = VERDICT_COLORS[verdict]

    console.print(
        Panel(
            f"[{color}]{verdict.value}[/{color}] — {VERDICT_HINTS[verdict]}",
            title=f"SkillTrap: {report.skill.name}",
            subtitle=f"{len(report.runs)} скрипт(ов), {report.duration_s} с",
        )
    )

    if report.sandbox_error:
        console.print(f"[red]Песочница не запустилась:[/red] {report.sandbox_error}")
        return

    if not report.findings:
        console.print("Находок нет.")
    else:
        table = Table(title="Находки", show_lines=True)
        table.add_column("Уровень", no_wrap=True)
        table.add_column("Что произошло")
        table.add_column("Скрипт", no_wrap=True)
        for finding in report.findings:
            level_color = SEVERITY_COLORS[finding.severity]
            evidence = finding.evidence[0] if finding.evidence else ""
            table.add_row(
                f"[{level_color}]{finding.severity.value}[/{level_color}]",
                f"{finding.title}\n[dim]{evidence}[/dim]" if evidence else finding.title,
                finding.script.as_posix() if finding.script else "-",
            )
        console.print(table)

    runs = Table(title="Запуски", show_header=True)
    runs.add_column("Скрипт")
    runs.add_column("Код выхода", no_wrap=True)
    runs.add_column("Таймаут", no_wrap=True)
    runs.add_column("Событий strace", no_wrap=True)
    for run in report.runs:
        runs.add_row(
            run.script.as_posix(),
            "-" if run.exit_code is None else str(run.exit_code),
            "да" if run.timed_out else "нет",
            str(len(run.events)),
        )
    console.print(runs)


def render_markdown(report: Report) -> str:
    """Собрать отчёт в Markdown — его удобно прикладывать к PR или задаче."""
    skill = report.skill
    lines: list[str] = [
        f"# SkillTrap — отчёт: {skill.name}",
        "",
        f"**Вердикт: {report.verdict.value}** — {VERDICT_HINTS[report.verdict]}",
        "",
        f"- Скил: `{skill.root.as_posix()}`",
        f"- Описание: {skill.description}",
        f"- Скриптов запущено: {len(report.runs)}",
        f"- Приманок подложено: {len(report.canaries)}",
        f"- Время: {report.duration_s} с ({report.started_at:%Y-%m-%d %H:%M:%S})",
        "",
    ]

    if report.sandbox_error:
        lines += ["## Ошибка песочницы", "", "```", report.sandbox_error, "```", ""]
        return "\n".join(lines)

    lines += ["## Находки", ""]
    if not report.findings:
        lines += ["Находок нет.", ""]
    else:
        for finding in report.findings:
            lines.append(f"### [{finding.severity.value}] {finding.title}")
            lines.append("")
            lines.append(finding.detail)
            lines.append("")
            if finding.script:
                lines.append(f"Скрипт: `{finding.script.as_posix()}`")
                lines.append("")
            if finding.evidence:
                lines.append("Доказательства (строки strace):")
                lines.append("")
                lines.append("```")
                lines += finding.evidence
                lines.append("```")
                lines.append("")

    changes = report.home_changes
    if not changes.is_empty:
        lines += ["## Изменения в домашней папке песочницы", ""]
        for label, paths in (
            ("Создано", changes.created),
            ("Изменено", changes.modified),
            ("Удалено", changes.deleted),
        ):
            if paths:
                lines.append(f"- {label}: " + ", ".join(f"`{p}`" for p in paths))
        lines.append("")

    lines += [
        "## Запуски",
        "",
        "| Скрипт | Код выхода | Таймаут | Событий strace |",
        "|---|---|---|---|",
    ]
    for run in report.runs:
        exit_code = "-" if run.exit_code is None else run.exit_code
        lines.append(
            f"| `{run.script.as_posix()}` | {exit_code} | "
            f"{'да' if run.timed_out else 'нет'} | {len(run.events)} |"
        )
    lines.append("")
    return "\n".join(lines)


def render_json(report: Report) -> str:
    """JSON-отчёт для CI. События strace в него не попадают — только находки."""
    return report.model_dump_json(indent=2)
