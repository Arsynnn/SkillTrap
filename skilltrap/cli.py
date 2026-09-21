"""Командная строка SkillTrap: `skilltrap scan <path>` и `skilltrap eval`."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from skilltrap.loader import SkillLoadError
from skilltrap.models import Verdict
from skilltrap.report import render_json, render_markdown, render_terminal
from skilltrap.sandbox.runner import SandboxConfig, docker_available
from skilltrap.scan import scan_skill

app = typer.Typer(
    help="SkillTrap — поведенческая проверка скилов ИИ-агентов в Docker-песочнице.",
    no_args_is_help=True,
)
console = Console()

#: Код выхода по вердикту: удобно использовать в CI.
EXIT_CODES: dict[Verdict, int] = {Verdict.SAFE: 0, Verdict.SUSPICIOUS: 1, Verdict.MALICIOUS: 2}


class OutputFormat(StrEnum):
    TABLE = "table"
    MARKDOWN = "markdown"
    JSON = "json"


@app.command()
def scan(
    path: Annotated[Path, typer.Argument(help="Папка скила или путь к SKILL.md")],
    output_format: Annotated[
        OutputFormat, typer.Option("--format", "-f", help="Формат отчёта")
    ] = OutputFormat.TABLE,
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Записать отчёт в файл")
    ] = None,
    timeout: Annotated[int, typer.Option(help="Таймаут одного скрипта, секунды")] = 30,
    keep_workspace: Annotated[
        Path | None,
        typer.Option(help="Не удалять песочницу: сюда лягут копия скила, fake_home и логи strace"),
    ] = None,
) -> None:
    """Запустить скил в песочнице и показать, что он делает."""
    if not docker_available():
        console.print("[red]Docker недоступен.[/red] Запустите Docker Desktop и повторите.")
        raise typer.Exit(code=3)

    try:
        report = scan_skill(
            path,
            config=SandboxConfig(timeout_s=timeout),
            keep_workspace=keep_workspace,
        )
    except SkillLoadError as error:
        console.print(f"[red]Не удалось прочитать скил:[/red] {error}")
        raise typer.Exit(code=3) from error

    if output_format is OutputFormat.JSON:
        text = render_json(report)
    elif output_format is OutputFormat.MARKDOWN:
        text = render_markdown(report)
    else:
        text = None

    if text is None:
        render_terminal(report, console)
    else:
        print(text)

    if output is not None:
        output.write_text(
            text if text is not None else render_markdown(report), encoding="utf-8", newline="\n"
        )
        console.print(f"Отчёт записан: {output}")

    if report.sandbox_error:
        raise typer.Exit(code=3)
    raise typer.Exit(code=EXIT_CODES[report.verdict])


@app.command(name="eval")
def run_eval(
    output: Annotated[
        Path, typer.Option("--output", "-o", help="Куда записать таблицу результатов")
    ] = Path("eval/results.md"),
) -> None:
    """Прогнать все фикстуры и посчитать precision/recall."""
    # Импорт внутри команды: eval нужен не всем и тянет свои зависимости.
    from eval.run_eval import run_all

    run_all(output_path=output, console=console)


if __name__ == "__main__":
    app()
