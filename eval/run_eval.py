"""Прогон всех фикстур и подсчёт precision/recall.

Запуск: `uv run skilltrap eval` или `uv run python -m eval.run_eval` из корня репозитория.

Считаем «сработало» = вердикт не SAFE. Тогда:

* TP — вредоносная фикстура помечена как SUSPICIOUS/MALICIOUS;
* FN — вредоносная фикстура получила SAFE (пропустили атаку);
* FP — «чистая» фикстура получила не SAFE (ложная тревога);
* TN — «чистая» фикстура получила SAFE.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from rich.console import Console
from rich.table import Table

from skilltrap.models import Report, Verdict
from skilltrap.scan import scan_skill

FIXTURES_DIR = Path("fixtures")

#: Ожидание по каждой фикстуре: True — должна быть поймана.
EXPECTED_MALICIOUS: dict[str, bool] = {
    "malicious/reads_env_canary": True,
    "malicious/reads_ssh_key": True,
    "malicious/connect_attempt": True,
    "malicious/persists_to_claude_md": True,
    "malicious/hidden_payload_in_git": True,
    "benign/markdown_toc": False,
    "benign/csv_stats": False,
}


@dataclass
class EvalRow:
    """Строка таблицы: что ожидали и что получили."""

    fixture: str
    expected_malicious: bool
    report: Report

    @property
    def detected(self) -> bool:
        return self.report.verdict is not Verdict.SAFE

    @property
    def outcome(self) -> str:
        if self.expected_malicious and self.detected:
            return "TP"
        if self.expected_malicious and not self.detected:
            return "FN"
        if not self.expected_malicious and self.detected:
            return "FP"
        return "TN"


@dataclass
class Metrics:
    """Итоговые числа по всем фикстурам."""

    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0

    @property
    def f1(self) -> float:
        total = self.precision + self.recall
        return 2 * self.precision * self.recall / total if total else 0.0


def evaluate_fixtures(console: Console | None = None) -> list[EvalRow]:
    """Просканировать все фикстуры по очереди."""
    console = console or Console()
    rows: list[EvalRow] = []
    for fixture, expected in EXPECTED_MALICIOUS.items():
        path = FIXTURES_DIR / fixture
        console.print(f"[dim]сканирую[/dim] {path}...")
        report = scan_skill(path)
        rows.append(EvalRow(fixture=fixture, expected_malicious=expected, report=report))
    return rows


def compute_metrics(rows: list[EvalRow]) -> Metrics:
    metrics = Metrics()
    for row in rows:
        setattr(metrics, row.outcome.lower(), getattr(metrics, row.outcome.lower()) + 1)
    return metrics


def render_markdown(rows: list[EvalRow], metrics: Metrics) -> str:
    lines = [
        "# Результаты оценки SkillTrap",
        "",
        "Таблица генерируется командой `uv run skilltrap eval`.",
        "",
        "| Фикстура | Ожидание | Вердикт | Находки | Итог |",
        "|---|---|---|---|---|",
    ]
    for row in rows:
        expected = "вредоносная" if row.expected_malicious else "чистая"
        rule_ids = sorted({f.rule_id for f in row.report.findings})
        findings = ", ".join(f"`{r}`" for r in rule_ids) if rule_ids else "—"
        lines.append(
            f"| `{row.fixture}` | {expected} | **{row.report.verdict.value}** | {findings} "
            f"| {row.outcome} |"
        )

    lines += [
        "",
        "## Метрики",
        "",
        f"- TP: {metrics.tp}, FP: {metrics.fp}, FN: {metrics.fn}, TN: {metrics.tn}",
        f"- Precision: **{metrics.precision:.2f}**",
        f"- Recall: **{metrics.recall:.2f}**",
        f"- F1: **{metrics.f1:.2f}**",
        "",
        "Детектирование считается сработавшим, если вердикт не SAFE.",
        "",
    ]
    return "\n".join(lines)


def run_all(output_path: Path = Path("eval/results.md"), console: Console | None = None) -> Metrics:
    """Прогнать фикстуры, напечатать таблицу и записать results.md."""
    console = console or Console()
    rows = evaluate_fixtures(console)
    metrics = compute_metrics(rows)

    table = Table(title="Оценка на фикстурах")
    table.add_column("Фикстура")
    table.add_column("Ожидание")
    table.add_column("Вердикт")
    table.add_column("Итог")
    for row in rows:
        table.add_row(
            row.fixture,
            "вредоносная" if row.expected_malicious else "чистая",
            row.report.verdict.value,
            row.outcome,
        )
    console.print(table)
    console.print(
        f"precision={metrics.precision:.2f} recall={metrics.recall:.2f} f1={metrics.f1:.2f}"
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_markdown(rows, metrics), encoding="utf-8", newline="\n")
    console.print(f"Таблица записана: {output_path}")
    return metrics


if __name__ == "__main__":
    run_all()
