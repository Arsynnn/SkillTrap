# Прогресс SkillTrap

Журнал автономной сессии: что сделано, какие решения приняты, что осталось.

## Как запустить

```bash
uv sync
uv run skilltrap scan fixtures/malicious/reads_env_canary   # появится после шага 8
uv run pytest
uv run ruff check . && uv run ruff format .
```

## Принятые решения

| Решение | Почему |
|---|---|
| Docker вызываем через `subprocess` + CLI `docker`, без Docker SDK | Ноль новых зависимостей, каждую команду видно целиком и можно скопировать в терминал — для учебного проекта прозрачнее. |
| `requires-python >= 3.11`, на машине 3.12 | `StrEnum` появился в 3.11, он используется в моделях. |
| `TraceEvent` хранится в `ScriptRun.events` с `exclude=True` | Правилам события нужны, но их тысячи на один запуск — в JSON-отчёт они не попадают, в отчёте остаются только строки-доказательства внутри находок. |
| Вердикт — вычисляемое свойство `Report.verdict`, а не поле | Нельзя рассинхронизировать вердикт и находки: он всегда выводится из самой серьёзной находки. |
| Порядок серьёзности вынесен в отдельный словарь `SEVERITY_ORDER` | `StrEnum` не сравнивается по порядку объявления, нужен явный числовой вес. |

## Сделано

### Шаг 1 — каркас проекта и модели (`feat: add project scaffolding and pydantic models`)

- `pyproject.toml`: зависимости `typer`, `rich`, `pydantic`, `pyyaml`; dev — `pytest`, `ruff`;
  точка входа `skilltrap = "skilltrap.cli:app"`; настройки `ruff` (line-length 100) и `pytest`.
- Структура папок из CLAUDE.md: `skilltrap/`, `skilltrap/sandbox/`, `fixtures/{benign,malicious}/`,
  `eval/`, `tests/data/`, `docs/`, `skill/skilltrap/`.
- `skilltrap/models.py` — все модели конвейера: `Severity`, `Verdict`, `Interpreter`, `SyscallKind`,
  `CanaryKind`, `SkillScript`, `SkillInfo`, `Canary`, `TraceEvent`, `ScriptRun`, `Finding`, `Report`
  и функция `verdict_for()`.
- `tests/test_models.py` — вердикт по худшей находке, наличие `verdict` в JSON, исключение событий из отчёта.

### Шаг 2 — loader (`feat: add skill loader with hidden script discovery`)

- `skilltrap/loader.py`: `load_skill()` (принимает папку или прямой путь к SKILL.md),
  `parse_frontmatter()` (YAML между двумя `---`, обязательные `name` и `description`),
  `find_scripts()` (`.py` -> python, `.sh` -> bash).
- Скрытые папки (`.git/`, `.internal/`) **сканируются** и помечаются флагом `hidden` — это вектор SkillCloak.
  Пропускаются только шумные служебные папки: `__pycache__`, `.venv`, `venv`, `node_modules`, кеши линтеров.
- `tests/test_loader.py`: 9 тестов, включая имитацию SkillCloak (`.git/hooks/payload.sh` находится).

## Осталось

1. `canaries.py` + `sandbox/fake_home/`.
3. `sandbox/Dockerfile` + `sandbox/runner.py`.
4. `trace_parser.py`.
5. `rules.py`.
6. `report.py` + `cli.py`.
7. Фикстуры (benign + безопасные имитации атак).
8. `eval/run_eval.py` + `eval/results.md`.
9. `static_checks.py`, `skill/skilltrap/SKILL.md`, `README.md`.

## Известные проблемы

Пока нет.
