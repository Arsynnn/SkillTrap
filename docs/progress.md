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

### Шаг 3 — приманки и fake_home (`feat: add canary generation and fake home template`)

- `skilltrap/canaries.py`: `generate_canaries()` (новые `CANARY-<uuid4>` на каждый запуск),
  `materialize_fake_home()` (копирует шаблон и подставляет значения), списки `decoy_paths()` и
  `persistence_paths()` — их дальше используют правила.
- `skilltrap/sandbox/fake_home/`: `.env`, `.ssh/id_rsa`, `.ssh/config`, `.aws/credentials`,
  `.config/skill/token.json`, `CLAUDE.md`, `AGENTS.md`, `.bashrc`, `.profile`.
  В репозитории лежат **только плейсхолдеры** `{{CANARY_*}}`; тест это проверяет.
- `.gitignore`: добавлено исключение для `skilltrap/sandbox/fake_home/**` и `fixtures/**`,
  иначе шаблонный `.env` не попадал в репозиторий.
- `.gitattributes`: `* text=auto eol=lf` — на Windows иначе `.sh` уезжает в CRLF и bash в контейнере падает.
- `tests/test_canaries.py`: 6 тестов (уникальность, отсутствие `CANARY-` в шаблоне, подстановка, ошибки).

### Шаг 4 — Docker-песочница и runner (`feat: add docker sandbox runner with strace`)

- `skilltrap/sandbox/Dockerfile`: `python:3.12-slim` + `strace`, пользователь `skill` (uid 1000),
  точки монтирования `/skill` и `/trace`.
- `skilltrap/sandbox/runner.py`: `build_image()`, `prepare_workspace()`, `run_script()`.
  Флаги запуска: `--network none --user 1000:1000 --memory=256m --cpus=1.0 --pids-limit=128
  --cap-drop ALL --cap-add SYS_PTRACE --security-opt no-new-privileges`, плюс `timeout --signal=KILL 30`
  внутри контейнера и таймаут subprocess снаружи.
- Скил копируется во временный workspace и монтируется уже копия — оригинал на хосте не изменяется.
- **strace заработал с первой попытки**, `--cap-add SYS_PTRACE` оставлен для надёжности.
- Ловушка Windows: `subprocess.run(text=True)` падал с `UnicodeDecodeError` на выводе контейнера —
  теперь явно `encoding="utf-8", errors="replace"`.
- `tests/test_runner.py`: 3 теста без Docker (флаги команды, workspace) + 1 интеграционный
  с маркером `docker` (пропускается, если демона нет).

### Шаг 5 — фикстуры (`test: add benign and malicious skill fixtures`)

Сделаны раньше плана, потому что на них отлаживалась песочница и с них сняты эталонные логи strace.

- `fixtures/malicious/`: `reads_env_canary` (читает `~/.env`, значение уходит в аргументы `echo`),
  `reads_ssh_key` (читает `~/.ssh/id_rsa` и `config`, копирует в `/tmp`), `connect_attempt`
  (`connect()` на 127.0.0.1 + запуск `curl`), `persists_to_claude_md` (дописывает `CLAUDE.md`,
  `AGENTS.md`, `.bashrc`), `hidden_payload_in_git` (нагрузка в скрытой `.cache/pip/_helper.sh`).
- `fixtures/benign/`: `markdown_toc` (python), `csv_stats` (bash) — ожидаемый вердикт SAFE.
- Все имитации соответствуют правилам безопасности: только приманки, только localhost,
  запись только внутри песочницы, никаких загрузок из сети.
- Оговорка: настоящий SkillCloak прячет нагрузку в `.git/`, но такую папку нельзя хранить
  внутри git-репозитория, поэтому в фикстуре используется скрытая `.cache/`.
- `tests/data/*.log` — настоящие логи strace с этих прогонов, на них тестируется парсер без Docker.

### Шаг 6 — парсер strace (`feat: add strace log parser`)

- `skilltrap/trace_parser.py`: `parse_trace_log()` / `parse_trace_text()` -> `list[TraceEvent]`.
- Обрабатываются все реальные формы строк: обычный вызов, `<unfinished ...>` + `<... resumed>`
  (склеиваются по pid), сигналы `--- SIGCHLD ---` и `+++ exited +++` (пропускаются).
- `split_args()` считает скобки и кавычки: наивный `split(",")` ломается на `["echo", "x"]`
  и на структурах `{sa_family=AF_INET, sin_port=...}`.
- Вспомогательные функции для правил: `is_write_open()` (флаги `O_WRONLY|O_CREAT|O_APPEND`)
  и `connect_target()` (`"127.0.0.1:9999"` или `unix:/path`).
- `tests/test_trace_parser.py`: 16 тестов, из них 7 — прогон настоящих логов всех фикстур.
  Docker для тестов парсера не нужен.

### Шаг 7 — правила (`feat: add detection rules`)

Восемь правил в `skilltrap/rules.py`:

| rule_id | Уровень | Когда срабатывает |
|---|---|---|
| `canary-file-read` | CRITICAL | открыт файл-приманка (`.env`, `.ssh/id_rsa`, `.aws/credentials`, токен) |
| `canary-value-leak` | CRITICAL | уникальное значение `CANARY-...` попало в аргументы другого вызова |
| `network-connect` | HIGH | `connect()` по AF_INET/AF_INET6 |
| `suspicious-exec` | HIGH | запуск `curl`, `wget`, `nc`, `ssh`… или оболочки с `-c` |
| `persistence-write` | HIGH | запись в `CLAUDE.md`, `AGENTS.md`, `.bashrc`, `.profile` |
| `write-outside-workdir` | MEDIUM | запись за пределами `/skill` |
| `file-deleted` | MEDIUM | удаление или переименование файла |
| `script-timeout` | MEDIUM | скрипт убит по таймауту (лог может быть неполным) |
| `hidden-script` | LOW | исполняемый файл в скрытой папке (SkillCloak) |

Калибровка по «чистым» логам, чтобы не было ложных срабатываний:

- `bash` сам ходит в unix-сокет `/var/run/nscd/socket` -> учитываем только AF_INET/AF_INET6;
- `bash` открывает `/dev/tty` на запись -> записи в `/dev`, `/proc`, `/sys`, `/run` игнорируем;
- интерпретатор скрипта (`bash /skill/scripts/x.sh`) не должен считаться подозрительным запуском
  -> оболочка подозрительна только с флагом `-c`.

Находки группируются по цели (путь, адрес, программа), в каждой не больше 3 строк лога как
доказательство. `tests/test_rules.py`: 9 тестов, включая проверку, что обе benign-фикстуры
дают ровно ноль находок.

### Шаг 8 — отчёт, CLI и eval (`feat: add report rendering, scan pipeline and CLI`)

- `skilltrap/scan.py` — сам конвейер `scan_skill()`. **Отступление от структуры в CLAUDE.md:**
  конвейер вынесен из `cli.py` в отдельный модуль, чтобы `eval/run_eval.py` не импортировал CLI.
- `skilltrap/report.py`: `render_terminal()` (rich: панель вердикта + таблицы),
  `render_markdown()`, `render_json()`.
- `skilltrap/cli.py`: `skilltrap scan <path> [--format table|markdown|json] [-o файл]
  [--timeout N] [--keep-workspace DIR]` и `skilltrap eval`.
  Коды выхода для CI: `0` SAFE, `1` SUSPICIOUS, `2` MALICIOUS, `3` ошибка (нет Docker / битый скил).
- `eval/run_eval.py`: прогон всех фикстур, TP/FP/FN/TN, precision/recall/F1, запись `eval/results.md`.
- Тесты: `tests/test_report.py` (5) и `tests/test_cli.py` (8, конвейер подменён — Docker не нужен).

**Результат первого полного прогона `uv run skilltrap eval`:**
5 вредоносных фикстур из 5 обнаружены, обе чистые получили SAFE —
precision = 1.00, recall = 1.00, F1 = 1.00.

## Осталось
3. `sandbox/Dockerfile` + `sandbox/runner.py`.
4. `trace_parser.py`.
5. `rules.py`.
6. `report.py` + `cli.py`.
7. Фикстуры (benign + безопасные имитации атак).
8. `eval/run_eval.py` + `eval/results.md`.
9. `static_checks.py`, `skill/skilltrap/SKILL.md`, `README.md`.

## Известные проблемы

Пока нет.
