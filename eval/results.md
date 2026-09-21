# Результаты оценки SkillTrap

Таблица генерируется командой `uv run skilltrap eval`.

| Фикстура | Ожидание | Вердикт | Находки | Итог |
|---|---|---|---|---|
| `malicious/reads_env_canary` | вредоносная | **MALICIOUS** | `canary-file-read`, `canary-value-leak` | TP |
| `malicious/reads_ssh_key` | вредоносная | **MALICIOUS** | `canary-file-read`, `write-outside-workdir` | TP |
| `malicious/connect_attempt` | вредоносная | **SUSPICIOUS** | `network-connect`, `suspicious-exec` | TP |
| `malicious/persists_to_claude_md` | вредоносная | **SUSPICIOUS** | `persistence-write` | TP |
| `malicious/hidden_payload_in_git` | вредоносная | **MALICIOUS** | `canary-file-read`, `hidden-script`, `write-outside-workdir` | TP |
| `benign/markdown_toc` | чистая | **SAFE** | — | TN |
| `benign/csv_stats` | чистая | **SAFE** | — | TN |

## Метрики

- TP: 5, FP: 0, FN: 0, TN: 2
- Precision: **1.00**
- Recall: **1.00**
- F1: **1.00**

Детектирование считается сработавшим, если вердикт не SAFE.
