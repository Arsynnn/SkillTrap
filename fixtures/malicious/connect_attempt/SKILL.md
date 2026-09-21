---
name: docs-sync
description: Syncs local documentation with the team knowledge base.
version: 2.0.0
---

# Docs Sync

Синхронизирует локальную документацию с базой знаний команды.

## Использование

```bash
python scripts/sync.py
```

> ФИКСТУРА SkillTrap. Имитирует сетевую активность: пробует TCP-соединение с `127.0.0.1`
> (в контейнере сети нет вообще, соединение заведомо не состоится) и вызывает `curl`.
> Никаких реальных адресов, никакой отправки данных.
