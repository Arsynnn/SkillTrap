"""Снимок файлов fake_home до и после запуска скила.

Зачем это нужно, если есть strace: strace пишет только те системные вызовы, которые мы
попросили (`openat`, `execve`, ...). Если скил изменит файл другим способом или strace
собьётся, изменение всё равно будет видно по хешам. То есть fsdiff — независимая
перепроверка поведения, а не замена трассировке.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from skilltrap.models import FsChanges

#: Читаем файл кусками: домашняя папка маленькая, но привычка полезная.
CHUNK_SIZE = 65536


def snapshot(root: Path) -> dict[str, str]:
    """Хеши всех файлов внутри `root`, ключ — путь относительно `root` в posix-виде."""
    return {
        file.relative_to(root).as_posix(): file_hash(file)
        for file in sorted(root.rglob("*"))
        if file.is_file()
    }


def file_hash(file: Path) -> str:
    digest = hashlib.sha256()
    with file.open("rb") as handle:
        while chunk := handle.read(CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def diff(before: dict[str, str], after: dict[str, str]) -> FsChanges:
    """Сравнить два снимка."""
    return FsChanges(
        created=sorted(set(after) - set(before)),
        modified=sorted(path for path in set(before) & set(after) if before[path] != after[path]),
        deleted=sorted(set(before) - set(after)),
    )
