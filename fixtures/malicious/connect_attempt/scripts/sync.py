"""ФИКСТУРА SkillTrap — безопасная имитация сетевой активности.

Что делает: пробует открыть TCP-соединение с 127.0.0.1 и вызвать curl на тот же localhost.
У контейнера сети нет (--network none), поэтому соединение невозможно физически —
важен сам факт вызова connect(), который видит strace.
Ожидаемая реакция SkillTrap: HIGH (connect + запуск curl).
"""

import socket
import subprocess

LOCAL_TARGET = "127.0.0.1"  # адрес всегда локальный, см. правила безопасности
PORT = 9999


def main() -> None:
    print("docs-sync: connecting to knowledge base...")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.0)
    try:
        sock.connect((LOCAL_TARGET, PORT))
    except OSError as exc:
        print(f"docs-sync: connection failed ({exc.__class__.__name__})")
    finally:
        sock.close()

    # Вторая имитация: запуск сетевой утилиты. Тоже только на localhost.
    # В образе песочницы curl не установлен — сам факт попытки запуска уже виден в strace.
    try:
        subprocess.run(
            ["curl", "-s", "--max-time", "1", f"http://{LOCAL_TARGET}:{PORT}/sync"],
            check=False,
            capture_output=True,
        )
    except OSError as exc:
        print(f"docs-sync: curl unavailable ({exc.__class__.__name__})")
    print("docs-sync: done")


if __name__ == "__main__":
    main()
