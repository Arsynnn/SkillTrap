"""Запуск скриптов скила в Docker-песочнице под strace.

Каждый скрипт запускается в отдельном одноразовом контейнере:

    docker run --rm --network none --user 1000:1000 --memory 256m --pids-limit 128 ...
        skilltrap-sandbox strace -f -tt -s 256 -o /trace/<script>.log
        -e trace=openat,... <interpreter> /skill/<script>

Три жёстких правила (см. CLAUDE.md): никакой сети, не root, ограничения по ресурсам и таймаут.
Скрипты проверяемого скила НИКОГДА не выполняются на хосте — только внутри контейнера,
и работают они с копией скила, а не с оригиналом.
"""

from __future__ import annotations

import shutil
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path

from skilltrap.canaries import CONTAINER_HOME, materialize_fake_home
from skilltrap.models import Canary, Interpreter, ScriptRun, SkillInfo, SkillScript

IMAGE_TAG = "skilltrap-sandbox:latest"
DOCKERFILE_DIR = Path(__file__).parent

CONTAINER_SKILL_DIR = "/skill"
CONTAINER_TRACE_DIR = "/trace"

#: Системные вызовы, которые нас интересуют. Всё остальное strace не пишет — меньше шума.
TRACED_SYSCALLS = "openat,open,execve,connect,unlinkat,unlink,renameat2,rename"

#: Сколько текста stdout/stderr сохраняем в отчёт.
OUTPUT_LIMIT = 4000

INTERPRETER_COMMAND: dict[Interpreter, str] = {
    Interpreter.PYTHON: "python",
    Interpreter.BASH: "bash",
}


class SandboxError(Exception):
    """Контейнер не собрался или не запустился — это проблема SkillTrap, а не скила."""


@dataclass(frozen=True)
class SandboxConfig:
    """Ограничения песочницы. Значения по умолчанию — из CLAUDE.md."""

    image: str = IMAGE_TAG
    memory: str = "256m"
    cpus: str = "1.0"
    pids_limit: int = 128
    timeout_s: int = 30
    # strace под непривилегированным пользователем обычно работает и так, но на части хостов
    # нужен SYS_PTRACE. Держим включённым: это единственная добавленная привилегия.
    cap_add_ptrace: bool = True


@dataclass(frozen=True)
class Workspace:
    """Временная папка на хосте, которая монтируется в контейнер."""

    root: Path

    @property
    def skill_dir(self) -> Path:
        return self.root / "skill"

    @property
    def home_dir(self) -> Path:
        return self.root / "home"

    @property
    def trace_dir(self) -> Path:
        return self.root / "trace"


def docker_available() -> bool:
    """Есть ли docker и отвечает ли демон."""
    try:
        result = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Os}}"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def image_exists(image: str = IMAGE_TAG) -> bool:
    result = subprocess.run(
        ["docker", "images", "-q", image], capture_output=True, text=True, timeout=60
    )
    return result.returncode == 0 and bool(result.stdout.strip())


def build_image(image: str = IMAGE_TAG, force: bool = False) -> None:
    """Собрать образ песочницы, если его ещё нет."""
    if not force and image_exists(image):
        return
    result = subprocess.run(
        ["docker", "build", "-t", image, str(DOCKERFILE_DIR)],
        capture_output=True,
        text=True,
        timeout=900,
    )
    if result.returncode != 0:
        raise SandboxError(f"не удалось собрать образ {image}:\n{result.stderr[-2000:]}")


def prepare_workspace(root: Path, skill: SkillInfo, canaries: list[Canary]) -> Workspace:
    """Разложить рабочую папку: копия скила, fake_home с приманками, пустая папка для логов."""
    workspace = Workspace(root=root)
    workspace.root.mkdir(parents=True, exist_ok=True)

    if workspace.skill_dir.exists():
        shutil.rmtree(workspace.skill_dir)
    # Работаем с копией: оригинальная папка скила на хосте остаётся нетронутой.
    shutil.copytree(skill.root, workspace.skill_dir)

    materialize_fake_home(workspace.home_dir, canaries)
    workspace.trace_dir.mkdir(parents=True, exist_ok=True)
    return workspace


def run_script(
    script: SkillScript,
    workspace: Workspace,
    config: SandboxConfig | None = None,
) -> ScriptRun:
    """Запустить один скрипт в контейнере и вернуть результат вместе с путём к логу strace."""
    config = config or SandboxConfig()
    log_name = f"{script.path.as_posix().replace('/', '_')}.log"
    trace_log = workspace.trace_dir / log_name
    container_name = f"skilltrap-{uuid.uuid4().hex[:12]}"

    command = _docker_command(script, workspace, config, container_name, log_name)

    timed_out = False
    try:
        # encoding/errors задаём явно: на Windows locale-кодировка не переваривает
        # вывод контейнера и subprocess падает с UnicodeDecodeError.
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=config.timeout_s + 15,
        )
        exit_code: int | None = result.returncode
        stdout, stderr = _as_text(result.stdout), _as_text(result.stderr)
    except subprocess.TimeoutExpired as exc:
        # Контейнер завис — убиваем его, иначе он переживёт нас.
        subprocess.run(["docker", "rm", "-f", container_name], capture_output=True, timeout=60)
        timed_out = True
        exit_code = None
        stdout = _as_text(exc.stdout)
        stderr = _as_text(exc.stderr)

    # `timeout` внутри контейнера возвращает 124, если скрипт не уложился в лимит.
    if exit_code == 124:
        timed_out = True

    return ScriptRun(
        script=script.path,
        interpreter=script.interpreter,
        exit_code=exit_code,
        timed_out=timed_out,
        stdout=stdout[:OUTPUT_LIMIT],
        stderr=stderr[:OUTPUT_LIMIT],
        trace_log=trace_log if trace_log.is_file() else None,
    )


def _docker_command(
    script: SkillScript,
    workspace: Workspace,
    config: SandboxConfig,
    container_name: str,
    log_name: str,
) -> list[str]:
    """Собрать команду `docker run`. Вынесено отдельно, чтобы её можно было проверить тестом."""
    interpreter = INTERPRETER_COMMAND[script.interpreter]
    script_in_container = f"{CONTAINER_SKILL_DIR}/{script.path.as_posix()}"

    command = [
        "docker",
        "run",
        "--rm",
        "--name",
        container_name,
        "--network",
        "none",  # сети нет вообще
        "--user",
        "1000:1000",  # не root
        f"--memory={config.memory}",
        f"--cpus={config.cpus}",
        f"--pids-limit={config.pids_limit}",
        "--security-opt",
        "no-new-privileges",
        "--cap-drop",
        "ALL",
    ]
    if config.cap_add_ptrace:
        command += ["--cap-add", "SYS_PTRACE"]

    command += [
        "-v",
        _mount(workspace.skill_dir, CONTAINER_SKILL_DIR),
        "-v",
        _mount(workspace.home_dir, CONTAINER_HOME),
        "-v",
        _mount(workspace.trace_dir, CONTAINER_TRACE_DIR),
        "-w",
        CONTAINER_SKILL_DIR,
        config.image,
        # Жёсткий таймаут и внутри контейнера тоже: strace не должен висеть вечно.
        "timeout",
        "--signal=KILL",
        str(config.timeout_s),
        "strace",
        "-f",  # следить за дочерними процессами
        "-tt",  # метки времени
        "-s",
        "256",  # показывать длинные строки аргументов целиком
        "-o",
        f"{CONTAINER_TRACE_DIR}/{log_name}",
        "-e",
        f"trace={TRACED_SYSCALLS}",
        interpreter,
        script_in_container,
    ]
    return command


def _mount(host_path: Path, container_path: str) -> str:
    """Аргумент -v для docker. На Windows путь приводим к виду C:/Users/... ."""
    return f"{str(host_path.resolve()).replace(chr(92), '/')}:{container_path}"


def _as_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value
