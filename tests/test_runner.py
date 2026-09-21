"""Тесты песочницы.

Проверка команды `docker run` и подготовки рабочей папки идёт без Docker.
Реальный запуск контейнера вынесен в тест с маркером `docker` — он пропускается,
если демон недоступен.
"""

from pathlib import Path

import pytest

from skilltrap.canaries import generate_canaries
from skilltrap.loader import load_skill
from skilltrap.models import Interpreter, SkillScript
from skilltrap.sandbox import runner

FIXTURE = Path("fixtures/benign/markdown_toc")


def make_workspace(tmp_path: Path) -> runner.Workspace:
    skill = load_skill(FIXTURE)
    return runner.prepare_workspace(tmp_path / "ws", skill, generate_canaries())


def test_prepare_workspace_copies_skill_and_plants_canaries(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path)

    assert (workspace.skill_dir / "SKILL.md").is_file()
    assert (workspace.home_dir / ".env").is_file()
    assert workspace.trace_dir.is_dir()
    # Оригинал скила не тронут: в песочницу уехала копия.
    assert (FIXTURE / "SKILL.md").is_file()


def test_docker_command_enforces_sandbox_flags(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path)
    script = SkillScript(path=Path("scripts/toc.py"), interpreter=Interpreter.PYTHON)

    command = runner._docker_command(
        script, workspace, runner.SandboxConfig(), "test-container", "toc.log"
    )
    joined = " ".join(command)

    # Обязательные ограничения из CLAUDE.md.
    assert "--network none" in joined
    assert "--user 1000:1000" in joined
    assert "--memory=256m" in joined
    assert "--pids-limit=128" in joined
    assert "--cap-drop ALL" in joined
    assert "--cap-add SYS_PTRACE" in joined
    assert "no-new-privileges" in joined
    # Таймаут и strace с нужными вызовами.
    assert "timeout --signal=KILL 30" in joined
    assert f"trace={runner.TRACED_SYSCALLS}" in joined
    # Путь скрипта внутри контейнера всегда через прямые слеши, даже если тест идёт на Windows.
    assert "/skill/scripts/toc.py" in command
    assert "\\" not in joined


def test_docker_command_uses_bash_for_shell_scripts(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path)
    script = SkillScript(path=Path("scripts/run.sh"), interpreter=Interpreter.BASH)

    command = runner._docker_command(script, workspace, runner.SandboxConfig(), "c", "run.log")

    assert command[-2] == "bash"
    assert command[-1] == "/skill/scripts/run.sh"


@pytest.mark.docker
@pytest.mark.skipif(not runner.docker_available(), reason="docker недоступен")
def test_benign_skill_runs_and_produces_trace(tmp_path: Path) -> None:
    """Интеграционный тест: контейнер запускается, strace пишет лог."""
    runner.build_image()
    skill = load_skill(FIXTURE)
    workspace = runner.prepare_workspace(tmp_path / "ws", skill, generate_canaries())

    run = runner.run_script(skill.scripts[0], workspace)

    assert run.exit_code == 0
    assert run.timed_out is False
    assert run.trace_log is not None
    assert "execve(" in run.trace_log.read_text(encoding="utf-8", errors="replace")
