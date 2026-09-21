# Образ песочницы SkillTrap.
# Внутри: python, bash и strace. Работаем под непривилегированным пользователем uid=1000.
# Сеть контейнеру не даётся вообще (--network none на запуске), поэтому любой connect()
# заведомо провалится — но strace успеет его записать, а это и есть наша находка.
FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends strace ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# uid 1000 — тот же, что передаётся в `docker run --user`, чтобы файлы в примонтированных
# папках были доступны на запись.
RUN useradd --create-home --uid 1000 --shell /bin/bash skill

# Точки монтирования: код скила, домашняя папка с приманками, логи strace.
RUN mkdir -p /skill /trace && chown skill:skill /skill /trace

# Скил не должен видеть окружение хоста: переменные задаём сами, минимальные.
ENV HOME=/home/skill \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER skill
WORKDIR /skill

CMD ["/bin/bash"]
