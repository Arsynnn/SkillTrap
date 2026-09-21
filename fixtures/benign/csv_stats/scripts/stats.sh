#!/usr/bin/env bash
# ФИКСТУРА SkillTrap — безвредный скил: статистика по CSV.
# Работает только с файлами внутри своей папки. Ожидаемый вердикт: SAFE.
set -u

FILE="${1:-data/sample.csv}"

if [ ! -f "$FILE" ]; then
    echo "csv-stats: file not found: $FILE"
    exit 0
fi

ROWS=$(wc -l < "$FILE")
COLS=$(head -1 "$FILE" | tr ',' '\n' | wc -l)

echo "csv-stats: rows=$ROWS columns=$COLS"
echo "csv-stats: header: $(head -1 "$FILE")"
