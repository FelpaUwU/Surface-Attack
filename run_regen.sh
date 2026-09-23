#!/bin/bash
set -e
cd "$(dirname "$0")"
export PYTHONIOENCODING=utf-8
export PYTHONUTF8=1
./.venv/Scripts/python.exe -c "
import shlex
for line in open('.env', encoding='utf-8'):
    line = line.strip()
    if not line or line.startswith('#') or '=' not in line:
        continue
    k, v = line.split('=', 1)
    print(f'export {k}={shlex.quote(v)}')
" > .env.sh
source .env.sh
rm .env.sh

TRACKER="data/FORMATO UNICO ANALISIS DE CAMPAÑAS, CORRERIAS O EVENTOS_DIAGNÓSTICO OCULTO DE SUPERFICIE DE ATAQUE.xlsx"

rm -rf output/_regen
for f in data/regen/batch_*.csv; do
  b=$(basename "$f" .csv)
  echo "=================================================================="
  echo "REGENERANDO $b"
  echo "=================================================================="
  ./.venv/Scripts/python.exe main.py \
    --input "$f" \
    --output "output/_regen/$b" \
    --workers 8 \
    --tools auto \
    --email-detail-mode obfuscated \
    --hunter-cache-group "$b" \
    --tracker-xlsx "$TRACKER" \
    --tracker-sheet "Clientes Objetivos"
done

echo "REGENERACION TERMINADA"
