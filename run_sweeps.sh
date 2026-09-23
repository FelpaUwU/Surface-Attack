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

for n in 01 02 03 04 05 06 07 08 09 10; do
  echo "=================================================================="
  echo "LOTE $n"
  echo "=================================================================="
  ./.venv/Scripts/python.exe main.py \
    --input "data/batches/companies_batch_${n}.csv" \
    --output "output/batch_${n}" \
    --workers 8 \
    --tools auto \
    --email-detail-mode obfuscated \
    --hunter-cache-group "batch_${n}" \
    --tracker-xlsx "$TRACKER" \
    --tracker-sheet "Clientes Objetivos"
done

echo "TODOS LOS LOTES TERMINADOS"
