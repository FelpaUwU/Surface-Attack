"""Extract the next sweep of N companies (name,url) from the full client DB
export and split it into batches of 100, same shape as convert_and_split.py
produced before.

Keeps a cumulative history file (companies_used_history.csv) of every
company name ever picked in a previous sweep, so re-running this script for
a new sweep never repeats a company that was already handed out in an
earlier batch. On first run it seeds that history from the existing
companies_full.csv (the previous sweep) before overwriting it.

Usage:
    ..\\.venv\\Scripts\\python.exe extract_next_sweep.py
"""
import csv
from pathlib import Path

import openpyxl

HERE = Path(__file__).parent
SOURCE = HERE / "FORMATO UNICO ANALISIS DE CAMPAÑAS, CORRERIAS O EVENTOS_DIAGNÓSTICO OCULTO DE SUPERFICIE DE ATAQUE.xlsx"
SHEET = "Clientes Objetivos"
HEADER_ROW = 4
DATA_START_ROW = 5
NAME_COL = 1  # "Nombre del cliente"
DOMAIN_COL = 3  # "dominio"

SWEEP_SIZE = 500
BATCH_SIZE = 100

FULL_CSV = HERE / "companies_full.csv"
HISTORY_CSV = HERE / "companies_used_history.csv"
BATCH_DIR = HERE / "batches"


def load_history() -> set[str]:
    if HISTORY_CSV.exists():
        with open(HISTORY_CSV, encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader, None)
            return {row[0].strip() for row in reader if row}

    # First run: seed history from whatever sweep is currently in
    # companies_full.csv so we don't re-pick it.
    if FULL_CSV.exists():
        with open(FULL_CSV, encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader, None)
            return {row[0].strip() for row in reader if row}

    return set()


def save_history(names_urls: list[tuple[str, str]]) -> None:
    existing = {}
    if HISTORY_CSV.exists():
        with open(HISTORY_CSV, encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader, None)
            for row in reader:
                if row:
                    existing[row[0].strip()] = row[1].strip() if len(row) > 1 else ""

    for name, url in names_urls:
        existing[name] = url

    with open(HISTORY_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["name", "url"])
        writer.writerows(sorted(existing.items()))


def main():
    used = load_history()
    print(f"Empresas ya usadas en barridos anteriores: {len(used)}")

    wb = openpyxl.load_workbook(SOURCE, read_only=True, data_only=True)
    ws = wb[SHEET]

    seen_this_pass = set()
    candidates: list[tuple[str, str]] = []
    for row in ws.iter_rows(min_row=DATA_START_ROW, values_only=True):
        padded = row + (None,) * (max(NAME_COL, DOMAIN_COL) + 1)
        name, url = padded[NAME_COL], padded[DOMAIN_COL]
        if name is None or url is None:
            continue
        name = str(name).strip()
        url = str(url).strip()
        if not name or not url:
            continue
        if name in used or name in seen_this_pass:
            continue
        seen_this_pass.add(name)
        candidates.append((name, url))

    if len(candidates) < SWEEP_SIZE:
        print(
            f"ADVERTENCIA: solo hay {len(candidates)} empresas nuevas disponibles, "
            f"menos de las {SWEEP_SIZE} solicitadas."
        )

    sweep = candidates[:SWEEP_SIZE]

    # Wipe previously generated batches/full CSV for the old sweep so there's
    # no confusion about which lot is current.
    if BATCH_DIR.exists():
        for old_batch in BATCH_DIR.glob("companies_batch_*.csv"):
            old_batch.unlink()
    BATCH_DIR.mkdir(exist_ok=True)

    with open(FULL_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["name", "url"])
        writer.writerows(sweep)

    batch_paths = []
    for i in range(0, len(sweep), BATCH_SIZE):
        batch = sweep[i : i + BATCH_SIZE]
        batch_num = i // BATCH_SIZE + 1
        path = BATCH_DIR / f"companies_batch_{batch_num:02d}.csv"
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["name", "url"])
            writer.writerows(batch)
        batch_paths.append((path, len(batch)))

    save_history(sweep)

    print(f"Nuevo barrido: {len(sweep)} empresas")
    print(f"CSV completo: {FULL_CSV}")
    print(f"Lotes de {BATCH_SIZE} en {BATCH_DIR}:")
    for path, count in batch_paths:
        print(f"  {path.name}: {count} empresas")
    print(f"Historial acumulado actualizado: {HISTORY_CSV}")


if __name__ == "__main__":
    main()
