"""One-off: convert the client list xlsx to CSV and split it into batches
of 100 (name,url) rows each, ready to pass to main.py --input.

Usage:
    ..\\.venv\\Scripts\\python.exe convert_and_split.py
"""
import csv
from pathlib import Path

import openpyxl

SOURCE = Path(__file__).parent / "BD1 SUPERFICIE DE ATAQUE.xlsx"
SHEET = "BD1"
BATCH_SIZE = 100
OUT_DIR = Path(__file__).parent / "batches"


def main():
    wb = openpyxl.load_workbook(SOURCE, read_only=True, data_only=True)
    ws = wb[SHEET]

    rows = []
    for row in ws.iter_rows(min_row=3, values_only=True):
        name, url = (row + (None, None, None))[1:3]
        if name is None and url is None:
            continue
        name = str(name).strip()
        url = str(url).strip()
        if name and url:
            rows.append((name, url))

    OUT_DIR.mkdir(exist_ok=True)

    full_path = Path(__file__).parent / "companies_full.csv"
    with open(full_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["name", "url"])
        writer.writerows(rows)

    batch_paths = []
    for i in range(0, len(rows), BATCH_SIZE):
        batch = rows[i : i + BATCH_SIZE]
        batch_num = i // BATCH_SIZE + 1
        path = OUT_DIR / f"companies_batch_{batch_num:02d}.csv"
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["name", "url"])
            writer.writerows(batch)
        batch_paths.append((path, len(batch)))

    print(f"Total clientes: {len(rows)}")
    print(f"CSV completo: {full_path}")
    print(f"Lotes de {BATCH_SIZE} en {OUT_DIR}:")
    for path, count in batch_paths:
        print(f"  {path.name}: {count} clientes")


if __name__ == "__main__":
    main()
