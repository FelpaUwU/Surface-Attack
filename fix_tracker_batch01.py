"""One-off recovery: batch 01 finished all 100 scans but the tracker update
failed with PermissionError because the xlsx was open elsewhere. Re-derive
the (domain, grade) pairs from the already-generated _resumen.csv (no need
to re-scan) and apply them now that the file is closed.
"""
import csv
from pathlib import Path

from checks.scanner import normalize_domain
from checks.client_tracker import update_tracker, TrackerLayoutError

RESUMEN = Path("output/batch_01/_resumen.csv")
TRACKER = Path("data/FORMATO UNICO ANALISIS DE CAMPAÑAS, CORRERIAS O EVENTOS_DIAGNÓSTICO OCULTO DE SUPERFICIE DE ATAQUE.xlsx")


def main():
    domain_grades = []
    with open(RESUMEN, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if not row["pdf"] or row["error"]:
                continue
            registered_domain, _, _ = normalize_domain(row["url"])
            domain_grades.append((registered_domain, row["grade"]))

    print(f"Empresas a marcar del lote 01: {len(domain_grades)}")
    matched, total, backup_path = update_tracker(TRACKER, "Clientes Objetivos", domain_grades)
    print(f"Tracker actualizado: {matched}/{total} dominios marcados (backup: {backup_path.name})")
    if matched < total:
        print(f"AVISO: {total - matched} dominios del lote 01 no se encontraron en la hoja de seguimiento.")


if __name__ == "__main__":
    main()
