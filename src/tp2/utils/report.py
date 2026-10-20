import json
from pathlib import Path

from fpdf import FPDF


def to_latin1(text):
    # les polices de base de fpdf ne gèrent que le latin-1
    return str(text).encode("latin-1", "replace").decode("latin-1")


def generate_report(results, out_dir):
    """Un JSON par échantillon (<sha256>.json) + un PDF lisible qui regroupe tout."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    pdf = FPDF()
    for result in results:
        (out_dir / f"{result['sha256']}.json").write_text(json.dumps(result, indent=2))

        pdf.add_page()
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, f"Echantillon {result['sha256'][:16]}...", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", size=10)
        for key, value in result.items():
            if isinstance(value, dict):
                value = "; ".join(f"{k}: {', '.join(v) or '-'}" for k, v in value.items())
            elif isinstance(value, list):
                value = ", ".join(value) or "-"
            pdf.multi_cell(0, 6, to_latin1(f"{key} : {value}"), new_x="LMARGIN", new_y="NEXT")

    if results:
        pdf.output(str(out_dir / "report.pdf"))