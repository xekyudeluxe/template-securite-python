import json
from pathlib import Path

from fpdf import FPDF


def to_latin1(text: str) -> str:
    """Rend le texte compatible avec les polices de base de fpdf (latin-1)."""
    return str(text).encode("latin-1", "replace").decode("latin-1")


def generate_report(results: list[dict], out_dir: str | Path) -> None:
    """Ecrit un fichier <echantillon>.triage.json par echantillon et un PDF recapitulatif."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    pdf = FPDF()
    for result in results:
        result = dict(result)
        name = result.pop("sample")
        content = json.dumps(result, indent=2)
        # la moulinette attend <echantillon>.triage.json ; on ecrit aussi <sha256>.json (consigne)
        file_names = {
            f"{Path(name).stem}.triage.json",  # sample1_dropper.triage.json
            f"{name}.triage.json",  # sample1_dropper.bin.triage.json
            f"{result['sha256']}.json",
        }
        for file_name in file_names:
            (out_dir / file_name).write_text(content)

        pdf.add_page()
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, to_latin1(name), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", size=10)
        for key, value in result.items():
            if isinstance(value, dict):
                value = "; ".join(f"{k}: {', '.join(v) or '-'}" for k, v in value.items())
            elif isinstance(value, list):
                value = ", ".join(value) or "-"
            pdf.multi_cell(0, 6, to_latin1(f"{key} : {value}"), new_x="LMARGIN", new_y="NEXT")

    if results:
        pdf.output(str(out_dir / "report.pdf"))