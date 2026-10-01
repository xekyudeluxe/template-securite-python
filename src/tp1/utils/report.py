import json

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
from fpdf import FPDF

from tp1.utils.capture import Capture


class Report:
    def __init__(self, capture: Capture, filename: str, summary: str):
        self.capture = capture
        self.filename = filename
        self.title = "Rapport TP1 - IDS/IPS maison"
        self.summary = summary
        self.array = ""
        self.graph = ""

    def concat_report(self) -> str:
        """
        Concat all data in report
        """
        content = ""
        content += self.title
        content += self.summary
        content += self.array
        content += self.graph
        return content

    def generate(self, param: str) -> None:
        """
        Generate graph and array
        """
        if param == "graph":
            self.graph = self.make_graph()
        elif param == "array":
            self.array = self.make_array()

    def make_graph(self) -> str:
        """
        Fait un graphique en barres des protocoles et renvoie le nom de l'image.
        """
        noms = list(self.capture.protocols.keys())
        valeurs = list(self.capture.protocols.values())

        plt.figure()
        plt.bar(noms, valeurs)
        plt.title("Protocoles reseau captures")
        plt.xlabel("Protocole")
        plt.ylabel("Nombre de paquets")
        plt.tight_layout()
        plt.savefig("protocols.png")
        plt.close()

        return "protocols.png"

    def make_array(self) -> str:
        """
        Fait le tableau des protocoles en texte.
        """
        texte = ""
        for nom in self.capture.protocols:
            texte += f"{nom} : {self.capture.protocols[nom]}\n"
        return texte

    def save(self, filename: str) -> None:
        """
        Save report in a PDF file
        """
        pdf = FPDF()
        pdf.add_page()

        pdf.set_font("Helvetica", size=14)
        pdf.cell(0, 10, self.title, ln=True)
        pdf.ln(5)

        # Le graphique (si il a ete genere)
        if self.graph:
            pdf.image(self.graph, w=180)
            pdf.ln(5)

        pdf.cell(0, 10, "Protocoles :", ln=True)
        for nom in self.capture.protocols:
            pdf.cell(0, 8, f"{nom} : {self.capture.protocols[nom]}", ln=True)
        pdf.ln(5)

        pdf.cell(0, 10, "Attaques :", ln=True)
        if self.capture.attacks:
            for attaque in self.capture.attacks:
                pdf.cell(0, 8, f"- {attaque['type']} depuis {attaque['attacker']}", ln=True)
        else:
            pdf.cell(0, 8, "Aucune attaque.", ln=True)

        pdf.output(filename)

    def write_json(self, out="report.json") -> None:
        """
        Write the report.json file
        """
        data = {
            "protocols": self.capture.protocols,
            "attacks": self.capture.attacks,
            "flag": self.capture.flag,
        }
        with open(out, "w") as f:
            json.dump(data, f, indent=2)