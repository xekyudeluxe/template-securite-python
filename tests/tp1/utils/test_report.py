import json

from src.tp1.utils.report import Report


class FaussaireCapture:
    """
    Capture fictive pour tester Report sans dépendance à scapy.
    """
    def __init__(self):
        self.protocols = {"TCP": 5, "ARP": 2}
        self.attacks = [{"type": "port_scan", "attacker": "10.0.0.5"}]
        self.flag = "ESGI{test}"


def test_initialisation_report():

    capture_simulee = FaussaireCapture()
    rapport = Report(capture_simulee, "test.pdf", "Test summary")

    assert rapport.capture == capture_simulee
    assert rapport.filename == "test.pdf"
    assert rapport.title == "Rapport TP1 - IDS/IPS maison"
    assert rapport.summary == "Test summary"
    assert rapport.array == ""
    assert rapport.graph == ""


def test_ecriture_json(tmp_path):

    rapport = Report(FaussaireCapture(), "test.pdf", "")
    chemin_fichier = tmp_path / "report.json"
    rapport.write_json(str(chemin_fichier))

    contenu = json.loads(chemin_fichier.read_text())
    assert contenu["protocols"] == {"TCP": 5, "ARP": 2}
    assert contenu["attacks"][0]["attacker"] == "10.0.0.5"
    assert contenu["flag"] == "ESGI{test}"


def test_sauvegarde_cree_pdf(tmp_path):
    rapport = Report(FaussaireCapture(), "test.pdf", "")
    rapport.generate("graph")
    rapport.generate("array")
    chemin_pdf = tmp_path / "rapport.pdf"

    rapport.save(str(chemin_pdf))

    assert chemin_pdf.exists()