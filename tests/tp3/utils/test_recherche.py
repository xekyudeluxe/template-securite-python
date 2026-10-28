from src.tp3.utils.recherche import Recherche


def test_lire_mots(tmp_path):
    fichier = tmp_path / "wl.txt"
    fichier.write_text("admin\n\nsecret\n")
    recherche = Recherche("http://x", fichier)
    assert recherche.lire_mots() == ["admin", "secret"]


def test_chercher(tmp_path, monkeypatch):
    fichier = tmp_path / "wl.txt"
    fichier.write_text("rien\nsecret\n")
    recherche = Recherche("http://x", fichier)

    class FausseReponse:
        def __init__(self, code):
            self.status_code = code

    def faux_get(url, timeout):
        return FausseReponse(200 if url.endswith("/secret") else 404)

    monkeypatch.setattr("src.tp3.utils.recherche.requests.get", faux_get)
    assert recherche.chercher() == "http://x/secret"
