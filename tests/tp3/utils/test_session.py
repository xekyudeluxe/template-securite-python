from src.tp3.utils.session import Session


def test_resoudre_captcha(monkeypatch):
    session = Session("http://x", "http://x/internal-panel")
    monkeypatch.setattr(session.http, "get", lambda url, timeout: None)

    class FauxCaptcha:
        def __init__(self, http, url):
            pass

        def capture(self):
            pass

        def solve(self):
            return "AB12"

    monkeypatch.setattr("src.tp3.utils.session.Captcha", FauxCaptcha)
    assert session.resoudre_captcha() == "AB12"


def test_envoyer_ok(monkeypatch):
    session = Session("http://x", "http://x/internal-panel")

    class FausseReponse:
        status_code = 200

        def json(self):
            return {"flag1": "ESGI{web_x}"}

    monkeypatch.setattr(session.http, "post", lambda url, data, timeout: FausseReponse())
    assert session.envoyer("AB12") is True
    assert session.data["flag1"] == "ESGI{web_x}"


def test_envoyer_ko(monkeypatch):
    session = Session("http://x", "http://x/internal-panel")

    class FausseReponse:
        status_code = 403

    monkeypatch.setattr(session.http, "post", lambda url, data, timeout: FausseReponse())
    assert session.envoyer("AB12") is False


def test_obtenir_infos(monkeypatch):
    session = Session("http://x", "http://x/internal-panel")
    monkeypatch.setattr(session, "resoudre_captcha", lambda: "AB12")

    essais = {"n": 0}

    def faux_envoyer(code):
        essais["n"] += 1
        if essais["n"] >= 2:
            session.data = {"flag1": "ESGI{web_x}"}
            return True
        return False

    monkeypatch.setattr(session, "envoyer", faux_envoyer)
    assert session.obtenir_infos()["flag1"] == "ESGI{web_x}"
