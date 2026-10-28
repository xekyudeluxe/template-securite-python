from src.tp3 import main


def test_parse_args():
    args = main.parse_args(["--target", "http://localhost:8080"])
    assert args.target == "http://localhost:8080"


def test_run(monkeypatch):
    logs = []

    class FausseRecherche:
        def __init__(self, target):
            pass

        def chercher(self):
            return "http://x/internal-panel"

    class FausseSession:
        def __init__(self, target, endpoint):
            pass

        def obtenir_infos(self):
            return {"flag1": "ESGI{web_x}", "host": "h", "port": 1, "key": "00"}

    class FauxReseau:
        def __init__(self, host, port, key):
            pass

        def connecter(self):
            pass

        def jouer(self):
            return "ESGI{chain_x}"

        def fermer(self):
            pass

    monkeypatch.setattr(main, "Recherche", FausseRecherche)
    monkeypatch.setattr(main, "Session", FausseSession)
    monkeypatch.setattr(main, "Reseau", FauxReseau)
    monkeypatch.setattr(main.logger, "info", lambda *a: logs.append(a))

    main.run("http://x")
    messages = [a[0] % a[1:] if len(a) > 1 else a[0] for a in logs]
    assert any("ESGI{web_x}" in m for m in messages)
    assert any("ESGI{chain_x}" in m for m in messages)
