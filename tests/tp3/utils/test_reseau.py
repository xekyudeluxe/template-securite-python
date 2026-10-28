import base64

from src.tp3.utils.reseau import Reseau, decoder


def test_decoder():
    cle = bytes.fromhex("01020304")
    clair = b"token123"
    chiffre = bytes(o ^ cle[i % len(cle)] for i, o in enumerate(clair))
    ligne = base64.b64encode(chiffre)
    assert decoder(ligne, cle) == clair


def test_jouer():
    cle = bytes.fromhex("01020304")
    token = b"abcd1234abcd1234"
    chiffre = bytes(o ^ cle[i % len(cle)] for i, o in enumerate(token))
    ligne = base64.b64encode(chiffre)

    class FauxSocket:
        def __init__(self, messages):
            self.messages = messages
            self.envoyes = []

        def recv(self, taille):
            return self.messages.pop(0) if self.messages else b""

        def sendall(self, data):
            self.envoyes.append(data)

    reseau = Reseau("x", 1, "01020304")
    reseau.sock = FauxSocket([ligne + b"\n", b"OK ESGI{chain_test}\n"])
    assert reseau.jouer() == "ESGI{chain_test}"
    assert reseau.sock.envoyes == [token + b"\n"]
