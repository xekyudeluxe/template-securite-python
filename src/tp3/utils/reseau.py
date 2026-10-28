import base64
import socket

from src.tp3.utils.config import logger


def decoder(ligne, cle):
    """base64 puis XOR avec la cle : retourne le token en clair."""
    brut = base64.b64decode(ligne)
    return bytes(o ^ cle[i % len(cle)] for i, o in enumerate(brut))


class Reseau:
    """Resout les rounds du service TCP et recupere le flag final."""

    def __init__(self, host, port, cle_hex):
        self.host = host
        self.port = int(port)
        self.cle = bytes.fromhex(cle_hex)
        self.sock = None

    def connecter(self):
        self.sock = socket.create_connection((self.host, self.port), timeout=5)

    def jouer(self):
        """Decode chaque jeton et le renvoie, jusqu'au flag final."""
        tampon = b""
        while True:
            tampon += self.sock.recv(4096)
            while b"\n" in tampon:
                ligne, tampon = tampon.split(b"\n", 1)
                ligne = ligne.strip()
                if b"ESGI{" in ligne:
                    logger.info("Flag final recu")
                    return ligne.decode(errors="ignore").replace("OK ", "")
                if not ligne or b"Decode" in ligne:
                    continue
                token = decoder(ligne, self.cle)
                self.sock.sendall(token + b"\n")

    def fermer(self):
        if self.sock:
            self.sock.close()
