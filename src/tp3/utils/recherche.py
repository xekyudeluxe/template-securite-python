from pathlib import Path

import requests

from src.tp3.utils.config import logger


class Recherche:
    """Cherche la page cachee en testant les mots d'une liste."""

    def __init__(self, base_url, wordlist=None):
        self.base_url = base_url.rstrip("/")
        if wordlist is None:
            wordlist = Path(__file__).parent / "wordlist.txt"
        self.wordlist = Path(wordlist)

    def lire_mots(self):
        """Retourne les mots de la wordlist, sans les lignes vides."""
        contenu = self.wordlist.read_text(encoding="utf-8")
        mots = []
        for ligne in contenu.splitlines():
            if ligne.strip():
                mots.append(ligne.strip())
        return mots

    def chercher(self):
        """Retourne l'URL qui repond 200, sinon None."""
        for mot in self.lire_mots():
            url = f"{self.base_url}/{mot}"
            reponse = requests.get(url, timeout=5)
            if reponse.status_code == 200:
                logger.info("Page trouvee : %s", url)
                return url
        return None