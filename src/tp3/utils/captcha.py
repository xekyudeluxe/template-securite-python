import io

import pytesseract
import requests
from PIL import Image

from src.tp3.utils.config import logger


class Captcha:
    """Telecharge et lit le captcha image via OCR."""

    def __init__(self, session, image_url):
        self.session = session
        self.image_url = image_url
        self.image = None
        self.value = ""

    def get_value(self):
        return self.value

    def capture(self):
        """Telecharge l'image du captcha."""
        reponse = self.session.get(self.image_url, timeout=5)
        self.image = Image.open(io.BytesIO(reponse.content))
        return self.image

    def nettoyer(self):
        """Passe en niveaux de gris et en noir et blanc pour l'OCR."""
        gris = self.image.convert("L")
        return gris.point(lambda x: 0 if x < 128 else 255)

    def solve(self):
        """Lit les 5 caracteres du captcha."""
        propre = self.nettoyer()
        texte = pytesseract.image_to_string(
            propre,
            config="--psm 7 -c tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        )
        self.value = texte.strip().upper()
        logger.info("Captcha lu : %s", self.value)
        return self.value