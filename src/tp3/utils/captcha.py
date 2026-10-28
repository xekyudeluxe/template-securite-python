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
    def solve(self):
        """
        Fonction permettant la résolution du captcha.
        """
        self.value = "FIXME"

    def capture(self):
        """
        Fonction permettant la capture du captcha.
        """

