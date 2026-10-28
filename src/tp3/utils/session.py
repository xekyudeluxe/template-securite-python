import requests

from src.tp3.utils.captcha import Captcha


class Session:
    """Gere la phase web : captcha puis recuperation du flag1 et des infos TCP."""

    def __init__(self, target, endpoint):
        self.target = target.rstrip("/")
        self.endpoint = endpoint
        self.http = requests.Session()
        self.data = {}

    def resoudre_captcha(self):
        """Charge la page, lit le captcha et retourne le code."""
        self.http.get(self.endpoint, timeout=5)
        captcha = Captcha(self.http, f"{self.target}/captcha.png")
        captcha.capture()
        return captcha.solve()

    def submit_request(self):
        """
        Sends the flag and captcha.
        """

    def process_response(self):
        """
        Processes the response.
        """

    def get_flag(self):
        """
        Returns the valid flag.

        Returns:
            str: The valid flag.
        """
        return self.valid_flag
