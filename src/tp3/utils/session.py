import requests

from src.tp3.utils.captcha import Captcha


class Session:
    """Gere la phase web : captcha puis recuperation du flag1 et des infos TCP."""

    def __init__(self, target, endpoint):
        self.target = target.rstrip("/")
        self.endpoint = endpoint
        self.http = requests.Session()
        self.data = {}
    def prepare_request(self):
        """
        Prepares the request for sending by capturing and solving the captcha.
        """
        captcha = Captcha(self.url)
        captcha.capture()
        captcha.solve()

        self.captcha_value = captcha.get_value()
        self.flag_value = "FIXME"

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
