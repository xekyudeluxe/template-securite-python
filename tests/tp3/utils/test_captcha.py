import io

from PIL import Image

from src.tp3.utils.captcha import Captcha


def _png():
    buf = io.BytesIO()
    Image.new("RGB", (10, 10), "white").save(buf, "PNG")
    return buf.getvalue()


class FausseSession:
    def __init__(self, contenu):
        self.contenu = contenu

    def get(self, url, timeout):
        class R:
            pass

        r = R()
        r.content = self.contenu
        return r


def test_capture():
    captcha = Captcha(FausseSession(_png()), "http://x/captcha.png")
    captcha.capture()
    assert captcha.image is not None


def test_nettoyer():
    captcha = Captcha(None, "http://x")
    captcha.image = Image.new("RGB", (10, 10), "white")
    assert captcha.nettoyer().mode == "L"


def test_solve(monkeypatch):
    captcha = Captcha(None, "http://x")
    captcha.image = Image.new("RGB", (10, 10), "white")
    monkeypatch.setattr(
        "src.tp3.utils.captcha.pytesseract.image_to_string",
        lambda img, config: "ab12\n",
    )
    assert captcha.solve() == "AB12"


def test_get_value():
    captcha = Captcha(None, "http://x")
    captcha.value = "XY9"
    assert captcha.get_value() == "XY9"
