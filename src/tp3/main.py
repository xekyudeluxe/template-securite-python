import argparse

import requests

from src.tp3.utils.captcha import Captcha
from src.tp3.utils.config import logger
from src.tp3.utils.recherche import Recherche
from src.tp3.utils.reseau import Reseau


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="TP3 - Breach the target")
    parser.add_argument("--target", required=True, help="ex: http://localhost:8080")
    return parser.parse_args(argv)


def phase_web(target, endpoint):
    """Resout le captcha jusqu'a obtenir flag1 + host/port/cle."""
    while True:
        session = requests.Session()
        session.get(endpoint, timeout=5)
        captcha = Captcha(session, f"{target}/captcha.png")
        captcha.capture()
        code = captcha.solve()
        reponse = session.post(endpoint, data={"captcha": code}, timeout=5)
        if reponse.status_code == 200:
            return reponse.json()


def run(target):
    logger.info("Starting TP3")
    target = target.rstrip("/")

    endpoint = Recherche(target).chercher()
    if not endpoint:
        logger.error("Endpoint cache introuvable")
        return

    data = phase_web(target, endpoint)
    logger.info("FLAG1: %s", data["flag1"])

    reseau = Reseau(data["host"], data["port"], data["key"])
    reseau.connecter()
    flag_final = reseau.jouer()
    reseau.fermer()
    logger.info("FLAG_FINAL: %s", flag_final)


def main(argv=None):
    args = parse_args(argv)
    run(args.target)


if __name__ == "__main__":
    main()
