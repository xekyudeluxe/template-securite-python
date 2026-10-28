import argparse

from src.tp3.utils.config import logger
from src.tp3.utils.recherche import Recherche
from src.tp3.utils.reseau import Reseau
from src.tp3.utils.session import Session


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="TP3 - Breach the target")
    parser.add_argument("--target", required=True, help="ex: http://localhost:8080")
    return parser.parse_args(argv)

def main():
    logger.info("Starting TP3")

    ip = "31.220.95.27:9002"
    challenges = {"1": f"http://{ip}/captcha1/", "2": f"http://{ip}/captcha2/"}

    for i in challenges:
        url = challenges[i]
        session = Session(url)
        session.prepare_request()
        session.submit_request()

        while not session.process_response():
            session.prepare_request()
            session.submit_request()

        logger.info("Smell good !")
        logger.info(f"Flag for {url} : {session.get_flag()}")


if __name__ == "__main__":
    main()
