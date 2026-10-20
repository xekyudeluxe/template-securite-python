from scapy.all import get_if_list

from tp1.utils.config import logger


def hello_world() -> str:
    """
    Hello world function

    :return: "hello world"
    """
    return "hello world"


def choose_interface() -> str:
    """
    Affiche les interfaces reseau et demande d'en choisir une.
    """
    interfaces = get_if_list()

    logger.info("Interfaces disponibles :")
    for i in range(len(interfaces)):
        logger.info(f"{i} -> {interfaces[i]}")

    num = int(input("Choisis une interface (numero) : "))
    interface = interfaces[num]

    logger.info(f"Interface choisie : {interface}")
    return interface