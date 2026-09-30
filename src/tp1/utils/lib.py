from scapy.all import get_if_list

from tp1.utils.config import logger


def choose_interface() -> str:
    """
    Affiche les interfaces reseau et demande d'en choisir une.
    """
    interfaces = get_if_list()

    print("Interfaces disponibles :")
    for i in range(len(interfaces)):
        print(i, "->", interfaces[i])

    num = int(input("Choisis une interface (numero) : "))
    interface = interfaces[num]

    logger.info(f"Interface choisie : {interface}")
    return interface