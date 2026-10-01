from unittest.mock import patch

from src.tp1.utils.lib import choose_interface, hello_world


def test_hello_world():
    # When
    result = hello_world()

    # Then
    assert result == "hello world"


def test_choose_interface():
    #on simule la liste des interfaces et le choix de l'utilisateur
    with patch("src.tp1.utils.lib.get_if_list", return_value=["eth0", "wlan0"]):
        with patch("builtins.input", return_value="0"):
            # When
            result = choose_interface()

    #on a choisi le numero 0, donc eth0
    assert result == "eth0"