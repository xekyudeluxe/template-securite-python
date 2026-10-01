from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, Ether, Raw, rdpcap, sniff
from src.tp1.utils.lib import choose_interface
from tp1.utils.config import logger


class Capture:
    def __init__(self, pcap=None) -> None:
        self.pcap = pcap
        self.packets = []
        self.protocols = {}
        self.attacks = []
        self.flag = ""
        self.summary = ""

        # Si on a un fichier pcap, pas besoin de choisir une interface.
        if pcap:
            self.interface = None
        else:
            self.interface = choose_interface()

    def capture_traffic(self) -> None:
        """
        Capture le trafic reseau, ou lit un fichier pcap.
        """
        if self.pcap:
            logger.info(f"Lecture du fichier {self.pcap}")
            self.packets = rdpcap(self.pcap)
        else:
            logger.info(f"Capture sur {self.interface} pendant 30 secondes")
            self.packets = sniff(iface=self.interface, timeout=30)

        logger.info(f"{len(self.packets)} paquets captures")
    def sort_network_protocols(self) -> str:
        """
        Sort and return all captured network protocols
        """
        return ""

    def add_one(self, nom) -> None:
        """
        Ajoute 1 au compteur d'un protocole.
        """
        if nom in self.protocols:
            self.protocols[nom] += 1
        else:
            self.protocols[nom] = 1

    def get_all_protocols(self) -> str:
        """
        Compte tous les protocoles et renvoie un texte recapitulatif.
        """
        for pkt in self.packets:
            if pkt.haslayer(Ether):
                self.add_one("Ethernet")
            if pkt.haslayer(ARP):
                self.add_one("ARP")
            if pkt.haslayer(IP):
                self.add_one("IP")
            if pkt.haslayer(TCP):
                self.add_one("TCP")
            if pkt.haslayer(UDP):
                self.add_one("UDP")
            if pkt.haslayer(ICMP):
                self.add_one("ICMP")
            if pkt.haslayer(DNS):
                self.add_one("DNS")
            if pkt.haslayer(TCP) and (pkt[TCP].dport == 80 or pkt[TCP].sport == 80):
                self.add_one("HTTP")

        logger.info(f"Protocoles : {self.protocols}")

        texte = ""
        for nom in self.protocols:
            texte += f"{nom} : {self.protocols[nom]}\n"
        return texte


    def analyse(self, protocols: str) -> None:
        """
        Analyse all captured data and return statement
        Si un tra c est illégitime (exemple : Injection SQL, ARP
        Spoo ng, etc)
        a Noter la tentative d'attaque.
        b Relever le protocole ainsi que l'adresse réseau/physique
        de l'attaquant.
        c (FACULTATIF) Opérer le blocage de la machine
        attaquante.
        Sinon a cher que tout va bien
        """
        all_protocols = self.get_all_protocols()
        sort = self.sort_network_protocols()
        logger.debug(f"All protocols: {all_protocols}")
        logger.debug(f"Sorted protocols: {sort}")

        self.summary = self._gen_summary()

    def get_summary(self) -> str:
        """
        Return summary
        :return:
        """
        return self.summary

    def _gen_summary(self) -> str:
        """
        Generate summary
        """
        summary = ""
        return summary
