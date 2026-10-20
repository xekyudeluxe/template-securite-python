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

    def sort_network_protocols(self) -> str:
        """
        Sort and return all captured network protocols
        """
        pairs = list(self.protocols.items())
        pairs.sort(key=lambda p: p[1], reverse=True)

        texte = ""
        for nom, nombre in pairs:
            texte += f"{nom} : {nombre}\n"
        return texte

    def detect_arp_spoofing(self) -> None:
        """
        ARP spoofing = plusieurs adresses MAC pour une meme IP.
        """
        ip_vers_mac = {}
        for pkt in self.packets:
            if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # 2 = reponse ARP
                ip = pkt[ARP].psrc
                mac = pkt[ARP].hwsrc
                if ip not in ip_vers_mac:
                    ip_vers_mac[ip] = []
                if mac not in ip_vers_mac[ip]:
                    ip_vers_mac[ip].append(mac)

        for ip in ip_vers_mac:
            if len(ip_vers_mac[ip]) > 1:
                attaquant = ip_vers_mac[ip][-1]
                self.attacks.append({"type": "arp_spoofing", "attacker": attaquant})
                logger.warning(f"ARP spoofing : IP {ip}")

    def detect_port_scan(self) -> None:
        """
        Scan de ports = une IP envoie des SYN vers beaucoup de ports differents.
        """
        ports_par_ip = {}
        for pkt in self.packets:
            if pkt.haslayer(TCP) and pkt.haslayer(IP):
                if pkt[TCP].flags == "S":  # SYN seul = tentative de connexion
                    src = pkt[IP].src
                    port = pkt[TCP].dport
                    if src not in ports_par_ip:
                        ports_par_ip[src] = []
                    if port not in ports_par_ip[src]:
                        ports_par_ip[src].append(port)

        for src in ports_par_ip:
            if len(ports_par_ip[src]) > 20:
                self.attacks.append({"type": "port_scan", "attacker": src})
                logger.warning(f"Scan de ports depuis {src}")

    def detect_sql_injection(self) -> None:
        """
        Injection SQL = motifs suspects dans le trafic (' OR 1=1, UNION SELECT...).
        """
        motifs = ["or 1=1", "union select", "'1'='1"]
        deja_vus = []
        for pkt in self.packets:
            if not pkt.haslayer(Raw):
                continue

            brut = bytes(pkt[Raw].load)
            texte = brut.decode(errors="ignore")
            texte = texte.lower()

            for motif in motifs:
                if motif in texte:
                    if pkt.haslayer(IP):
                        attaquant = pkt[IP].src
                    else:
                        attaquant = "inconnu"
                    if attaquant not in deja_vus:
                        deja_vus.append(attaquant)
                        self.attacks.append({"type": "sql_injection", "attacker": attaquant})
                        logger.warning(f"Injection SQL depuis {attaquant}")
                    break

    def find_flag(self) -> None:
        """
        Cherche le flag ESGI{...} cache dans les paquets.
        """
        for pkt in self.packets:
            data = bytes(pkt)
            if b"ESGI{" in data:
                debut = data.find(b"ESGI{")
                fin = data.find(b"}", debut) + 1
                self.flag = data[debut:fin].decode(errors="ignore")
                logger.info(f"Flag trouve : {self.flag}")
                return

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
        self.detect_arp_spoofing()
        self.detect_port_scan()
        self.detect_sql_injection()
        self.find_flag()

        if not self.attacks:
            logger.info("Aucune attaque detectee, tout va bien.")

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
        summary += "Protocoles :\n"
        summary += self.sort_network_protocols()
        summary += "\nAttaques :\n"
        if self.attacks:
            for a in self.attacks:
                summary += f"- {a['type']} depuis {a['attacker']}\n"
        else:
            summary += "Aucune attaque.\n"
        if self.flag:
            summary += f"\nFlag : {self.flag}\n"
        return summary
