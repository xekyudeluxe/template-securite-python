import argparse

from tp1.utils.capture import Capture
from tp1.utils.config import logger
from tp1.utils.report import Report


def main():
    parser = argparse.ArgumentParser(description="TP1 - IDS/IPS maison")
    parser.add_argument("fichier", nargs="?", help="Fichier pcap a analyser")
    parser.add_argument("--pcap", help="Fichier pcap a analyser")
    parser.add_argument("--iface", help="Interface reseau (capture live)")
    parser.add_argument("--out", default="report.json", help="Fichier JSON de sortie")
    args = parser.parse_args()

    logger.info("Starting TP1")

    # Le fichier peut etre donne en positionnel ou avec --pcap
    pcap = args.pcap or args.fichier
    capture = Capture(pcap)
    capture.capture_traffic()
    capture.analyse("tcp")
    summary = capture.get_summary()

    filename = "report.pdf"
    report = Report(capture, filename, summary)
    report.generate("graph")
    report.generate("array")
    report.save(filename)
    report.write_json(args.out)

    logger.info("Termine")


if __name__ == "__main__":
    main()