import hashlib
import ipaddress
import math
import re
from pathlib import Path

import lief
import magic
import yara

lief.logging.disable()

TLDS = ["com", "net", "org", "info", "biz", "io", "co", "me", "xyz", "top", "site", "online",
        "ru", "su", "cn", "de", "fr", "uk", "eu", "nl", "us", "ro", "ua", "onion", "test", "local"]

# domaines normaux qu'on retrouve dans les binaires linux (aide de coreutils)
DOMAINES_OK = ["gnu.org", "www.gnu.org", "translationproject.org", "microsoft.com"]

APIS = {
    "keylogger": ["SetWindowsHookExA", "GetAsyncKeyState", "GetKeyState"],
    "dropper": ["URLDownloadToFileA", "WinExec", "ShellExecuteA"],
    "backdoor": ["WSASocketA", "WSAStartup", "connect", "recv"],
    "injector": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
    "trojan": ["CreateProcessA", "RegSetValueExA"],
}


def entropy(data):
    if len(data) == 0:
        return 0.0
    compte = [0] * 256
    for octet in data:
        compte[octet] += 1
    res = 0.0
    for c in compte:
        if c > 0:
            p = c / len(data)
            res -= p * math.log2(p)
    return res


def get_file_metadata(data):
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
        "size": len(data),
        "entropy": round(entropy(data), 2),
        "file_type": magic.from_buffer(data),
    }


def get_strings(data):
    # comme la commande strings : suites de caracteres lisibles (5 min)
    return [s.decode() for s in re.findall(rb"[\x20-\x7e]{5,}", data)]


def find_domains(texte):
    res = []
    for m in re.finditer(r"\b(?:[a-z0-9-]+\.)+([a-z]{2,24})\b", texte, re.IGNORECASE):
        domaine = m.group(0).lower()
        # si il y a un point juste avant c'est une section elf (.gnu.hash...)
        if m.start() > 0 and texte[m.start() - 1] == ".":
            continue
        # cmd.exe, ws2_32.dll, gate.php... ne sont pas des domaines
        if m.group(1).lower() not in TLDS:
            continue
        if domaine in DOMAINES_OK:
            continue
        res.append(domaine)
    return res


def extract_iocs(data):
    iocs = {"domains": [], "ips": [], "urls": [], "mutex": [], "registry": [], "paths": []}
    for s in get_strings(data):
        iocs["domains"] += find_domains(s)

        for url in re.findall(r"https?://[^\s\"'<>]+", s):
            if not any(d in url for d in DOMAINES_OK):
                iocs["urls"].append(url)

        for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", s):
            try:
                ipaddress.IPv4Address(ip)
                iocs["ips"].append(ip)
            except ValueError:
                pass  # ex: 999.1.1.1

        iocs["mutex"] += re.findall(r"\b(?:Global|Local)\\[\w.-]+", s)
        iocs["registry"] += re.findall(r"\b(?:HKCU|HKLM|HKEY_[A-Z_]+)\\[^\s\"'<>]+", s)
        iocs["paths"] += re.findall(r"\b[A-Za-z]:\\[^\s\"'<>|]+", s)

    # enlever les doublons
    for cle in iocs:
        iocs[cle] = list(dict.fromkeys(iocs[cle]))
    return iocs


def extract_flag(data):
    # on prend seulement le flag apres FLAG= (les autres ESGI{} sont des pieges)
    m = re.search(r"FLAG=(ESGI\{[^}\s]+\})", data.decode("latin-1"))
    if m:
        return m.group(1)
    return ""


def find_apis(data):
    mots = re.split(rb"[\x00\n]", data)
    trouvees = []
    for famille in APIS:
        for api in APIS[famille]:
            if api.encode() in mots:
                trouvees.append(api)
    return trouvees


def parse_binary(path):
    binaire = lief.parse(str(path))
    if binaire is None:
        return {"imports": [], "exports": [], "sections": []}
    imports = [f.name for f in binaire.imported_functions if f.name]
    exports = [f.name for f in binaire.exported_functions if f.name]
    sections = [s.name for s in binaire.sections if s.name]
    return {"imports": sorted(set(imports)), "exports": sorted(set(exports)), "sections": sections}


def load_rules(dossier):
    fichiers = list(Path(dossier).glob("*.yar")) + list(Path(dossier).glob("*.yara"))
    if len(fichiers) == 0:
        return None
    return yara.compile(filepaths={f.stem: str(f) for f in fichiers})


def yara_scan(data, rules):
    if rules is None:
        return []
    noms = [m.rule for m in rules.match(data=data)]
    return sorted(set(noms))


def guess_family(apis, ent):
    for famille in APIS:
        for api in apis:
            if api in APIS[famille]:
                return famille
    if ent >= 7.0:
        return "packed"
    return "unknown"


def guess_mitre(iocs, famille, ent):
    mitre = []
    if iocs["urls"] or iocs["domains"] or iocs["ips"]:
        mitre.append("T1071")  # C2
    if iocs["registry"]:
        mitre.append("T1547")  # persistance cle Run
    if famille == "dropper":
        mitre.append("T1105")
    elif famille == "keylogger":
        mitre.append("T1056")
    elif famille == "injector":
        mitre.append("T1055")
    elif famille == "trojan":
        mitre.append("T1059")
    if ent >= 7.0:
        mitre.append("T1027")  # packing
    return mitre


def base_score(iocs, apis, yara_matches, ent):
    score = 0
    if iocs["urls"] or iocs["domains"] or iocs["ips"]:
        score += 2
    if iocs["registry"]:
        score += 2
    if iocs["mutex"]:
        score += 1
    if apis:
        score += 2
    if ent >= 7.0:
        score += 2
    score += min(len(yara_matches), 3)
    return min(score, 10)