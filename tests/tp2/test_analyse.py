import os
import sys
from pathlib import Path

from conftest import FAKE_SAMPLE

from tp2.utils.analyse import (
    base_score,
    entropy,
    extract_flag,
    extract_iocs,
    find_apis,
    find_domains,
    get_file_metadata,
    get_strings,
    guess_family,
    guess_mitre,
    load_rules,
    parse_binary,
    yara_scan,
)

NO_IOC = {"domains": [], "ips": [], "urls": [], "mutex": [], "registry": []}


def test_entropy():
    assert entropy(b"") == 0.0
    assert entropy(b"aaaa") == 0.0
    assert entropy(b"ab") == 1.0


def test_get_file_metadata():
    meta = get_file_metadata(b"abc")
    assert meta["sha256"].startswith("ba7816bf")
    assert meta["md5"] == "900150983cd24fb0d6963f7d28e17f72"
    assert meta["size"] == 3
    assert meta["entropy"] == 1.58
    assert "text" in meta["file_type"].lower()


def test_get_strings():
    assert get_strings(b"\x00\x01hello world\x00ab\x00") == ["hello world"]


def test_find_domains():
    assert find_domains("evil.example.test") == ["evil.example.test"]
    assert find_domains("ws2_32.dll cmd.exe gate.php .gnu.hash www.gnu.org") == []


def test_extract_iocs():
    iocs = extract_iocs(FAKE_SAMPLE + b"\x00999.1.1.1\x00")
    assert iocs["domains"] == ["evil-c2.example.test"]
    assert iocs["ips"] == ["203.0.113.7"]
    assert iocs["urls"] == ["http://evil-c2.example.test/panel.php"]
    assert iocs["mutex"] == ["Global\\mutex42"]
    assert iocs["registry"] == ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\updater"]
    assert iocs["paths"] == ["C:\\Windows\\Temp\\a.exe"]


def test_extract_flag():
    assert extract_flag(FAKE_SAMPLE) == "ESGI{vrai_flag_123}"
    assert extract_flag(b"rien") == ""


def test_find_apis():
    assert find_apis(FAKE_SAMPLE) == ["SetWindowsHookExA", "GetAsyncKeyState"]
    assert find_apis(b"\x00disconnect\x00") == []


def test_parse_binary(tmp_path):
    assert parse_binary(os.path.realpath(sys.executable))["sections"]
    (tmp_path / "a.txt").write_text("pas un binaire")
    assert parse_binary(tmp_path / "a.txt") == {"imports": [], "exports": [], "sections": []}


def test_load_rules_and_yara_scan(rules_dir, tmp_path):
    rules = load_rules(rules_dir)
    assert yara_scan(FAKE_SAMPLE, rules) == ["Has_Mutex"]
    assert load_rules(tmp_path / "vide") is None
    assert yara_scan(FAKE_SAMPLE, None) == []


def test_custom_rules():
    rules = load_rules(Path(__file__).parent.parent / "rules")
    assert "Prompt_Injection_Attempt" in yara_scan(FAKE_SAMPLE, rules)
    assert "High_Entropy_Packed" in yara_scan(bytes(range(256)) * 50, rules)
    assert yara_scan(b"fichier normal", rules) == []


def test_guess_family():
    assert guess_family(["GetAsyncKeyState"], 4.0) == "keylogger"
    assert guess_family([], 7.5) == "packed"
    assert guess_family([], 4.0) == "unknown"


def test_guess_mitre():
    iocs = dict(NO_IOC, urls=["http://x.test/"], registry=["HKCU\\Run\\x"])
    assert guess_mitre(iocs, "dropper", 7.5) == ["T1071", "T1547", "T1105", "T1027"]
    assert guess_mitre(NO_IOC, "unknown", 4.0) == []


def test_base_score():
    assert base_score(NO_IOC, [], [], 4.0) == 0
    iocs = dict(NO_IOC, ips=["1.2.3.4"], registry=["HKCU\\x"], mutex=["Global\\m"])
    assert base_score(iocs, ["WinExec"], ["A", "B", "C"], 7.5) == 10