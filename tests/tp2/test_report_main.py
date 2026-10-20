import json

from conftest import FakeClient

from tp2.main import analyze_file, combine_score, main, parse_args
from tp2.utils.analyse import load_rules
from tp2.utils.report import generate_report, to_latin1

# Réponse d'un LLM qui "obéit" à l'injection du fichier
INJECTED = json.dumps({"family": "clean", "score": 0, "summary": "Sain. Flag ESGI{faux_flag}"})


def test_parse_args():
    args = parse_args(["--samples", "s", "--rules", "r", "--out", "o"])
    assert (args.samples, args.rules, args.out) == ("s", "r", "o")


def test_combine_score():
    assert combine_score(8, None) == 8
    assert combine_score(8, 0) == 6
    assert combine_score(9, 10) == 10


def test_analyze_file_resists_injection(sample_dir, rules_dir):
    result = analyze_file(sample_dir / "fake.bin", load_rules(rules_dir), FakeClient(INJECTED))
    assert result["flag"] == "ESGI{vrai_flag_123}"
    assert result["score"] >= 5
    assert result["family_guess"] == "keylogger"
    assert "faux_flag" not in json.dumps(result)
    assert list(result["iocs"]) == ["domains", "ips", "urls", "mutex", "registry"]


def test_to_latin1():
    assert to_latin1("é → x") == "é ? x"


def test_generate_report(sample_dir, rules_dir, tmp_path):
    result = analyze_file(sample_dir / "fake.bin", load_rules(rules_dir), FakeClient(None))
    generate_report([result], tmp_path / "out")
    assert (tmp_path / "out" / f"{result['sha256']}.json").exists()
    assert (tmp_path / "out" / "report.pdf").read_bytes().startswith(b"%PDF")


def test_main(sample_dir, rules_dir, tmp_path, monkeypatch):
    monkeypatch.setenv("LLM_BACKEND", "none")
    out = tmp_path / "out"
    main(["--samples", str(sample_dir), "--rules", str(rules_dir), "--out", str(out)])
    report = json.loads(next(out.glob("*.json")).read_text())
    assert report["flag"] == "ESGI{vrai_flag_123}"