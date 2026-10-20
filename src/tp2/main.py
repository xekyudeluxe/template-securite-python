import argparse
from pathlib import Path

from tp2.utils.analyse import (
    base_score,
    extract_flag,
    extract_iocs,
    find_apis,
    get_file_metadata,
    guess_family,
    guess_mitre,
    load_rules,
    parse_binary,
    yara_scan,
)
from tp2.utils.config import logger
from tp2.utils.llm import LLMClient, llm_triage
from tp2.utils.report import generate_report

IOC_KEYS = ["domains", "ips", "urls", "mutex", "registry"]


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Triage de malware")
    parser.add_argument("--samples", required=True)
    parser.add_argument("--rules", required=True)
    parser.add_argument("--out", required=True)
    return parser.parse_args(argv)


def combine_score(score, llm_score):
    """Le LLM peut ajuster le score de 2 points maximum : il ne décide jamais seul."""
    if llm_score is None:
        return score
    return max(0, min(10, max(score - 2, min(score + 2, llm_score))))


def analyze_file(path, rules, client):
    data = path.read_bytes()
    meta = get_file_metadata(data)
    iocs = {key: value for key, value in extract_iocs(data).items() if key in IOC_KEYS}
    apis = find_apis(data)
    yara_matches = yara_scan(data, rules)
    family = guess_family(apis, meta["entropy"])
    mitre = guess_mitre(iocs, family, meta["entropy"])
    score = base_score(iocs, apis, yara_matches, meta["entropy"])

    summary = {"entropy": meta["entropy"], "iocs": iocs, "apis": apis, "yara": yara_matches, "family": family}
    verdict = llm_triage(summary, client)
    llm_summary = f"Famille probable : {family}. Règles YARA : {', '.join(yara_matches) or 'aucune'}."
    if verdict:
        mitre = list(dict.fromkeys(mitre + verdict["mitre_attack"]))
        score = combine_score(score, verdict["score"])
        llm_summary = verdict["summary"] or llm_summary

    return {
        **meta,
        "iocs": iocs,
        "imports": apis + parse_binary(path)["imports"],
        "yara_matches": yara_matches,
        "family_guess": family,
        "mitre_attack": mitre,
        "llm_summary": llm_summary,
        "score": score,
        "flag": extract_flag(data),
    }


def main(argv=None):
    args = parse_args(argv)
    rules = load_rules(args.rules)
    client = LLMClient()
    results = []
    for path in sorted(Path(args.samples).iterdir()):
        if path.is_file():
            logger.info("Analyse de %s", path.name)
            results.append(analyze_file(path, rules, client))
    generate_report(results, args.out)
    logger.info("%d rapport(s) dans %s", len(results), args.out)


if __name__ == "__main__":
    main()