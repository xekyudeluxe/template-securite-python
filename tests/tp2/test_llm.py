import json

import requests
from tp2.utils.llm import LLMClient, llm_triage, parse_llm_answer


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self.payload


def test_llmclient_without_key(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("LLM_BACKEND", raising=False)
    client = LLMClient()
    assert client.backend == "none"
    assert client.ask("s", "u") is None


def test_llmclient_openrouter(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "cle-test")
    payload = {"choices": [{"message": {"content": "ok"}}]}
    monkeypatch.setattr(requests, "post", lambda *a, **k: FakeResponse(payload))
    assert LLMClient("openrouter").ask("s", "u") == "ok"


def test_llmclient_ollama(monkeypatch):
    monkeypatch.setattr(requests, "post", lambda *a, **k: FakeResponse({"message": {"content": "ok"}}))
    assert LLMClient("ollama").ask("s", "u") == "ok"


def test_llmclient_network_error(monkeypatch):
    def no_network(*args, **kwargs):
        raise requests.ConnectionError()

    monkeypatch.setattr(requests, "post", no_network)
    assert LLMClient("ollama").ask("s", "u") is None


def test_parse_llm_answer():
    text = 'Voici : {"family": "Dropper", "mitre_attack": ["T1105", "faux"], "score": 15, "summary": "flag ESGI{x}"}'
    answer = parse_llm_answer(text)
    assert answer["family"] == "dropper"
    assert answer["mitre_attack"] == ["T1105"]
    assert answer["score"] == 10
    assert "ESGI{" not in answer["summary"]
    assert parse_llm_answer(None) is None
    assert parse_llm_answer("{cassé") is None
    assert parse_llm_answer('{"score": "dix"}') is None


def test_llm_triage(fake_llm):
    verdict = llm_triage({"ips": []}, fake_llm(json.dumps({"score": 3, "summary": "ok"})))
    assert verdict["score"] == 3