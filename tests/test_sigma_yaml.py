import os

from tools.sigma_yaml import load_sigma_yaml


def test_load_sigma_yaml(tmp_path):
    content = "- title: Test Sigma Rule\n  level: high\n  detection:\n    selection:\n      keywords: ['mimikatz']\n  tags: ['attack.t1003']\n"
    p = tmp_path / "rule.yaml"
    p.write_text(content, encoding="utf-8")
    rules = load_sigma_yaml(str(p))
    assert len(rules) == 1
    assert rules[0]["name"] == "Test Sigma Rule"
    assert rules[0]["severity"] == "high"
    assert rules[0]["pattern_stdout"] == "mimikatz"


def test_load_yaml_rules_appends(tmp_path):
    from knowledge.detection import RULES, load_yaml_rules
    before = len(RULES)
    content = "- title: Yaml Append Rule\n  level: medium\n  detection:\n    selection:\n      keywords: ['boom42']\n"
    p = tmp_path / "append.yaml"
    p.write_text(content, encoding="utf-8")
    loaded = load_yaml_rules(str(p))
    assert len(loaded) == 1
    assert len(RULES) == before + 1
    assert any(r["name"] == "Yaml Append Rule" for r in RULES)
    RULES.pop()
