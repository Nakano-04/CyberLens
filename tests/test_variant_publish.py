from pathlib import Path

from tools.variant_publish import build_variant_doc, calc_evasion_score, feedback_remutate, list_elite_variants, upsert_variant


def test_calc_evasion():
    base = b"A" * 100
    var = b"B" * 100
    score = calc_evasion_score(var, base)
    assert 50 < score <= 99


def test_build_doc():
    doc = build_variant_doc("a1b2c3", "parent123", {"xor_key": 0x5A, "spray_count": 16, "detection_evasion_score": 92})
    assert doc["sha256"] == "a1b2c3"
    assert doc["status"] == "ELITE"
    assert doc["sigma_mapping"] == ["T1210", "T1203"]


def test_upsert_and_list(tmp_path):
    store = tmp_path / "store.json"
    doc = build_variant_doc("sha1", "parent", {"xor_key": 1, "detection_evasion_score": 90})
    upsert_variant(doc, store)
    doc2 = build_variant_doc("sha2", "parent", {"xor_key": 2, "detection_evasion_score": 95})
    upsert_variant(doc2, store)
    elites = list_elite_variants(store, limit=5)
    assert len(elites) == 2
    assert elites[0]["sha256"] == "sha2"


def test_feedback(tmp_path):
    store = tmp_path / "store.json"
    doc = build_variant_doc("base", "parent", {"xor_key": 1, "trans2_size": 0x10001, "detection_evasion_score": 90})
    upsert_variant(doc, store)
    res = feedback_remutate("base", {"rop_offset": 0x10}, store)
    assert "new_sha" in res
    assert res["next_phase"] == "B4"
