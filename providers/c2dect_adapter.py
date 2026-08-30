from __future__ import annotations

import json

_TECHNIQUE_MAP = {
    "heap-buffer-overflow": "T1203",
    "stack-buffer-overflow": "T1203",
    "use-after-free": "T1203",
    "format-string": "T1203",
    "heap overflow": "T1203",
    "sql-injection": "T1190",
    "command-injection": "T1059",
    "deserialization": "T1059",
    "privilege-escalation": "T1548",
    "privilege escalation": "T1548",
}

_CLASSIFICATION_MAP = {
    "exploit": "T1203",
    "c2": "T1071",
    "beacon": "T1071",
    "lateral movement": "T1021",
}


def adapt_exploit_finding(finding: dict) -> dict:
    """Mapea ExploitStrike bridge Finding -> CyberLens ToolResult/Node.

    Finding esperado: {signature, campaign_id, classification, cve, confidence, ...}
    Retorna {command, stdout, technique_id, confidence, ...}
    """
    signature = str(finding.get("signature") or finding.get("name") or finding.get("title") or "")
    campaign_id = str(finding.get("campaign_id") or finding.get("campaign") or "")
    classification = str(finding.get("classification") or finding.get("class") or "")
    cve = str(finding.get("cve") or finding.get("cve_id") or campaign_id or signature or "unknown")
    confidence = float(finding.get("confidence") or finding.get("score") or 0.8)
    technique_id = "T1203"
    hay = f"{signature} {classification}".lower()
    for key, tid in _TECHNIQUE_MAP.items():
        if key.lower() in hay:
            technique_id = tid
            break
    else:
        for key, tid in _CLASSIFICATION_MAP.items():
            if key.lower() in classification.lower():
                technique_id = tid
                break
        if "heap-buffer-overflow" in hay:
            technique_id = "T1203"
    return {
        "command": f"exploit {cve}",
        "stdout": json.dumps(finding, ensure_ascii=False),
        "technique_id": technique_id,
        "confidence": confidence,
        "signature": signature,
        "campaign_id": campaign_id,
        "classification": classification,
    }


def ingest_c2_event(session_id: str, c2_event: dict, mediator=None) -> dict:
    """Ingiere evento C2-DECT -> cyberlens_ingest_telemetry con source=c2dect."""
    adapted = adapt_exploit_finding(c2_event)
    if mediator is None:
        try:
            from mcp_server import _m

            mediator = _m()
        except Exception:
            from core.mediator import Mediator

            mediator = Mediator()
    try:
        result = mediator.ingest_event(session_id, "c2dect", adapted["stdout"], {"technique_id": adapted["technique_id"], "campaign_id": adapted.get("campaign_id"), "classification": adapted.get("classification")})
        return result.model_dump(mode="json") if hasattr(result, "model_dump") else {"source": "c2dect", "stdout": adapted["stdout"]}
    except Exception as exc:
        return {"error": str(exc), "source": "c2dect", "stdout": adapted["stdout"]}


def sync_weaponization(mediator_url: str, job: dict, intel: dict) -> dict:
    import requests as _req
    sha = job.get("sha256") or intel.get("sha256", "")[:64]
    if not sha:
        return {"error": "sin sha256"}
    payload = {"title": f"0-Day {job.get('target','')[-30:]}", "technique_id": "T1203", "sha256": sha, "confidence": 0.9, "evidence": {"job_id": job.get("id"), "sha256": sha, "feasibility": intel.get("feasibility", {}).get("feasibility_score")}}
    try:
        existing = _req.get(f"{mediator_url}/api/findings", params={"sha256": sha}, timeout=5).json()
        if isinstance(existing, dict) and existing.get("findings"):
            fid = existing["findings"][0].get("id")
            r = _req.patch(f"{mediator_url}/api/findings/{fid}", json=payload, timeout=5)
            return {"action": "updated", "id": fid, "status": r.status_code}
        r = _req.post(f"{mediator_url}/api/finding-add", json={"session_id": job.get("session_id", ""), **payload}, timeout=5)
        return {"action": "created", "status": r.status_code, "resp": r.text[:500]}
    except Exception as e:
        return {"error": str(e)[:500]}
