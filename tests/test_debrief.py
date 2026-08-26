from __future__ import annotations

from datetime import datetime, timedelta, timezone

from core.debrief import (
    ApiDebriefSource,
    DebriefEngine,
    KILL_CHAIN,
    LocalDebriefSource,
    run_debrief,
)
from knowledge.sentryguard import SentryGuardIndex
from models.session import SessionCreate


def _dt(offset_seconds: int) -> datetime:
    return datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)


def _session(start: datetime) -> dict:
    return {"id": "sess-1", "created_at": start.isoformat()}


def _alert(
    rule_id: str,
    rule_name: str,
    techniques: list[str],
    seconds: int,
    start: datetime,
    status: str = "open",
) -> dict:
    return {
        "id": f"a-{rule_id}",
        "rule_id": rule_id,
        "rule_name": rule_name,
        "title": rule_name,
        "detail": "",
        "severity": "high",
        "status": status,
        "host": "app.lab.local",
        "technique_ids": techniques,
        "occurrences": 1,
        "event_time": _dt(seconds).isoformat(),
        "created_at": _dt(seconds).isoformat(),
    }


def _result(result_id: str, command: str, start: datetime) -> dict:
    return {
        "id": result_id,
        "session_id": "sess-1",
        "tool": "shell",
        "command": command,
        "stdout": "",
        "stderr": "",
        "exit_code": 0,
        "parsed": {},
        "created_at": start.isoformat(),
    }


def test_kill_chain_ordering():
    ids = [step["id"] for step in KILL_CHAIN]
    assert ids.index("acceso") < ids.index("lpe") < ids.index("credenciales") < ids.index("lateral")


def test_analyze_correlates_alerts_by_kill_chain_step():
    start = _dt(0).replace(microsecond=0)
    alerts = [
        _alert("SIGMA-0002", "Webshell Upload / Web Shell Activity", ["T1505.003"], 10, start),
        _alert("SIGMA-0007", "Privilege Escalation (UAC / EOP)", ["T1548"], 42, start),
        _alert("SIGMA-0001", "Credential Dump (LSASS access)", ["T1003"], 90, start),
    ]
    analysis = DebriefEngine().analyze(_session(start), alerts, [], source="local")

    assert analysis["first_detection"]["step_id"] == "acceso"
    assert analysis["first_detection"]["seconds"] == 10
    assert analysis["first_detection"]["label"] == "Acceso inicial"
    assert "Te detectaron en el paso acceso" in analysis["summary"]
    assert "a los 10 segundos" in analysis["summary"]

    steps = {s["step_id"]: s for s in analysis["steps"]}
    assert steps["lpe"]["detected"]
    assert steps["lpe"]["first_detection_seconds"] == 42
    assert steps["lpe"]["first_rule_name"] == "Privilege Escalation (UAC / EOP)"
    assert steps["acceso"]["techniques"] == ["T1505.003"]
    assert not steps["lateral"]["detected"]
    assert analysis["total_alerts"] == 3
    assert analysis["detected_steps"] == 3

    transitions = analysis["transitions"]
    assert transitions[0]["from_step"] == "acceso"
    assert transitions[0]["to_step"] == "lpe"
    assert transitions[0]["delta_seconds"] == 32


def test_analyze_no_detections():
    start = _dt(0).replace(microsecond=0)
    analysis = DebriefEngine().analyze(_session(start), [], [], source="local")
    assert analysis["total_alerts"] == 0
    assert analysis["first_detection"] is None
    assert analysis["summary"] == "Sin detecciones: la operacion no fue detectada por el equipo azul."


def test_classify_fallback_by_keyword():
    start = _dt(0).replace(microsecond=0)
    manual = {
        "id": "a-manual",
        "rule_id": "custom",
        "rule_name": "Brute Force Detected",
        "title": "Brute Force Detected",
        "detail": "",
        "severity": "medium",
        "status": "open",
        "host": None,
        "technique_ids": [],
        "occurrences": 1,
        "event_time": _dt(20).isoformat(),
        "created_at": _dt(20).isoformat(),
    }
    analysis = DebriefEngine().analyze(_session(start), [manual], [], source="local")
    steps = {s["step_id"]: s for s in analysis["steps"]}
    assert steps["credenciales"]["detected"]


def test_suggestions_from_detections():
    start = _dt(0).replace(microsecond=0)
    alerts = [
        _alert("SIGMA-0004", "C2 Beaconing Pattern", ["T1071"], 10, start),
        _alert("SIGMA-0001", "Credential Dump (LSASS access)", ["T1003"], 90, start),
    ]
    analysis = DebriefEngine().analyze(_session(start), alerts, [], source="local")
    suggestions = DebriefEngine().suggestions(analysis)
    ids = [s["suggestion"] for s in suggestions]

    assert "SUG-0001" in ids
    assert "SUG-0002" in ids
    assert "SUG-0003" in ids
    assert "SUG-0009" in ids

    jitter = next(s for s in suggestions if s["suggestion"] == "SUG-0001")
    assert jitter["parameters"]["jitter"] == 45
    assert "C2 Beaconing Pattern" in jitter["triggered_by"]


def test_seed_contains_c2dect_profile_and_cyberlens_rules():
    start = _dt(0).replace(microsecond=0)
    alerts = [
        _alert("SIGMA-0004", "C2 Beaconing Pattern", ["T1071"], 10, start),
        _alert("SIGMA-0001", "Credential Dump (LSASS access)", ["T1003"], 90, start),
    ]
    analysis = DebriefEngine().analyze(_session(start), alerts, [], source="local")
    engine = DebriefEngine()
    seed = engine.build_seed(analysis, engine.suggestions(analysis))

    profile = seed["c2_dect"]["profile"]
    assert profile["jitter"] == 45
    assert profile["default_sleep"] == 45
    assert "channel" in seed["c2_dect"]["profile"]
    assert seed["cyberlens"]["focus_steps"]
    rule_ids = [r["id"] for r in seed["cyberlens"]["rules"]]
    assert "SIGMA-0001" in rule_ids
    assert "SIGMA-0004" in rule_ids
    sigma1 = next(r for r in seed["cyberlens"]["rules"] if r["id"] == "SIGMA-0001")
    assert sigma1["patterns"]
    assert sigma1["patterns"]["command"]


def test_report_mentions_step_event_and_seconds():
    start = _dt(0).replace(microsecond=0)
    alerts = [
        _alert("SIGMA-0007", "Privilege Escalation (UAC / EOP)", ["T1548"], 42, start),
    ]
    analysis = DebriefEngine().analyze(_session(start), alerts, [], source="local")
    report = DebriefEngine().report(analysis)
    assert "Paso" in report
    assert "lpe" in report
    assert "Privilege Escalation (UAC / EOP)" in report
    assert "42s" in report


def test_evidence_from_results():
    start = _dt(0).replace(microsecond=0)
    result = _result("res-1", "mimikatz sekurlsa::logonpasswords", start)
    alert = _alert("SIGMA-0001", "Credential Dump (LSASS access)", ["T1003"], 90, start)
    alert["evidence_result_id"] = "res-1"
    analysis = DebriefEngine().analyze(_session(start), [alert], [result], source="local")
    steps = {s["step_id"]: s for s in analysis["steps"]}
    event = steps["credenciales"]["events"][0]
    assert event["evidence"] == "mimikatz sekurlsa::logonpasswords"


def test_local_source_roundtrip(mediator, session):
    start = _dt(0).replace(microsecond=0)
    blue = mediator.create_session(
        SessionCreate(
            target_id=session.target_id, team="blue", objective="detectar"
        )
    )
    mediator.ingest_event(blue.id, "process", "mimikatz sekurlsa::logonpasswords")
    analysis = run_debrief(LocalDebriefSource(mediator), blue.id)
    assert analysis["source"] == "local"
    assert analysis["total_alerts"] >= 1
    assert analysis["first_detection"]["step_id"] == "credenciales"
    assert analysis["first_detection"]["rule_name"] == "Credential Dump (LSASS access)"


def test_sentryguard_index_from_rules_dir():
    index = SentryGuardIndex()
    loaded = index.load_dir("../SentryGuard/src/SentryGuard.Rules/Rules/JSON")
    if loaded.rule_count == 0:
        return
    rules = index.rules_for(["T1003"])
    assert isinstance(rules, list)


def test_api_source_methods():
    source = ApiDebriefSource(object())
    assert hasattr(source, "fetch")


def test_debrief_via_mediator(mediator, session):
    blue = mediator.create_session(
        SessionCreate(
            target_id=session.target_id, team="blue", objective="detectar"
        )
    )
    mediator.ingest_event(blue.id, "network", "GET /a1b2c3d4.php HTTP/1.1")
    analysis = mediator.debrief(blue.id)
    assert analysis["total_alerts"] >= 1
    assert analysis["summary"]

    suggestions = mediator.debrief_suggestions(blue.id)
    assert isinstance(suggestions, list)

    seed = mediator.debrief_seed(blue.id)
    assert seed["c2_dect"]["profile"]
    assert seed["source_session_id"] == blue.id

    report = mediator.debrief_report(blue.id)
    assert report.startswith("#")