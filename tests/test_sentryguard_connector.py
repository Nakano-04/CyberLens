import json
import os

from providers.sentryguard_connector import SentryGuardConnector, import_sentryguard_rules


def test_poll_dedup(monkeypatch):
    from core.mediator import Mediator
    from models.session import SessionCreate
    from models.target import TargetCreate
    from models.team import Team

    m = Mediator(command_timeout=10)
    t = m.create_target(TargetCreate(host="app.test-lab.com", assessment="web"))
    s = m.create_session(SessionCreate(target_id=t.id, agent="blue", objective="test", team=Team.BLUE))
    events = [
        {"event_id": "evt-1", "source": "sentryguard", "stdout": "mimikatz sekurlsa::logonpasswords"},
        {"event_id": "evt-1", "source": "sentryguard", "stdout": "mimikatz dup"},
        {"event_id": "evt-2", "source": "sentryguard", "stdout": "normal event"},
    ]

    class FakeResp:
        def raise_for_status(self): pass
        def json(self): return events

    import requests as _req

    monkeypatch.setattr(_req, "get", lambda url, timeout=10: FakeResp())
    c = SentryGuardConnector("http://dummy.local", timeout=10)
    first = c.poll(s.id, m)
    assert len(first) == 2
    assert "evt-1" in c._seen and "evt-2" in c._seen
    second = c.poll(s.id, m)
    assert len(second) == 0


def test_import_sentryguard_rules(tmp_path):
    data = {"id": "SG-0001", "name": "Test Rule", "severity": "high", "patterns": {"stdout": ["mimikatz"]}, "technique_ids": ["T1003"]}
    p = tmp_path / "rule.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    rules = import_sentryguard_rules(str(tmp_path))
    assert len(rules) == 1
    assert rules[0].name == "Test Rule"
    assert rules[0].severity.value == "high"
    assert not import_sentryguard_rules("/nonexistent/dir")
