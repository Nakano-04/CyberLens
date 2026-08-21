import pytest
from fastapi.testclient import TestClient

from api.server import create_app
from core.mediator import Mediator


@pytest.fixture
def client():
    m = Mediator(command_timeout=10)
    app = create_app(m)
    return TestClient(app), m


def _setup(client, m):
    t = client.post("/targets", json={"host": "app.test-lab.com", "assessment": "web"}).json()
    s = client.post("/sessions", json={"target_id": t["id"], "agent": "api-test"}).json()
    return t, s


def test_health(client):
    c, _ = client
    r = c.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_ciclo_vida_completo(client):
    c, m = client
    t, s = _setup(c, m)
    sid = s["id"]

    assert c.post(f"/sessions/{sid}/phase", json={"phase": "validation"}).status_code == 400
    for ph in ["enumeration", "modeling", "hypothesis"]:
        assert c.post(f"/sessions/{sid}/phase", json={"phase": ph}).status_code == 200

    r = c.post(
        f"/sessions/{sid}/execute",
        json={"tool": "shell", "command": "echo HTTP/1.1 200 OK welcome dashboard"},
    ).json()
    assert r["approved"]
    assert r["exit_code"] == 0

    f = c.post(
        f"/sessions/{sid}/findings",
        json={"title": "Broken auth", "confidence": 0.62, "evidence_ids": [r["id"]], "technique_id": "T1078"},
    ).json()
    assert f["verified"]

    assert c.post(f"/sessions/{sid}/phase", json={"phase": "validation"}).status_code == 200
    c.patch(f"/sessions/{sid}/findings/{f['id']}", json={"status": "validated"})
    assert c.post(f"/sessions/{sid}/phase", json={"phase": "impact"}).status_code == 200

    plan = c.get(f"/sessions/{sid}/plan").json()
    assert "branches" in plan
    report = c.get(f"/sessions/{sid}/report").json()["report"]
    assert "Hallazgos" in report
    report_html = c.get(f"/sessions/{sid}/report?format=html").json()["report"]
    assert "<table>" in report_html


def test_404s(client):
    c, _ = client
    assert c.get("/targets/nonexistent").status_code == 404
    assert c.get("/sessions/nonexistent/plan").status_code == 404


def test_errores_validacion(client):
    c, m = client
    t, s = _setup(c, m)
    r = c.post("/sessions/nonexistent/execute", json={"command": "ls"}).status_code
    assert r == 404


def test_scope_403_en_sesion_fuera_de_scope():
    m = Mediator(allowed_hosts=["solo-lab.com"], command_timeout=10)
    c = TestClient(create_app(m))
    t = c.post("/targets", json={"host": "app.test-lab.com", "assessment": "web"}).json()
    assert c.post("/sessions", json={"target_id": t["id"]}).status_code == 403


def test_audit_visible(client):
    c, m = client
    t, s = _setup(c, m)
    c.post(f"/sessions/{s['id']}/notes", json={"note": "nota de api"})
    audit = c.get("/audit").json()
    assert any("session.note" == e["action"] for e in audit)


def test_websocket_eventos(client):
    c, m = client
    t, s = _setup(c, m)
    with c.websocket_connect(f"/ws/sessions/{s['id']}") as ws:
        assert ws.receive_json()["type"] == "connected"
        c.post(
            f"/sessions/{s['id']}/execute",
            json={"tool": "shell", "command": "echo hola ws"},
        )
        assert ws.receive_json()["type"] == "tool.execute"


def test_websocket_sesion_inexistente(client):
    c, _ = client
    with c.websocket_connect("/ws/sessions/nope") as ws:
        assert ws.receive_json()["type"] == "error"


def test_auth_token_obligatorio():
    m = Mediator(command_timeout=10)
    c = TestClient(create_app(m, api_token="secret-token"))
    assert c.get("/health").status_code == 200
    assert c.get("/targets").status_code == 401
    assert c.get("/targets", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert c.get("/targets", headers={"Authorization": "Bearer secret-token"}).status_code == 200
    assert c.get("/targets", headers={"X-API-Key": "secret-token"}).status_code == 200

    with c.websocket_connect("/ws/sessions/x?token=secret-token") as ws:
        assert ws.receive_json()["type"] == "error"  # sesion no existe pero auth OK


def test_ws_risk_event():
    m = Mediator(command_timeout=10)
    c = TestClient(create_app(m))
    t = c.post("/targets", json={"host": "risk.test", "assessment": "web"}).json()
    s = c.post("/sessions", json={"target_id": t["id"]}).json()
    with c.websocket_connect(f"/ws/sessions/{s['id']}") as ws:
        ws.receive_json()
        # varias ejecuciones fallidas disparan riesgo medio/alto
        for i in range(4):
            c.post(
                f"/sessions/{s['id']}/execute",
                json={"command": f"exit 1 # fallo {i}"},
            )
        events = [ws.receive_json() for _ in range(4)]
        risk_events = [e for e in events if e["type"] == "metrics.risk"]
        assert risk_events