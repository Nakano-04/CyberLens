import pytest

from core.mediator import Mediator
from models.finding import FindingCreate, FindingStatus
from models.graph import KnowledgeState, LinkCreate, NodeUpsert
from models.session import Phase, SessionCreate
from models.target import TargetCreate


def test_flujo_completo_con_fases(mediator, target, session):
    sid = session.id

    mediator.update_objective(
        sid,
        objective="demostrar impacto",
        current_position="usuario autenticado",
        known=["portal", "test-user"],
        unknown=["limites de autorizacion"],
        next_areas=["modelo de autorizacion"],
    )
    s = mediator.state.get_session(sid)
    assert s.objective == "demostrar impacto"

    mediator.upsert_node(
        sid, NodeUpsert(kind="application", name="portal", state=KnowledgeState.KNOWN, confidence=0.9)
    )
    mediator.upsert_node(
        sid, NodeUpsert(kind="endpoint", name="/admin", state=KnowledgeState.UNVERIFIED, confidence=0.4)
    )
    mediator.link_nodes(
        sid,
        LinkCreate(source="session:application:portal", target="session:endpoint:/admin", kind="expone"),
    )
    assert len(mediator.get_nodes(sid)) == 2
    assert len(mediator.get_surface(sid)) >= 2

    for phase in [Phase.ENUMERATION, Phase.MODELING, Phase.HYPOTHESIS]:
        mediator.set_phase(sid, phase)
    assert mediator.state.get_session(sid).phase == Phase.HYPOTHESIS

    r = mediator.execute(sid, "shell", "echo HTTP/1.1 200 OK welcome dashboard")
    assert r.approved
    assert r.exit_code == 0

    f = mediator.add_finding(
        sid,
        FindingCreate(
            title="Posible broken authorization",
            confidence=0.62,
            evidence_ids=[r.id],
            technique_id="T1078",
        ),
    )
    assert f.verified  # evidencia semantica exitosa
    assert f.confidence >= 0.62

    mediator.set_phase(sid, Phase.VALIDATION)
    mediator.update_finding_status(sid, f.id, FindingStatus.VALIDATED)
    mediator.set_phase(sid, Phase.IMPACT)
    mediator.set_phase(sid, Phase.EVIDENCE)
    mediator.set_phase(sid, Phase.REPORT)

    plan = mediator.plan(sid)
    assert "branches" in plan
    metrics = mediator.get_metrics(sid)
    assert 0 <= metrics["evidence_hygiene"]["score"] <= 100
    chains = mediator.evidence_chains(sid)
    assert chains
    context = mediator.get_context(sid)
    assert "HIPOTESIS" in context or "broken authorization" in context


def test_ejecucion_bloqueada_queda_en_audit(mediator, target, session):
    r = mediator.execute(session.id, "shell", "shutdown -h now")
    assert not r.approved
    blocked = [a for a in mediator.audit.entries() if a.verdict.value == "blocked"]
    assert any("shutdown" in b.detail for b in blocked)


def test_finding_sin_evidencia_no_verificado(mediator, target, session):
    f = mediator.add_finding(session.id, FindingCreate(title="sin evidencia", confidence=0.9))
    assert not f.verified
    assert any("sin evidencia" in n for n in f.verification_notes)


def test_finding_con_evidencia_en_contra_no_verificado(mediator, target, session):
    ok = mediator.execute(session.id, "shell", "echo HTTP/1.1 200 OK admin dashboard")
    assert ok.approved
    deny = mediator.execute(session.id, "shell", "echo HTTP/1.1 403 Forbidden access denied")
    assert deny.approved
    f = mediator.add_finding(
        session.id,
        FindingCreate(
            title="broken auth",
            confidence=0.7,
            evidence_ids=[ok.id],
            against=[deny.id],
        ),
    )
    assert not f.verified
    assert f.confidence <= 0.4
    assert any("en contra" in n for n in f.verification_notes)


def test_finding_con_evidencia_divergente_no_verificado(mediator, target, session):
    bad = mediator.execute(session.id, "shell", "echo HTTP/1.1 500 Internal Server Error")
    assert bad.approved
    ok = mediator.execute(session.id, "shell", "echo HTTP/1.1 200 OK auth granted")
    assert ok.approved
    f = mediator.add_finding(
        session.id,
        FindingCreate(
            title="auth bypass",
            confidence=0.8,
            evidence_ids=[bad.id, ok.id],
        ),
    )
    assert not f.verified
    assert any("no toda la evidencia" in n for n in f.verification_notes)


def test_presupuesto_de_pasos(mediator, target):
    from core.mediator import Mediator as M

    m = M(command_timeout=10)
    t = m.create_target(TargetCreate(host="budget.test", assessment="web"))
    s = m.create_session(SessionCreate(target_id=t.id, max_steps=1))
    r1 = m.execute(s.id, "shell", "echo paso 1")
    assert r1.approved
    r2 = m.execute(s.id, "shell", "echo paso 2")
    assert not r2.approved
    assert "presupuesto" in r2.stderr


def test_target_fuera_de_scope_no_crea_sesion(mediator):
    from core.mediator import Mediator as M

    m = M(allowed_hosts=["solo-lab.com"], command_timeout=10)
    t = m.create_target(TargetCreate(host="app.test-lab.com", assessment="web"))
    with pytest.raises(PermissionError):
        m.create_session(SessionCreate(target_id=t.id, agent="a"))


def test_auditoria_registra_todo(mediator, target, session):
    mediator.add_note(session.id, "nota de prueba")
    entries = mediator.audit.entries()
    actions = {e.action for e in entries}
    assert {"target.create", "session.create", "session.note"} <= actions