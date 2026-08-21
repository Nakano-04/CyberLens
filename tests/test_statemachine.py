import pytest

from core.statemachine import TRANSITIONS, allowed_transitions, blockers, can_skip, critical_evidence_exists
from models.finding import FindingStatus
from models.graph import KnowledgeState, NodeUpsert
from models.session import Phase, Session
from models.target import Target
from models.tool_result import ToolResult


def test_transiciones_validas():
    assert allowed_transitions(Phase.RECON) == [Phase.ENUMERATION]
    assert allowed_transitions(Phase.ENUMERATION) == [Phase.MODELING]
    assert allowed_transitions(Phase.MODELING) == [Phase.HYPOTHESIS]
    assert allowed_transitions(Phase.HYPOTHESIS) == [Phase.VALIDATION]
    assert set(allowed_transitions(Phase.VALIDATION)) == {Phase.IMPACT, Phase.HYPOTHESIS}
    assert allowed_transitions(Phase.IMPACT) == [Phase.EVIDENCE]
    assert allowed_transitions(Phase.EVIDENCE) == [Phase.REPORT]


def test_can_skip_direccion():
    assert can_skip(Phase.RECON, Phase.REPORT)
    assert not can_skip(Phase.REPORT, Phase.RECON)


def test_validation_requiere_finding(state_with_session):
    session, mediator = state_with_session
    assert blockers(mediator.state, session, Phase.VALIDATION)


def test_validation_con_finding_pasa(state_with_session):
    session, mediator = state_with_session
    session.phase = Phase.HYPOTHESIS
    mediator.add_finding(session.id, models_finding_create())
    assert not blockers(mediator.state, session, Phase.VALIDATION)


def test_evidence_requiere_finding_validated(state_with_session):
    session, mediator = state_with_session
    session.phase = Phase.IMPACT
    f = mediator.add_finding(session.id, models_finding_create())
    assert blockers(mediator.state, session, Phase.EVIDENCE)
    f.status = FindingStatus.VALIDATED
    assert not blockers(mediator.state, session, Phase.EVIDENCE)


def test_report_requiere_validado_y_verificado(state_with_session):
    session, mediator = state_with_session
    session.phase = Phase.IMPACT
    f = mediator.add_finding(session.id, models_finding_create())
    f.status = FindingStatus.VALIDATED
    session.phase = Phase.EVIDENCE
    assert blockers(mediator.state, session, Phase.REPORT)  # verified=False
    f.verified = True
    assert not blockers(mediator.state, session, Phase.REPORT)


def test_transicion_a_fase_no_permitida_bloquea(state_with_session):
    session, mediator = state_with_session
    with pytest.raises(ValueError):
        mediator.set_phase(session.id, Phase.VALIDATION)


def test_override_con_razon_pasa(state_with_session):
    session, mediator = state_with_session
    s = mediator.set_phase(session.id, Phase.REPORT, override=True, reason="break-glass")
    assert s.phase == Phase.REPORT


def test_override_sin_razon_falla(state_with_session):
    session, mediator = state_with_session
    with pytest.raises(ValueError):
        mediator.set_phase(session.id, Phase.REPORT, override=True)


def test_salto_critico_por_nodo_critico(state_with_session):
    session, mediator = state_with_session
    mediator.upsert_node(
        session.id,
        NodeUpsert(kind="vulnerability", name="rce", state=KnowledgeState.KNOWN, confidence=0.95),
    )
    assert critical_evidence_exists(mediator.state, session.id)
    s = mediator.set_phase(session.id, Phase.VALIDATION)
    assert s.phase == Phase.VALIDATION


def test_repetir_fase_actual_no_es_bloqueo(state_with_session):
    session, mediator = state_with_session
    assert not blockers(mediator.state, session, Phase.RECON)


def models_finding_create():
    from models.finding import FindingCreate

    return FindingCreate(title="hipotesis de prueba")


@pytest.fixture
def state_with_session():
    from core.mediator import Mediator
    from models.session import SessionCreate
    from models.target import TargetCreate

    mediator = Mediator(command_timeout=10)
    target = mediator.create_target(
        TargetCreate(host="app.test-lab.com", assessment="web")
    )
    session = mediator.create_session(
        SessionCreate(target_id=target.id, agent="test-agent")
    )
    return session, mediator