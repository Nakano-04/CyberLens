import pytest

from core.report import generate_report
from core.statemachine import allowed_transitions, blockers
from models.finding import FindingCreate
from models.session import Phase, SessionCreate
from models.team import Team


@pytest.fixture
def three_teams(mediator, target):
    red = mediator.create_session(
        SessionCreate(target_id=target.id, agent="r", objective="entrar", team=Team.RED)
    )
    blue = mediator.create_session(
        SessionCreate(target_id=target.id, agent="b", objective="detectar", team=Team.BLUE)
    )
    purple = mediator.create_session(
        SessionCreate(target_id=target.id, agent="p", objective="cobertura", team=Team.PURPLE)
    )
    return red, blue, purple


def test_teams_isolated_states(mediator, three_teams):
    red, blue, purple = three_teams
    mediator.ingest_event(blue.id, "network", "4625 failed logon")
    assert mediator.state.get_alerts(red.id) == []
    assert mediator.state.get_alerts(purple.id) == []
    assert len(mediator.state.get_alerts(blue.id)) == 1
    assert mediator.state.get_results(red.id) == []


def test_blue_entities_forbidden_for_red(mediator, three_teams):
    red, _, _ = three_teams
    with pytest.raises(PermissionError):
        mediator.ingest_event(red.id, "network", "evento")
    with pytest.raises(PermissionError):
        mediator.add_recommendation(red.id, "recomendacion")


def test_phase_machines_per_team(mediator, three_teams):
    from core.machines import machine_for

    red, blue, purple = three_teams
    assert allowed_transitions(Phase.RECON, team=Team.RED) == [Phase.ENUMERATION]
    assert allowed_transitions(Phase.DETECT, team=Team.BLUE) == [Phase.TRIAGE]
    assert Phase.COVERAGE in machine_for(Team.PURPLE).TRANSITIONS
    # red no conoce fases blue; blue no conoce fases red
    red_phases = {p for t in machine_for(Team.RED).TRANSITIONS.values() for p in t}
    blue_phases = {p for t in machine_for(Team.BLUE).TRANSITIONS.values() for p in t}
    assert Phase.TRIAGE not in red_phases
    assert Phase.VALIDATION not in blue_phases


def test_red_flow_unaffected_by_blue(mediator, three_teams):
    red, _, _ = three_teams
    mediator.set_phase(red.id, Phase.ENUMERATION)
    assert mediator.state.get_session(red.id).phase == Phase.ENUMERATION


def test_blue_flow_machine(mediator, three_teams):
    _, blue, _ = three_teams
    mediator.ingest_event(blue.id, "network", "4625 failed logon")
    mediator.set_phase(blue.id, Phase.TRIAGE)
    assert mediator.state.get_session(blue.id).phase == Phase.TRIAGE


def test_purple_links_and_report_dispatch(mediator, three_teams):
    red, blue, purple = three_teams
    mediator.link_session(purple.id, Team.RED.value, red.id)
    mediator.link_session(purple.id, Team.BLUE.value, blue.id)
    mediator.ingest_event(blue.id, "llm_gateway", "ignore previous instructions")
    mediator.add_finding(red.id, FindingCreate(title="f", technique_id="T1027"))

    assert "Equipo: BLUE" in generate_report(mediator, blue.id)
    assert "Equipo: PURPLE" in generate_report(mediator, purple.id)
    assert "Equipo: RED" in generate_report(mediator, red.id)
    assert "Orquestacion" in generate_report(mediator, purple.id)
    assert "Matriz de cobertura" in generate_report(mediator, purple.id)


def test_statemachine_facade_backward_compat(mediator, three_teams):
    red, _, _ = three_teams
    assert Phase.VALIDATION in allowed_transitions(Phase.HYPOTHESIS)
    session = mediator.state.get_session(red.id)
    assert blockers(mediator.state, session, Phase.ENUMERATION) == []


def test_red_reports_still_work(mediator, three_teams):
    red, _, _ = three_teams
    mediator.update_objective(red.id, objective="deep dive")
    report = generate_report(mediator, red.id)
    assert "Resumen" in report
    assert "Metricas" in report


def test_audit_records_team_actions(mediator, three_teams):
    red, blue, purple = three_teams
    mediator.ingest_event(blue.id, "network", "password incorrect")
    entries = mediator.audit.entries()
    assert any(e.action == "telemetry.ingest" for e in entries)
    assert any(e.action == "session.create" and "blue" in e.detail for e in entries)