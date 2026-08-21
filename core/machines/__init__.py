from __future__ import annotations

from core.machines import blue, purple, red
from models.session import Phase
from models.team import Team

# Registry de maquinas de estado por equipo. Cada maquina define:
#   TRANSITIONS  -> dict[Phase, list[Phase]]
#   REQUIREMENTS -> dict[Phase, str] (mensajes de bloqueo)
#   blockers(state, session, target_phase) -> list[str]

MACHINES: dict[Team, dict] = {
    Team.RED: red,
    Team.BLUE: blue,
    Team.PURPLE: purple,
}

INITIAL_PHASE: dict[Team, Phase] = {
    Team.RED: Phase.RECON,
    Team.BLUE: Phase.DETECT,
    Team.PURPLE: Phase.PLAN,
}


def machine_for(team: Team):
    return MACHINES.get(team, red)


def initial_phase(team: Team) -> Phase:
    return INITIAL_PHASE.get(team, Phase.RECON)
