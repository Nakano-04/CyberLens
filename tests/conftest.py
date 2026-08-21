import pytest

from core.mediator import Mediator
from models.session import SessionCreate
from models.target import TargetCreate


@pytest.fixture
def mediator():
    return Mediator(command_timeout=10)


@pytest.fixture
def target(mediator):
    return mediator.create_target(
        TargetCreate(host="app.test-lab.com", assessment="web", description="lab")
    )


@pytest.fixture
def session(mediator, target):
    return mediator.create_session(
        SessionCreate(target_id=target.id, agent="test-agent", objective="smoke test")
    )


def make_mediator(**kwargs):
    return Mediator(command_timeout=10, **kwargs)
