from core.mediator import Mediator
from core.storage import Storage
from models.finding import FindingCreate, FindingStatus
from models.graph import KnowledgeState, NodeUpsert
from models.session import Phase, SessionCreate
from models.target import TargetCreate


def _setup(db_path):
    m = Mediator(command_timeout=10, storage=Storage(db_path))
    t = m.create_target(TargetCreate(host="persist.test", assessment="web"))
    s = m.create_session(SessionCreate(target_id=t.id, agent="agent"))
    m.upsert_node(
        s.id,
        NodeUpsert(kind="host", name="persist.test", state=KnowledgeState.KNOWN, confidence=0.9),
    )
    m.execute(s.id, "shell", "echo persist")
    f = m.add_finding(s.id, FindingCreate(title="persistido", confidence=0.5))
    m.update_finding_status(s.id, f.id, FindingStatus.VALIDATED)
    m._storage.close()
    return t, s, f


def test_persistencia_completa(tmp_path):
    db = tmp_path / "mediator.db"
    t, s, f = _setup(str(db))

    m2 = Mediator(command_timeout=10, storage=Storage(str(db)))
    assert m2.state.get_target(t.id)
    s2 = m2.state.get_session(s.id)
    assert s2
    assert s2.id == s.id
    assert m2.state.get_results(s.id)
    assert m2.get_nodes(s.id)
    f2 = [x for x in m2.state.get_findings(s.id) if x.id == f.id][0]
    assert f2.status == FindingStatus.VALIDATED
    assert m2.audit.entries()
    m2._storage.close()


def test_restauracion_no_duplica(tmp_path):
    db = tmp_path / "mediator.db"
    t, s, f = _setup(str(db))

    m2 = Mediator(command_timeout=10, storage=Storage(str(db)))
    n_before = len(m2.state.list_sessions())
    m2.update_objective(s.id, objective="otro objetivo")
    m2._storage.close()

    m3 = Mediator(command_timeout=10, storage=Storage(str(db)))
    assert len(m3.state.list_sessions()) == n_before
    assert m3.state.get_session(s.id).objective == "otro objetivo"
    m3._storage.close()