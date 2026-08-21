from core.evidence import adjust_confidence, evaluate
from models.tool_result import ToolResult


def tool(stdout="", stderr="", exit_code=0, approved=True, timed_out=False, parsed=None):
    return ToolResult(
        id="r1",
        session_id="s1",
        tool="shell",
        command="test",
        stdout=stdout,
        stderr=stderr,
        exit_code=exit_code,
        timed_out=timed_out,
        approved=approved,
        parsed=parsed or {},
    )


def test_exit_ok_sin_senales():
    v = evaluate(tool(stdout="salida neutral"))
    assert v["exit_ok"]
    assert not v["supported"]
    assert v["score"] == 0.5


def test_http_2xx_soporta():
    v = evaluate(tool(stdout="HTTP/1.1 200 OK\nwelcome to dashboard"))
    assert v["exit_ok"]
    assert v["supported"]
    assert v["score"] > 0.5


def test_http_4xx_contradice():
    v = evaluate(tool(stdout="HTTP/1.1 403 Forbidden"))
    assert v["exit_ok"]
    assert not v["supported"]
    assert "http-4xx" in v["negatives"]


def test_exit_distinto_de_cero_falla():
    v = evaluate(tool(stdout="HTTP/1.1 200 OK", exit_code=1))
    assert not v["exit_ok"]
    assert not v["supported"]
    assert 0.0 <= v["score"] <= 0.3  # senal no basta: requiere exit_ok


def test_timed_out_no_es_evidencia():
    v = evaluate(tool(stdout="HTTP/1.1 200 OK", timed_out=True))
    assert not v["exit_ok"]


def test_no_aprobado_no_es_evidencia():
    v = evaluate(tool(stdout="HTTP/1.1 200 OK", approved=False))
    assert not v["exit_ok"]


def test_parsed_http_responses_suma_soporte():
    v = evaluate(tool(stdout="", parsed={"http_responses": [{"status": 200}]}))
    assert v["exit_ok"]
    assert v["supported"]


def test_parsed_yara_match_soporta():
    v = evaluate(tool(stdout="", parsed={"yara_matches": ["rule1"]}))
    assert v["supported"]


def test_senales_y_negativas_se_restan():
    v = evaluate(tool(stdout="HTTP/1.1 200 OK\nforbidden"))
    assert not v["supported"]
    assert v["negatives"]


def test_adjust_confianza_evidencia_exitosa_subida():
    v = evaluate(tool(stdout="HTTP/1.1 200 OK welcome dashboard"))
    c = adjust_confidence(0.5, v)
    assert c >= 0.5
    assert 0.4 <= c <= 0.95


def test_adjust_confianza_evidencia_fallida_bajada():
    v = evaluate(tool(stdout="error: connection refused", exit_code=1))
    c = adjust_confidence(0.8, v)
    assert c <= 0.4


def test_adjust_confianza_neutra_topada():
    v = evaluate(tool(stdout="sin senales"))
    c = adjust_confidence(0.9, v)
    assert c <= 0.6