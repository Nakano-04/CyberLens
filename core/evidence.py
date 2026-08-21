from __future__ import annotations

import re

from models.tool_result import ToolResult

# Patrones de exito en stdout/stderr
_SUCCESS_PATTERNS = [
    ("http-2xx", re.compile(r"HTTP/\d\.\d\s+2\d\d")),
    ("http-3xx", re.compile(r"HTTP/\d\.\d\s+3\d\d")),
    ("http-200-ok", re.compile(r"200\s+OK", re.IGNORECASE)),
    ("set-cookie", re.compile(r"set-cookie:", re.IGNORECASE)),
    ("redirect", re.compile(r"^location:", re.IGNORECASE | re.MULTILINE)),
    ("auth-ok", re.compile(r"welcome|dashboard|logged in|logged-in|valid session", re.IGNORECASE)),
    ("data-leak", re.compile(r"(admin|password|token|secret|apikey|api[-_]?key|Authorization)", re.IGNORECASE)),
]

# Patrones que contradicen la hipotesis
_NEGATIVE_PATTERNS = [
    ("http-4xx", re.compile(r"HTTP/\d\.\d\s+4\d\d")),
    ("http-5xx", re.compile(r"HTTP/\d\.\d\s+5\d\d")),
    ("denied", re.compile(r"\b(forbidden|access denied|401|403|404|not found|refused)\b", re.IGNORECASE)),
    ("error", re.compile(r"\b(error|traceback|exception|failed|timed? ?out)\b", re.IGNORECASE)),
]


def evaluate(result: ToolResult) -> dict:
    """Validacion semantica de un ToolResult como evidencia.

    Devuelve: exit_ok (exit_code==0, aprobado, sin timeout), supported
    (hay senales de exito verificables en stdout/parsed), score 0-1 y
    las listas de senales positivas/negativas encontradas.
    """
    exit_ok = bool(result.approved) and result.exit_code == 0 and not result.timed_out
    text = f"{result.stdout or ''}\n{result.stderr or ''}"

    signals: list[str] = []
    negatives: list[str] = []
    for name, pattern in _SUCCESS_PATTERNS:
        if pattern.search(text):
            signals.append(name)
    for name, pattern in _NEGATIVE_PATTERNS:
        if pattern.search(text):
            negatives.append(name)

    parsed = result.parsed or {}
    if parsed.get("http_responses"):
        if any(int(r.get("status", 0)) < 400 for r in parsed["http_responses"]):
            signals.append("parsed-http-2xx")
        if any(int(r.get("status", 0)) >= 400 for r in parsed["http_responses"]):
            negatives.append("parsed-http-error")
    if parsed.get("requests"):
        if any(int(r.get("status", 0)) < 400 for r in parsed["requests"]):
            signals.append("parsed-burp-ok")
    if parsed.get("yara_matches"):
        signals.append("parsed-yara-match")
    if parsed.get("msf_events"):
        if any(ev.get("event") == "session_opened" for ev in parsed["msf_events"]):
            signals.append("parsed-msf-session")

    score = 0.5 if exit_ok else 0.0
    if signals:
        score += 0.3
    if negatives:
        score -= 0.25
    score = max(0.0, min(1.0, score))
    supported = bool(exit_ok and signals and not negatives)
    return {
        "exit_ok": exit_ok,
        "supported": supported,
        "score": round(score, 3),
        "signals": signals,
        "negatives": negatives,
    }


def adjust_confidence(base: float, verdict: dict) -> float:
    """Ajusta la confianza de la hipotesis segun la validacion semantica.

    - Evidencia exitosa con senales: sube hasta +0.25 (tope 0.95).
    - Evidencia neutral (exit 0 sin senales): tope 0.6.
    - Evidencia fallida o en contra: baja, tope 0.4.
    """
    confidence = base
    if verdict["exit_ok"]:
        if verdict["supported"]:
            confidence = max(confidence, min(0.95, base + 0.25))
        else:
            confidence = min(confidence, 0.6)
    else:
        confidence = min(confidence, 0.4)
    if verdict["negatives"]:
        confidence -= 0.15
    return round(min(1.0, max(0.05, confidence)), 3)
