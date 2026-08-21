from __future__ import annotations

import re

from models.target import Service

_NMAP_SERVICE_RE = re.compile(
    r"^\s*(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?$"
)


def parse_nmap_services(stdout: str) -> list[Service]:
    services: list[Service] = []
    for line in stdout.splitlines():
        match = _NMAP_SERVICE_RE.match(line)
        if not match:
            continue
        port, protocol, name, detail = match.groups()
        version = None
        banner = None
        if detail:
            parts = detail.strip().split(None, 1)
            if parts and parts[0].lower() not in {"open", "closed", "filtered"}:
                version = parts[0]
            if len(parts) > 1:
                banner = parts[1]
        services.append(
            Service(
                port=int(port),
                protocol=protocol,
                name=name,
                version=version,
                banner=banner,
            )
        )
    return services


def parse_http_requests(stdout: str) -> list[dict]:
    responses = []
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("< HTTP/"):
            parts = line[2:].split(None, 2)
            if len(parts) >= 2 and parts[1].isdigit():
                responses.append(
                    {
                        "protocol": parts[0],
                        "status": int(parts[1]),
                        "reason": parts[2] if len(parts) > 2 else "",
                    }
                )
    return responses


_BURP_RE = re.compile(r".*?\s+(\w{3,7})\s+(\S+)\s+HTTP/\S+\s+(\d{3})")


def parse_burp_log(stdout: str) -> list[dict]:
    requests = []
    for line in stdout.splitlines():
        match = _BURP_RE.match(line)
        if match:
            requests.append(
                {
                    "method": match.group(1),
                    "path": match.group(2),
                    "status": int(match.group(3)),
                }
            )
    return requests


_MSF_SESSION_RE = re.compile(r"\[\*\]\s+(Meterpreter session \d+ opened.*)")


def parse_msf_output(stdout: str) -> list[dict]:
    events = []
    for line in stdout.splitlines():
        line = line.strip()
        session = _MSF_SESSION_RE.match(line)
        if session:
            events.append({"event": "session_opened", "detail": session.group(1)})
        elif line.startswith("[*]"):
            events.append({"event": "info", "detail": line[3:].strip()})
        elif line.startswith("[+]"):
            events.append({"event": "success", "detail": line[3:].strip()})
        elif line.startswith("[-]"):
            events.append({"event": "error", "detail": line[3:].strip()})
    return events


# ---------------------------------------------------------------------------
# Modo observador: parseo difuso con regex genericos. Si un parser especifico
# falla (salida masiva, formato inesperado, herramienta sin parser), esto evita
# que el grafo quede ciego. Nada de esto es "verdad" -> nodos INFERRED.
# ---------------------------------------------------------------------------

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_NMAP_HOST_RE = re.compile(r"Nmap scan report for (\S+)")
_HTTP_STATUS_RE = re.compile(r"(?:HTTP/\d\.\d|HTTP)\s+(\d{3})")
_PORT_OPEN_RE = re.compile(r"(\d{1,5})/(tcp|udp)\s+open")
_URL_RE = re.compile(r"https?://([^\s'\">]+)")
_SS_LISTEN_RE = re.compile(r":(\d{1,5})\b")

# Comandos que indican pivoting / listeners / sesiones C2 (siempre de interes)
_PIVOT_TOKENS = ("-l 8080", "-l 4444", "-l ", "-d ", "chisel", "socat", "ngrok", "ssh -l", "ssh -d", "ssh -r")
_LISTENER_TOKENS = ("nc -lvp", "ncat -lvp", "nc -lv", "nc -lp", "listen", "listening on")
_SESSION_TOKENS = ("meterpreter", "reverse_http", "reverse_https", "reverse_tcp", "bind_tcp", "session opened", "shell opened", "msfconsole")


def parse_observations(stdout: str, command: str) -> dict:
    """Extraccion difusa: hosts, ips, endpoints, puertos abiertos, listeners,
    pivots y sesiones. Diseñada para NO romper ante salidas no estructuradas."""
    obs: dict = {
        "hosts": [],
        "ips": [],
        "endpoints": [],
        "ports": [],
        "listeners": [],
        "pivots": [],
        "sessions": [],
        "http_statuses": [],
    }
    low_cmd = command.lower()
    low_out = stdout.lower()

    for host in _NMAP_HOST_RE.findall(stdout):
        if host not in obs["hosts"]:
            obs["hosts"].append(host)
    for ip in _IPV4_RE.findall(stdout):
        if ip not in obs["ips"]:
            obs["ips"].append(ip)
    for url in _URL_RE.findall(stdout):
        if "://" in url:
            url = url[url.index("://") + 3 :]
        path = url.split("?", 1)[0]
        if path not in obs["endpoints"]:
            obs["endpoints"].append(path)
    for status in _HTTP_STATUS_RE.findall(stdout):
        obs["http_statuses"].append(int(status))
    for port, proto in _PORT_OPEN_RE.findall(stdout):
        key = f"{proto}/{port}"
        if key not in obs["ports"]:
            obs["ports"].append(key)
    for line in stdout.splitlines():
        if "listen" in line.lower():
            match = _SS_LISTEN_RE.search(line)
            if match:
                key = f"listen/{match.group(1)}"
                if key not in obs["listeners"]:
                    obs["listeners"].append(key)
    for token in _PIVOT_TOKENS:
        if token in low_cmd:
            obs["pivots"].append(command)
            break
    for token in _LISTENER_TOKENS:
        if token in low_cmd or token in low_out:
            obs["listeners"].append("listener-detected")
            break
    for token in _SESSION_TOKENS:
        if token in low_cmd or token in low_out:
            obs["sessions"].append(command)
            break
    return {k: v for k, v in obs.items() if v}
