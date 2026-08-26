from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field

from models.target import Target

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_URL_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)

# Interpreters that can execute arbitrary code from a flag (evasion tipica)
_EXEC_WRAPPERS = {
    "python", "python3", "python2", "perl", "ruby", "node", "php", "lua",
    "sh", "bash", "zsh", "ksh", "dash", "cmd", "powershell", "pwsh", "awk",
    "openssl", "env", "eval", "exec", "source", ".", "xargs", "nohup",
}
_WRAPPER_EVAL_FLAGS = {"-c", "-e", "-r", "-k", "/c", "/k", "-command"}

_DANGEROUS_BINARIES = {
    "shutdown", "reboot", "poweroff", "halt", "mkfs", "mkfs.ext4", "mkfs.btrfs",
    "dd", "fdisk", "gdisk", "parted", "gparted", "pkill", "killall", "iptables",
    "ip6tables", "ufw", "fwupdmgr", "format",
}

_CRITICAL_PATHS = (
    r"/etc/", r"/boot/", r"/root/", r"/usr/", r"/sbin/", r"/bin/", r"/var/",
    r"c:\windows", r"c:\program files",
)

_SHELL_METACHARS = [";", "&&", "||", "`", "$(", "$((", "${"]

_PIVOT_FLAGS = ("--resolve", "--connect-to")

# Patrones de comando que exigen aprobacion humana antes de ejecutar
_DEFAULT_REQUIRE_APPROVAL = [
    "shutdown",
    "reboot",
    "poweroff",
    "dd if=",
    "mkfs",
    "fdisk",
    "gdisk",
    "iptables",
    "ufw ",
    "chmod -r",
    "chown -r /",
    "git push --force",
    "drop table",
    "delete from",
]


@dataclass
class ScopeVerdict:
    approved: bool
    reasons: list[str] = field(default_factory=list)
    requires_approval: bool = False


class ScopeGuard:
    """Validacion determinista de targets y comandos (el codigo decide, no el prompt).

    - Denegacion por defecto ante evasiones: separadores, subshells, wrappers,
      codificaciones, path traversal, redirecciones a rutas criticas.
    - Los hosts extraidos del comando deben estar dentro de allowed_hosts.
    - Patrones que exigen aprobacion humana (ToolAuthZ require_human).
    """

    def __init__(
        self,
        allowed_hosts: list[str] | None = None,
        denied_prefixes: list[str] | None = None,
        deny_evasions: bool = True,
        require_approval_patterns: list[str] | None = None,
    ) -> None:
        self._allowed_hosts = [h.lower() for h in (allowed_hosts or [])]
        self._denied_prefixes = [d.lower() for d in (denied_prefixes or [])]
        self._deny_evasions = deny_evasions
        self._require_approval = list(require_approval_patterns) if require_approval_patterns is not None else list(_DEFAULT_REQUIRE_APPROVAL)

    # ------------------------------------------------------------------
    # targets
    # ------------------------------------------------------------------
    def validate_target(self, target: Target) -> bool:
        if not target.authorized:
            return False
        host = target.host.lower()
        if self._allowed_hosts and not self._host_in_scope(host):
            return False
        return True

    # ------------------------------------------------------------------
    # comandos
    # ------------------------------------------------------------------
    def validate_command(self, command: str, target: Target) -> ScopeVerdict:
        if not command or not command.strip():
            return ScopeVerdict(False, ["comando vacio"])
        tokens = self._tokenize(command)
        reasons: list[str] = []

        # 1. prefijos denegados (normalizado: espacios multiples, sin espacios finales)
        normalized = re.sub(r"\s+", " ", command.strip().lower())
        for prefix in self._denied_prefixes:
            if normalized == prefix or normalized.startswith(prefix):
                reasons.append(f"prefijo denegado: {prefix}")

        # 2. evasiones de scope
        if self._deny_evasions:
            reasons.extend(self._evasion_reasons(command, tokens))

        # 3. hosts fuera de scope (solo si hay allowlist configurada)
        if self._allowed_hosts:
            hosts = self._extract_hosts(command, tokens)
            outside = sorted({h for h in hosts if not self._host_in_scope(h)})
            if outside:
                reasons.append(f"host(s) fuera de scope: {', '.join(outside)}")

        # 4. autorizacion del target
        if target.authorized is False:
            reasons.append("target no autorizado")

        # 5. approval gate humano
        requires = False
        joined = " ".join(tokens).lower()
        for pattern in self._require_approval:
            if pattern in joined:
                requires = True
                break

        reasons = list(dict.fromkeys(reasons))
        return ScopeVerdict(approved=not reasons, reasons=reasons, requires_approval=requires)

    # ------------------------------------------------------------------
    # tokenizacion
    # ------------------------------------------------------------------
    @staticmethod
    def _tokenize(command: str) -> list[str]:
        try:
            return shlex.split(command, posix=True)
        except ValueError:
            return re.findall(r"\"[^\"]*\"|'[^']*'|[^\s]+", command)

    # ------------------------------------------------------------------
    # evasiones
    # ------------------------------------------------------------------
    def _evasion_reasons(self, command: str, tokens: list[str]) -> list[str]:
        reasons: list[str] = []
        low = command.lower()

        for meta in _SHELL_METACHARS:
            if meta in low:
                reasons.append(f"metacaracter shell: {meta}")
                break

        clean_tokens = [t.lower().strip("\"'") for t in tokens]
        for i, tok in enumerate(clean_tokens):
            if tok in {"sudo", "su", "doas"}:
                reasons.append(f"escalada de privilegios: {tok}")
            if tok in _DANGEROUS_BINARIES:
                reasons.append(f"binario peligroso: {tok}")
            if tok in _PIVOT_FLAGS:
                reasons.append(f"bypass de host: {tok}")
            if tok in _EXEC_WRAPPERS:
                nxt = clean_tokens[i + 1] if i + 1 < len(clean_tokens) else ""
                if nxt in _WRAPPER_EVAL_FLAGS:
                    reasons.append(f"ejecucion arbitraria: {tok} {nxt}")

        # comandos codificados / ofuscados
        if re.search(r"\b(base64|xxd|hexdump)\b", low) and re.search(r"(-d|-r|decode|decoded)", low):
            reasons.append("comando codificado (base64/hex)")
        if re.search(r"\b(printf|echo)\b.*\\x[0-9a-f]{2}", low, re.IGNORECASE):
            reasons.append("escape hex ofuscado")

        # path traversal (regex previo + tokens: cubre URLs con esquema tipo "http://x/../")
        if re.search(r"(^|[\s\"'])[a-z0-9_\-./]*\.\./", low) or " /../" in low or "/../ " in low:
            reasons.append("path traversal (..)")
        for tok in clean_tokens:
            if not tok.startswith("-") and (
                "/../" in tok or tok.startswith("../") or tok.endswith("/..")
            ):
                reasons.append("path traversal (..)")
                break

        # redireccion a rutas criticas (escribir fuera del workspace)
        for match in re.finditer(r"(?:^|[\s|;&])(?:>|tee)\s+([^\s|;&]+)", low):
            path = match.group(1).strip("\"'").replace("\\", "/").lower()
            for critical in _CRITICAL_PATHS:
                if path.startswith(critical) or critical.rstrip("/") in path:
                    reasons.append(f"escritura a ruta critica: {path}")
                    break

        # descargas con escritura directa a rutas criticas (curl -o/--output, wget -O)
        for match in re.finditer(r"(?:^|[\s])(?:-o|--output|-O)\s+([^\s]+)", low):
            path = match.group(1).strip("\"'").replace("\\", "/").lower()
            for critical in _CRITICAL_PATHS:
                if path.startswith(critical) or critical.rstrip("/") in path:
                    reasons.append(f"escritura a ruta critica: {path}")
                    break

        # fork bomb / loops infinitos
        if re.search(r":\(\)\s*\{", low) or re.search(r"while\s+true\s*;", low):
            reasons.append("fork bomb / loop infinito")

        return reasons

    # ------------------------------------------------------------------
    # extraccion de hosts
    # ------------------------------------------------------------------
    def _extract_hosts(self, command: str, tokens: list[str]) -> list[str]:
        hosts: list[str] = []
        for token in tokens:
            candidate = token.strip("\"'(),[]")
            if _URL_SCHEME_RE.match(candidate):
                candidate = candidate.split("://", 1)[1].split("/")[0]
            candidate = candidate.lower().rstrip(".:/")
            if not candidate or candidate.startswith("-"):
                continue
            if _IP_RE.match(candidate) or (
                candidate.count(".") >= 1
                and re.fullmatch(r"[a-z0-9][a-z0-9.-]*[a-z0-9]", candidate)
            ):
                hosts.append(candidate)
        for flag in _PIVOT_FLAGS:
            for match in re.finditer(rf"{re.escape(flag)}=?([^\s]+)", command):
                parts = match.group(1).split(":")
                if len(parts) >= 3:
                    hosts.append(parts[2].lower())  # --resolve host:port:ip / --connect-to h:p:ip:p
        return [h for h in dict.fromkeys(hosts) if h != "localhost"]

    def _host_in_scope(self, host: str) -> bool:
        for allowed in self._allowed_hosts:
            if allowed == "*":
                return True
            if allowed == host:
                return True
            if allowed.startswith("*.") and host.endswith(allowed[1:]):
                return True
        return False
