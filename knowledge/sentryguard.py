from __future__ import annotations

import json
from pathlib import Path

# Indice de detecciones conocidas de SentryGuard (EDR del ecosistema).
# Escanea el directorio de reglas del EDR y construye un mapa
# tecnica MITRE -> nombres de regla, para que el debrief diga CUAL
# regla de SentryGuard disparo cada deteccion.

CATEGORY_TECHNIQUES: dict[str, list[str]] = {
    "webshell": ["T1505.003"],
    "ransomware": ["T1486"],
    "exploit": ["T1068"],
    "vulnerabilities": ["T1190"],
    "c2": ["T1071"],
    "malware": ["T1204"],
    "hacktool": ["T1588.002"],
    "apt": ["T1078"],
}

FILE_GLOSSARY: dict[str, list[str]] = {
    "webshell": ["T1505.003"],
    "ransom": ["T1486"],
    "miner": ["T1496"],
    "beacon": ["T1071"],
    "dump": ["T1003"],
    "lpe": ["T1068"],
    "uac": ["T1548"],
    "kerber": ["T1558"],
    "psexec": ["T1021"],
    "scan": ["T1046"],
    "phish": ["T1566"],
    "exfil": ["T1041"],
}


class SentryGuardIndex:
    def __init__(self) -> None:
        self._by_technique: dict[str, list[str]] = {}
        self._rules: dict[str, str] = {}
        self.source_dir: str | None = None

    def load_dir(self, rules_dir: str) -> "SentryGuardIndex":
        base = Path(rules_dir)
        if not base.is_dir():
            return self
        self.source_dir = str(base)
        for path in sorted(base.rglob("*.json")):
            try:
                raw = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            except (json.JSONDecodeError, OSError):
                continue
            name = (
                (raw.get("rule_identity") or {}).get("name")
                or (raw.get("metadata") or {}).get("description")
                or path.stem
            )
            techniques: list[str] = []
            mitre = raw.get("mitre_mapping") or {}
            if mitre:
                tid = mitre.get("technique_id")
                if tid and str(tid).startswith("T"):
                    techniques.append(str(tid))
                techniques.extend(
                    str(t) for t in (mitre.get("all_techniques") or []) if str(t).startswith("T")
                )
            detection = raw.get("detection") or {}
            category = str(detection.get("category") or "").lower()
            if not techniques and category in CATEGORY_TECHNIQUES:
                techniques = list(CATEGORY_TECHNIQUES[category])
            lower_name = str(name).lower()
            if not techniques:
                for token, tids in FILE_GLOSSARY.items():
                    if token in lower_name:
                        techniques = list(tids)
                        break
            if not techniques:
                continue
            self._rules[str(name)] = str(path)
            for tid in techniques:
                self._by_technique.setdefault(tid, [])
                if name not in self._by_technique[tid]:
                    self._by_technique[tid].append(name)
        return self

    def rules_for(self, technique_ids: list[str]) -> list[str]:
        found: list[str] = []
        for tid in technique_ids:
            for rule in self._by_technique.get(tid, []):
                if rule not in found:
                    found.append(rule)
        return found

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def __bool__(self) -> bool:
        return bool(self._rules)