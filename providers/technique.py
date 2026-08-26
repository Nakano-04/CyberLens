from __future__ import annotations

from knowledge.mitre import PHASE_TACTICS, TECHNIQUES


class TechniqueProvider:
    def all(self) -> list[dict]:
        raise NotImplementedError

    def get(self, technique_id: str) -> dict:
        raise NotImplementedError

    def suggested(self, phase: str, limit: int = 10) -> list[dict]:
        raise NotImplementedError


class BuiltinTechniqueProvider(TechniqueProvider):
    def all(self) -> list[dict]:
        return [{"id": tid, **t} for tid, t in TECHNIQUES.items()]

    def get(self, technique_id: str) -> dict:
        tech = TECHNIQUES.get(technique_id.upper())
        if not tech:
            raise KeyError(f"technique {technique_id} not found")
        return {"id": technique_id.upper(), **tech}

    def suggested(self, phase: str, limit: int = 10) -> list[dict]:
        tactics = PHASE_TACTICS.get(phase, [])
        out = [
            {"id": tid, **t} for tid, t in TECHNIQUES.items() if t["tactic"] in tactics
        ]
        return out[:limit]
