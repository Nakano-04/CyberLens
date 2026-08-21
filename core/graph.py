from __future__ import annotations

from datetime import datetime, timedelta, timezone

from models.graph import KnowledgeState, LinkCreate, Node, NodeUpsert, Relationship

# Kinds que, con confianza alta, habilitan el salto de fases (estado machine)
CRITICAL_KINDS = {"vulnerability", "data_asset", "beacon", "session", "pivot"}


class GraphStore:
    def __init__(
        self,
        node_ttl_seconds: int | None = None,
        max_nodes_per_kind: int | None = None,
    ) -> None:
        self._nodes: dict[str, Node] = {}
        self._links: list[Relationship] = []
        self._node_ttl = timedelta(seconds=node_ttl_seconds) if node_ttl_seconds else None
        self._max_per_kind = max_nodes_per_kind

    def upsert_node(self, session_id: str, data: NodeUpsert) -> Node:
        key = f"{session_id}:{data.kind}:{data.name.lower()}"
        existing = self._nodes.get(key)
        if existing:
            existing.state = data.state
            existing.confidence = data.confidence
            existing.source = data.source
            existing.properties = data.properties
            existing.last_seen = datetime.now(timezone.utc)
            return existing
        node = Node(
            id=key,
            session_id=session_id,
            kind=data.kind,
            name=data.name,
            state=data.state,
            confidence=data.confidence,
            source=data.source,
            properties=data.properties,
        )
        self._nodes[key] = node
        if self._max_per_kind:
            self._cap_kind(session_id, data.kind)
        return node

    def _cap_kind(self, session_id: str, kind: str) -> None:
        """Degradacion automatica: si un kind crece demasiado, se conservan los
        nodos de mayor confianza/vistos mas recientes (evita saturar el grafo
        con cientos de endpoints 404)."""
        group = [n for n in self.nodes(session_id) if n.kind == kind]
        if len(group) <= self._max_per_kind:
            return
        keep = sorted(
            group, key=lambda n: (n.confidence, n.last_seen.timestamp()), reverse=True
        )[self._max_per_kind :]
        for node in keep:
            self._nodes.pop(node.id, None)

    def link(self, session_id: str, data: LinkCreate) -> Relationship:
        rel = Relationship(session_id=session_id, **data.model_dump())
        self._links.append(rel)
        return rel

    def nodes(self, session_id: str) -> list[Node]:
        return [n for n in self._nodes.values() if n.session_id == session_id]

    def links(self, session_id: str) -> list[Relationship]:
        return [l for l in self._links if l.session_id == session_id]

    def all_nodes(self) -> list[Node]:
        return list(self._nodes.values())

    def all_links(self) -> list[Relationship]:
        return list(self._links)

    def restore(self, nodes: list[Node], links: list[Relationship]) -> None:
        self._nodes = {n.id: n for n in nodes}
        self._links = list(links)

    def critical_nodes(self, session_id: str, min_confidence: float = 0.9) -> list[Node]:
        """Nodos de kind critico con confianza alta (habilitan salto de fases)."""
        return [
            n
            for n in self.nodes(session_id)
            if n.kind in CRITICAL_KINDS and n.confidence >= min_confidence
        ]

    def prune(
        self,
        session_id: str,
        min_confidence: float = 0.5,
        now: datetime | None = None,
    ) -> list[str]:
        """Poda por TTL: descarta nodos UNVERIFIED/INFERRED con confianza baja
        que no se han visto en node_ttl. Devuelve los ids eliminados."""
        removed: list[str] = []
        if not self._node_ttl:
            return removed
        now = now or datetime.now(timezone.utc)
        for node in self.nodes(session_id):
            if node.state in (KnowledgeState.UNVERIFIED, KnowledgeState.INFERRED):
                if node.confidence < min_confidence and now - node.last_seen > self._node_ttl:
                    self._nodes.pop(node.id, None)
                    removed.append(node.id)
        return removed

    def remove(self, node_ids: list[str]) -> None:
        for node_id in node_ids:
            self._nodes.pop(node_id, None)

    def surface(self, session_id: str) -> dict:
        groups: dict[str, list[dict]] = {}
        for node in self.nodes(session_id):
            groups.setdefault(node.kind, []).append(
                {
                    "name": node.name,
                    "state": node.state.value,
                    "confidence": node.confidence,
                    "last_seen": node.last_seen.isoformat(),
                    "source": node.source,
                    "related_findings": node.related_findings,
                    "related_tests": node.related_tests,
                }
            )
        return groups
