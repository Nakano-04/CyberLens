from __future__ import annotations

import json
import urllib.error
import urllib.request

from models.target import Target
from models.tool_result import ToolResult


class Compactor:
    def __init__(
        self,
        base_url: str = "",
        api_key: str = "",
        model: str = "",
        min_results: int = 20,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._model = model
        self._min_results = min_results

    @property
    def enabled(self) -> bool:
        return bool(self._base_url and self._api_key and self._model)

    def should_compact(self, results: list[ToolResult]) -> bool:
        return len(results) >= self._min_results

    def summarize(
        self,
        results: list[ToolResult],
        target: Target,
        fallback_summary: str,
    ) -> str:
        if not self.enabled:
            return fallback_summary
        blocks = [r.to_context_block() for r in results]
        prompt = (
            "Eres el compresor de contexto de una operacion de seguridad autorizada.\n"
            f"TARGET: {target.summary()}\n"
            "Resume en espanol, en maximo 30 lineas, la siguiente evidencia de "
            "herramientas. Conserva: puertos/servicios/versiones, credenciales o "
            "rutas encontradas, comandos que fallaron, y resultados inconclusos. "
            "No inventes datos que no esten en la evidencia.\n\n"
            + "\n\n".join(blocks)
        )
        payload = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": "Resumidor fiel de evidencia de operaciones de seguridad."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
            "max_tokens": 900,
        }
        req = urllib.request.Request(
            self._base_url + "/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self._api_key}"},
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data["choices"][0]["message"]["content"].strip()
        except (urllib.error.URLError, KeyError, IndexError, json.JSONDecodeError):
            return fallback_summary
