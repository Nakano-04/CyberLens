from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

from providers.scanner import ScanResult, ScannerProvider
from providers.technique import TechniqueProvider


class _HttpBase:
    def __init__(self, base_url: str, api_key: str = "", timeout: int = 30) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout

    def _request(self, method: str, path: str, body: dict | None = None):
        url = self._base_url + path
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=self._timeout) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw) if raw else {}


class HttpTechniqueProvider(TechniqueProvider, _HttpBase):
    def __init__(self, base_url: str, api_key: str = "", timeout: int = 30) -> None:
        super().__init__(base_url, api_key, timeout)

    def all(self) -> list[dict]:
        return self._request("GET", "/techniques")

    def get(self, technique_id: str) -> dict:
        return self._request("GET", f"/techniques/{urllib.parse.quote(technique_id)}")

    def suggested(self, phase: str, limit: int = 10) -> list[dict]:
        params = urllib.parse.urlencode({"phase": phase, "limit": limit})
        return self._request("GET", f"/techniques/suggested?{params}")


class HttpScannerProvider(ScannerProvider, _HttpBase):
    def __init__(self, base_url: str, api_key: str = "", timeout: int = 120) -> None:
        super().__init__(base_url, api_key, timeout)

    def scan(self, rules: str, target_path: str) -> ScanResult:
        try:
            data = self._request(
                "POST", "/yara/scan", {"rules": rules, "target": target_path}
            )
            return ScanResult(
                matches=data.get("matches", []),
                stdout=data.get("stdout", ""),
                stderr=data.get("stderr", ""),
                exit_code=data.get("exit_code", 0),
            )
        except (urllib.error.URLError, urllib.error.HTTPError) as exc:
            return ScanResult([], "", f"error consultando motor EDR: {exc}", -1)
