from __future__ import annotations

import subprocess
from dataclasses import dataclass, field


@dataclass
class ScanResult:
    matches: list[str] = field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0


class ScannerProvider:
    def scan(self, rules: str, target_path: str) -> ScanResult:
        raise NotImplementedError


class YaraScannerProvider(ScannerProvider):
    def __init__(self, binary: str = "yara", timeout: int = 120) -> None:
        self._binary = binary
        self._timeout = timeout

    def scan(self, rules: str, target_path: str) -> ScanResult:
        try:
            proc = subprocess.run(
                [self._binary, rules, target_path],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self._timeout,
            )
            matches = [
                line.split(" ", 1)[0] for line in proc.stdout.splitlines() if line.strip()
            ]
            return ScanResult(matches, proc.stdout, proc.stderr, proc.returncode)
        except FileNotFoundError:
            return ScanResult([], "", f"binario '{self._binary}' no encontrado", 127)
        except subprocess.TimeoutExpired:
            return ScanResult([], "", f"scan excedio el timeout de {self._timeout}s", -1)
