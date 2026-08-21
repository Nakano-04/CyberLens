from __future__ import annotations

import subprocess


class YaraScanner:
    def __init__(self, binary: str = "yara") -> None:
        self._binary = binary

    def available(self) -> bool:
        try:
            proc = subprocess.run(
                [self._binary, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return proc.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def scan(self, rules: str, target_path: str) -> tuple[list[str], str, str, int]:
        proc = subprocess.run(
            [self._binary, rules, target_path],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
        matches = [line.split(" ", 1)[0] for line in proc.stdout.splitlines() if line.strip()]
        return matches, proc.stdout, proc.stderr, proc.returncode
