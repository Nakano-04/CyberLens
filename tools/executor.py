from __future__ import annotations

import os
import subprocess
import time


class SandboxUnavailable(Exception):
    """El sandbox configurado no esta disponible: fail-closed (no se ejecuta nada)."""


class ExecResult:
    def __init__(
        self,
        stdout: str,
        stderr: str,
        exit_code: int,
        timed_out: bool,
        duration_ms: int,
    ) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code
        self.timed_out = timed_out
        self.duration_ms = duration_ms


class Executor:
    """Ejecuta comandos con timeout real (mata el arbol de procesos por PID,
    no por coincidencia de texto) y sandbox opcional via Docker con egress
    bloqueado por defecto (--network=none), memoria y CPU limitadas."""

    def __init__(
        self,
        default_timeout: int = 60,
        sandbox: str | None = None,
        sandbox_image: str = "alpine",
    ) -> None:
        self._default_timeout = default_timeout
        self._sandbox = sandbox
        self._sandbox_image = sandbox_image
        self._sandbox_checked: bool | None = None
        self._sandbox_error: str = ""

    @property
    def sandbox(self) -> str | None:
        return self._sandbox

    def check_sandbox(self) -> tuple[bool, str]:
        """Verifica que el sandbox exista UNA vez; si falla, fail-closed."""
        if self._sandbox != "docker":
            return True, ""
        if self._sandbox_checked is not None:
            return self._sandbox_checked, self._sandbox_error
        try:
            proc = subprocess.run(
                ["docker", "info", "--format", "{{.ServerVersion}}"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if proc.returncode == 0:
                self._sandbox_checked = True
                return True, ""
            self._sandbox_checked = False
            self._sandbox_error = (proc.stderr or "docker no disponible").strip()[:300]
        except (OSError, subprocess.TimeoutExpired) as exc:
            self._sandbox_checked = False
            self._sandbox_error = str(exc)[:300]
        return False, self._sandbox_error

    def run(self, command: str, timeout: int | None = None) -> ExecResult:
        timeout = timeout or self._default_timeout
        if self._sandbox == "docker":
            ok, err = self.check_sandbox()
            if not ok:
                raise SandboxUnavailable(err)
            return self._run_docker(command, timeout)
        return self._run_local(command, timeout)

    # ------------------------------------------------------------------
    def _run_local(self, command: str, timeout: int) -> ExecResult:
        start = time.monotonic()
        timed_out = False
        kwargs: dict = {}
        if os.name == "nt":
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            kwargs["start_new_session"] = True
        proc = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            **kwargs,
        )
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
            exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            self._kill_tree(proc)
            stdout, stderr = proc.communicate()
            stdout = stdout or ""
            stderr = (stderr or "") + f"\ncomando excedio el timeout de {timeout}s"
            exit_code = -1
        duration_ms = int((time.monotonic() - start) * 1000)
        return ExecResult(stdout, stderr, exit_code, timed_out, duration_ms)

    def _run_docker(self, command: str, timeout: int) -> ExecResult:
        start = time.monotonic()
        try:
            proc = subprocess.run(
                [
                    "docker", "run", "--rm", "--init",
                    "--network=none",
                    "--memory=256m", "--memory-swap=256m",
                    "--cpus=0.5",
                    "--pids-limit=128",
                    self._sandbox_image,
                    "sh", "-c", command,
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )
            return ExecResult(
                proc.stdout,
                proc.stderr,
                proc.returncode,
                False,
                int((time.monotonic() - start) * 1000),
            )
        except subprocess.TimeoutExpired:
            return ExecResult(
                "",
                f"comando excedio el timeout de {timeout}s en sandbox",
                -1,
                True,
                int((time.monotonic() - start) * 1000),
            )

    @staticmethod
    def _kill_tree(proc: subprocess.Popen) -> None:
        """Mata el proceso y todo su arbol (evita procesos huerfanos)."""
        if os.name == "nt":
            try:
                subprocess.run(
                    ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                    capture_output=True,
                    timeout=10,
                )
                return
            except (OSError, subprocess.TimeoutExpired):
                pass
        else:
            try:
                os.killpg(os.getpgid(proc.pid), 9)
                return
            except (OSError, ProcessLookupError):
                pass
        try:
            proc.kill()
        except OSError:
            pass
