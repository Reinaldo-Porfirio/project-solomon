import logging
import os
import subprocess
from dataclasses import dataclass


@dataclass
class SubprocessResult:
    stdout: str
    stderr: str
    returncode: int
    success: bool
    error_message: str | None = None


class SafeSubprocess:
    """
    Centralized abstraction for safe subprocess execution.
    Handles timeout, capture, exit codes, and error classification.
    Never uses shell=True.
    """

    def __init__(self, timeout: int = 15):
        self.timeout = timeout
        self.logger = logging.getLogger("solomon.subprocess")

    def run(self, cmd: list[str]) -> SubprocessResult:
        try:
            # We don't log the exact full command if it might contain secrets,
            # but for this milestone it's mostly static providers.
            self.logger.debug(f"Executing: {cmd[0]}")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
                shell=False,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )

            return SubprocessResult(
                stdout=result.stdout.strip(),
                stderr=result.stderr.strip(),
                returncode=result.returncode,
                success=(result.returncode == 0),
            )

        except subprocess.TimeoutExpired as e:
            return SubprocessResult(
                "", "", -1, False, f"Command timed out after {self.timeout}s: {e}"
            )
        except FileNotFoundError as e:
            return SubprocessResult("", "", -1, False, f"Executable not found: {e}")
        except Exception as e:
            return SubprocessResult("", "", -1, False, f"Execution error: {e}")
