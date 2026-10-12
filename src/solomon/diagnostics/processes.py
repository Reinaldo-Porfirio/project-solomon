import psutil

from .base import DiagnosticCollector
from .status import CollectionResult, CollectionStatus


class ProcessesCollector(DiagnosticCollector):
    def collect(self) -> CollectionResult:
        evidence = []
        status = CollectionStatus.SUCCESS

        try:
            for proc in psutil.process_iter(["pid", "name", "exe", "ppid", "username", "status"]):
                try:
                    info = proc.info

                    # Try to get cpu and memory gracefully
                    try:
                        info["cpu_percent"] = proc.cpu_percent()
                        info["memory_percent"] = proc.memory_percent()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        info["cpu_percent"] = 0.0
                        info["memory_percent"] = 0.0

                    # Command line might be restricted
                    try:
                        info["cmdline"] = proc.cmdline()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        info["cmdline"] = []

                    ev = self._create_evidence(
                        category="os.process",
                        component=str(info["pid"]),
                        observation=(
                            f"Process {info.get('name', 'unknown')} (PID: {info['pid']}) "
                            f"running as {info.get('username', 'unknown')}"
                        ),
                        raw_data=info,
                    )
                    evidence.append(ev)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    status = CollectionStatus.PARTIAL
                    continue

            return CollectionResult(module_name=self.module_name, status=status, evidence=evidence)
        except Exception as e:
            return CollectionResult(
                module_name=self.module_name,
                status=CollectionStatus.FAILED,
                evidence=[],
                message=str(e),
            )
