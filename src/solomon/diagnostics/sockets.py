import psutil

from .base import DiagnosticCollector
from .status import CollectionResult, CollectionStatus


class SocketsCollector(DiagnosticCollector):
    def collect(self) -> CollectionResult:
        evidence = []
        status = CollectionStatus.SUCCESS

        try:
            connections = psutil.net_connections(kind="all")

            for conn in connections:
                if conn.status != "LISTEN":
                    continue

                raw_data = {
                    "family": int(conn.family),
                    "type": int(conn.type),
                    "laddr_ip": conn.laddr.ip if conn.laddr else None,
                    "laddr_port": conn.laddr.port if conn.laddr else None,
                    "status": conn.status,
                    "pid": conn.pid,
                    "process_name": None,
                }

                if conn.pid:
                    try:
                        proc = psutil.Process(conn.pid)
                        raw_data["process_name"] = proc.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                obs = f"Listening on {raw_data['laddr_ip']}:{raw_data['laddr_port']}"
                if raw_data["process_name"]:
                    obs += f" (PID: {conn.pid}, {raw_data['process_name']})"

                ev = self._create_evidence(
                    category="network.socket",
                    component=f"{raw_data['laddr_ip']}:{raw_data['laddr_port']}",
                    observation=obs,
                    raw_data=raw_data,
                )
                evidence.append(ev)

            return CollectionResult(module_name=self.module_name, status=status, evidence=evidence)
        except psutil.AccessDenied:
            return CollectionResult(
                module_name=self.module_name,
                status=CollectionStatus.INSUFFICIENT_PRIVILEGES,
                evidence=[],
            )
        except Exception as e:
            return CollectionResult(
                module_name=self.module_name,
                status=CollectionStatus.FAILED,
                evidence=[],
                message=str(e),
            )
