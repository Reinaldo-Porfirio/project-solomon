import psutil

from .base import DiagnosticCollector
from .status import CollectionResult, CollectionStatus


class CPUCollector(DiagnosticCollector):
    """
    Collects CPU diagnostics across platforms using psutil.
    """

    def collect(self) -> CollectionResult:
        evidence = []
        try:
            # CPU count
            logical_cores = psutil.cpu_count(logical=True)
            physical_cores = psutil.cpu_count(logical=False)

            # CPU usage
            cpu_usage_per_core = psutil.cpu_percent(interval=1, percpu=True)
            overall_usage = (
                sum(cpu_usage_per_core) / len(cpu_usage_per_core) if cpu_usage_per_core else 0.0
            )

            raw_data = {
                "logical_cores": logical_cores,
                "physical_cores": physical_cores,
                "overall_usage_percent": overall_usage,
                "core_usage_percent": cpu_usage_per_core,
            }

            obs = f"CPU Load is at {overall_usage:.1f}% across {logical_cores} logical cores."

            ev = self._create_evidence(
                category="hardware.cpu", component="cpu_load", observation=obs, raw_data=raw_data
            )
            evidence.append(ev)
            return CollectionResult(
                module_name="cpu", status=CollectionStatus.SUCCESS, evidence=evidence
            )
        except Exception as e:
            return CollectionResult(
                module_name="cpu", status=CollectionStatus.FAILED, evidence=[], message=str(e)
            )
