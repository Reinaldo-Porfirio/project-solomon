import psutil

from .base import DiagnosticCollector
from .status import CollectionResult, CollectionStatus


class MemoryCollector(DiagnosticCollector):
    """
    Collects Memory diagnostics across platforms using psutil.
    """

    def collect(self) -> CollectionResult:
        evidence = []
        try:
            mem = psutil.virtual_memory()
            swap = psutil.swap_memory()

            raw_data = {
                "total_bytes": mem.total,
                "available_bytes": mem.available,
                "percent_used": mem.percent,
                "swap_total_bytes": swap.total,
                "swap_used_bytes": swap.used,
                "swap_percent_used": swap.percent,
            }

            total_gb = mem.total / (1024**3)
            available_gb = mem.available / (1024**3)

            obs = (
                f"Memory: {available_gb:.1f}GB available out of {total_gb:.1f}GB "
                f"({mem.percent}% used)."
            )

            ev = self._create_evidence(
                category="hardware.memory",
                component="virtual_memory",
                observation=obs,
                raw_data=raw_data,
            )
            evidence.append(ev)
            return CollectionResult(
                module_name="memory", status=CollectionStatus.SUCCESS, evidence=evidence
            )
        except Exception as e:
            return CollectionResult(
                module_name="memory", status=CollectionStatus.FAILED, evidence=[], message=str(e)
            )
