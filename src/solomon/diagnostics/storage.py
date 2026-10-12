import psutil

from .base import DiagnosticCollector
from .status import CollectionResult, CollectionStatus


class StorageCollector(DiagnosticCollector):
    """
    Collects Storage diagnostics across platforms using psutil.
    """

    def collect(self) -> CollectionResult:
        evidence = []
        status = CollectionStatus.SUCCESS
        unavailable = []
        try:
            partitions = psutil.disk_partitions(all=False)

            for part in partitions:
                try:
                    usage = psutil.disk_usage(part.mountpoint)

                    raw_data = {
                        "device": part.device,
                        "mountpoint": part.mountpoint,
                        "fstype": part.fstype,
                        "opts": part.opts,
                        "total_bytes": usage.total,
                        "used_bytes": usage.used,
                        "free_bytes": usage.free,
                        "percent_used": usage.percent,
                    }

                    total_gb = usage.total / (1024**3)
                    free_gb = usage.free / (1024**3)

                    obs = (
                        f"Partition {part.mountpoint} ({part.fstype}): "
                        f"{free_gb:.1f}GB free of {total_gb:.1f}GB ({usage.percent}% used)."
                    )

                    ev = self._create_evidence(
                        category="hardware.storage",
                        component=part.mountpoint,
                        observation=obs,
                        raw_data=raw_data,
                    )
                    evidence.append(ev)
                except (OSError, psutil.Error) as exc:
                    status = CollectionStatus.PARTIAL
                    unavailable.append(f"{part.mountpoint}: {exc}")
                    continue

            return CollectionResult(
                module_name="storage",
                status=status,
                evidence=evidence,
                message="; ".join(unavailable) or None,
            )
        except Exception as e:
            return CollectionResult(
                module_name="storage", status=CollectionStatus.FAILED, evidence=[], message=str(e)
            )
