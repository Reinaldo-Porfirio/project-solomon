import psutil

from .base import DiagnosticCollector
from .status import CollectionResult, CollectionStatus


class NetworkCollector(DiagnosticCollector):
    def collect(self) -> CollectionResult:
        evidence = []
        status = CollectionStatus.SUCCESS

        try:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()

            for iface_name, iface_addrs in addrs.items():
                iface_stat = stats.get(iface_name)

                raw_data = {
                    "interface": iface_name,
                    "is_up": iface_stat.isup if iface_stat else None,
                    "mtu": iface_stat.mtu if iface_stat else None,
                    "addresses": [],
                }

                for addr in iface_addrs:
                    raw_data["addresses"].append(
                        {
                            "family": int(addr.family),
                            "address": addr.address,
                            "netmask": addr.netmask,
                            "broadcast": addr.broadcast,
                            "ptp": addr.ptp,
                        }
                    )

                up_state = "UP" if raw_data["is_up"] else "DOWN"

                ev = self._create_evidence(
                    category="network.interface",
                    component=iface_name,
                    observation=(
                        f"Interface {iface_name} is {up_state} with "
                        f"{len(raw_data['addresses'])} addresses assigned."
                    ),
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
