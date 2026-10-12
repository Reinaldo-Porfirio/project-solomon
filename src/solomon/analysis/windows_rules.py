"""Windows configuration rules; listener bindings do not prove remote reachability."""

import ipaddress

from solomon.analysis.rules import CorrelationRequirement, Rule, RuleMatch, RuleRegistry
from solomon.core.evidence import Evidence
from solomon.core.findings import FindingSeverity


def non_loopback(value: str | None) -> bool:
    try:
        return value is not None and not ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def firewall_disabled(value) -> bool:
    # New collectors return booleans; older snapshots used CIM values 1=True, 2=False.
    return value is False or (type(value) is int and value in (0, 2))


@RuleRegistry.register
class WinRDP001(Rule):
    rule_id = "WIN-RDP-001"
    name = "RDP bound to network with a weak firewall profile"
    description = (
        "RDP is running on a non-loopback listener and a firewall profile is permissive. "
        "Remote reachability and the active interface profile have not been verified."
    )
    category = "Remote Access"
    severity = FindingSeverity.MEDIUM
    platforms = ["Windows"]

    def get_correlation_requirements(self) -> list[CorrelationRequirement]:
        return [
            CorrelationRequirement("rdp_enabled", "RDP service is enabled and running"),
            CorrelationRequirement("rdp_listener", "TCP/3389 listener exists"),
            CorrelationRequirement("rdp_external", "Listener is bound to a non-loopback address"),
            CorrelationRequirement("rdp_firewall", "A firewall profile is disabled or permissive"),
        ]

    def evaluate(self, evidence: list[Evidence]) -> list[RuleMatch]:
        matches = []
        for ev in evidence:
            if (
                ev.category == "os.service"
                and ev.component.lower() == "termservice"
                and ev.raw_data.get("State") == "Running"
            ):
                matches.append(
                    RuleMatch(
                        condition_name="rdp_enabled",
                        evidence_ids=[ev.evidence_id],
                        explanation="TermService is running.",
                    )
                )
            elif (
                ev.category == "network.socket"
                and ev.raw_data.get("laddr_port") == 3389
                and ev.raw_data.get("status") == "LISTEN"
            ):
                matches.append(
                    RuleMatch(
                        condition_name="rdp_listener",
                        evidence_ids=[ev.evidence_id],
                        explanation=f"TCP 3389 listener, PID {ev.raw_data.get('pid')}.",
                    )
                )
                ip = ev.raw_data.get("laddr_ip")
                if non_loopback(ip):
                    matches.append(
                        RuleMatch(
                            condition_name="rdp_external",
                            evidence_ids=[ev.evidence_id],
                            explanation=f"Listener bind {ip}; remote reachability is unverified.",
                        )
                    )
            elif ev.category == "network.firewall":
                for profile in ev.raw_data.get("profiles", []):
                    enabled = profile.get("Enabled")
                    inbound = profile.get("DefaultInboundAction")
                    if firewall_disabled(enabled) or (
                        enabled in (True, 1) and inbound in ("Allow", 2)
                    ):
                        matches.append(
                            RuleMatch(
                                condition_name="rdp_firewall",
                                evidence_ids=[ev.evidence_id],
                                explanation=f"Profile {profile.get('Name')}: Enabled={enabled}, "
                                f"DefaultInboundAction={inbound}; active profile unverified.",
                            )
                        )
        return matches


@RuleRegistry.register
class WinFW001(Rule):
    rule_id = "WIN-FW-001"
    name = "Firewall Profile Disabled"
    description = "One or more Windows Defender Firewall profiles are disabled."
    category = "Firewall"
    severity = FindingSeverity.MEDIUM
    platforms = ["Windows"]

    def get_correlation_requirements(self) -> list[CorrelationRequirement]:
        return [CorrelationRequirement("fw_disabled", "Firewall profile explicitly disabled")]

    def evaluate(self, evidence: list[Evidence]) -> list[RuleMatch]:
        matches = []
        for ev in evidence:
            if ev.category == "network.firewall" and ev.component == "Windows Defender Firewall":
                names = sorted(
                    profile.get("Name", "Unknown")
                    for profile in ev.raw_data.get("profiles", [])
                    if firewall_disabled(profile.get("Enabled"))
                )
                if names:
                    matches.append(
                        RuleMatch(
                            condition_name="fw_disabled",
                            evidence_ids=[ev.evidence_id],
                            explanation=f"Disabled firewall profiles: {', '.join(names)}.",
                        )
                    )
        return matches


@RuleRegistry.register
class WinSVC001(Rule):
    rule_id = "WIN-SVC-001"
    name = "Print Spooler network listener observed"
    description = "A running Spooler has a non-loopback listener; exploitability is unverified."
    category = "Services"
    severity = FindingSeverity.INFORMATIONAL
    platforms = ["Windows"]

    def get_correlation_requirements(self) -> list[CorrelationRequirement]:
        return [
            CorrelationRequirement("svc_running", "Print Spooler is running"),
            CorrelationRequirement("svc_listener", "Matching process has a non-loopback listener"),
        ]

    def evaluate(self, evidence: list[Evidence]) -> list[RuleMatch]:
        matches = []
        services = [
            ev
            for ev in evidence
            if ev.category == "os.service"
            and ev.raw_data.get("Name") == "Spooler"
            and ev.raw_data.get("State") == "Running"
        ]
        for service in services:
            pid = service.raw_data.get("ProcessId")
            for sock in evidence:
                if (
                    sock.category == "network.socket"
                    and sock.raw_data.get("status") == "LISTEN"
                    and non_loopback(sock.raw_data.get("laddr_ip"))
                    and (
                        (pid and pid == sock.raw_data.get("pid"))
                        or (
                            not pid
                            and sock.raw_data.get("process_name", "").lower() == "spoolsv.exe"
                        )
                    )
                ):
                    matches.extend(
                        [
                            RuleMatch(
                                condition_name="svc_running",
                                evidence_ids=[service.evidence_id],
                                explanation="Print Spooler is running.",
                            ),
                            RuleMatch(
                                condition_name="svc_listener",
                                evidence_ids=[sock.evidence_id],
                                explanation="Print Spooler process owns a non-loopback listener.",
                            ),
                        ]
                    )
        return matches


@RuleRegistry.register
class WinAcc001(Rule):
    rule_id = "WIN-ACC-001"
    name = "Risky Privileged Account"
    description = "Reserved rule; account evidence collection is not implemented."
    category = "Accounts"
    severity = FindingSeverity.MEDIUM
    platforms = ["Windows"]

    def get_correlation_requirements(self) -> list[CorrelationRequirement]:
        return [CorrelationRequirement("acc_risky", "Account configuration is risky")]

    def evaluate(self, evidence: list[Evidence]) -> list[RuleMatch]:
        return []


@RuleRegistry.register
class WinUpdate001(Rule):
    rule_id = "WIN-UPDATE-001"
    name = "Security Updates Pending"
    description = "Reserved rule; update evidence collection is not implemented."
    category = "Updates"
    severity = FindingSeverity.HIGH
    platforms = ["Windows"]

    def get_correlation_requirements(self) -> list[CorrelationRequirement]:
        return [CorrelationRequirement("update_missing", "Critical update missing")]

    def evaluate(self, evidence: list[Evidence]) -> list[RuleMatch]:
        return []
