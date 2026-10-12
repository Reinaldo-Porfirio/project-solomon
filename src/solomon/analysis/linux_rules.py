from solomon.analysis.rules import CorrelationRequirement, Rule, RuleMatch, RuleRegistry
from solomon.core.evidence import Evidence
from solomon.core.findings import FindingSeverity


@RuleRegistry.register
class LinuxFW001(Rule):
    rule_id = "LINUX-FW-001"
    name = "Firewall Inactive"
    description = (
        "The system firewall (ufw, iptables, nftables) is explicitly disabled or inactive."
    )
    category = "Firewall"
    severity = FindingSeverity.MEDIUM
    platforms = ["Linux"]

    def get_correlation_requirements(self) -> list[CorrelationRequirement]:
        return [CorrelationRequirement("fw_inactive", "Firewall is inactive", required=True)]

    def evaluate(self, evidence: list[Evidence]) -> list[RuleMatch]:
        matches = []
        for ev in evidence:
            if ev.category == "network.firewall":
                output = ev.raw_data.get("output", "").lower()
                backend = ev.raw_data.get("backend", "").lower()
                if backend == "ufw" and "status: inactive" in output:
                    matches.append(
                        RuleMatch(
                            condition_name="fw_inactive",
                            evidence_ids=[ev.evidence_id],
                            explanation="UFW reports status as inactive.",
                        )
                    )
        return matches


@RuleRegistry.register
class LinuxSSH001(Rule):
    rule_id = "LINUX-SSH-001"
    name = "Insecure SSH Exposure"
    description = "SSH is enabled and externally reachable."
    category = "Remote Access"
    severity = FindingSeverity.MEDIUM
    platforms = ["Linux"]

    def get_correlation_requirements(self) -> list[CorrelationRequirement]:
        return [
            CorrelationRequirement("ssh_running", "SSH service is running", required=True),
            CorrelationRequirement(
                "ssh_external", "SSH is bound to an external interface", required=True
            ),
        ]

    def evaluate(self, evidence: list[Evidence]) -> list[RuleMatch]:
        matches = []
        for ev in evidence:
            if ev.category == "os.service" and ev.component in ("ssh", "sshd"):
                if ev.raw_data.get("sub") == "running":
                    matches.append(
                        RuleMatch(
                            condition_name="ssh_running",
                            evidence_ids=[ev.evidence_id],
                            explanation="SSH service is running.",
                        )
                    )
            elif ev.category == "network.socket":
                if ev.raw_data.get("laddr_port") == 22 and ev.raw_data.get("status") == "LISTEN":
                    ip = ev.raw_data.get("laddr_ip")
                    if ip and ip not in ("127.0.0.1", "::1"):
                        matches.append(
                            RuleMatch(
                                condition_name="ssh_external",
                                evidence_ids=[ev.evidence_id],
                                explanation=f"SSH listening on external interface {ip}.",
                            )
                        )
        return matches


@RuleRegistry.register
class LinuxNet001(Rule):
    rule_id = "LINUX-NET-001"
    name = "Unnecessary Externally Reachable Service"
    description = "A generic service (e.g., Telnet, FTP) is exposed externally."
    category = "Network"
    severity = FindingSeverity.MEDIUM
    platforms = ["Linux"]

    def get_correlation_requirements(self) -> list[CorrelationRequirement]:
        return [CorrelationRequirement("net_exposed", "Unnecessary service exposed")]

    def evaluate(self, evidence: list[Evidence]) -> list[RuleMatch]:
        return []


@RuleRegistry.register
class LinuxAcc001(Rule):
    rule_id = "LINUX-ACC-001"
    name = "Risky Privileged Account"
    description = "A privileged account (like root) is misconfigured."
    category = "Accounts"
    severity = FindingSeverity.MEDIUM
    platforms = ["Linux"]

    def get_correlation_requirements(self) -> list[CorrelationRequirement]:
        return [CorrelationRequirement("acc_risky", "Account configuration is risky")]

    def evaluate(self, evidence: list[Evidence]) -> list[RuleMatch]:
        return []
