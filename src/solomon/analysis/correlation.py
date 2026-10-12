"""Deterministic correlation, preserving the confidence and all supporting evidence."""

import hashlib
from dataclasses import dataclass

from solomon.analysis.rules import RuleMatch, RuleRegistry
from solomon.core.evidence import Evidence
from solomon.core.findings import Finding, FindingStatus

LOCAL_DETAILS = {
    "WIN-FW-001": (
        "Um perfil sem firewall pode deixar tráfego sem filtragem quando estiver ativo.",
        "Revise o perfil de rede ativo e habilite o firewall após revisar as regras necessárias.",
        "Confirme o estado com Get-NetFirewallProfile e repita a auditoria.",
    ),
    "WIN-RDP-001": (
        "O listener RDP pode ficar acessível na rede se o perfil permissivo for aplicável.",
        "Restrinja origens de RDP, revise o perfil ativo e exija autenticação de nível de rede.",
        "Confirme perfil da interface, regras efetivas de firewall e alcance em um teste "
        "autorizado.",
    ),
    "WIN-SVC-001": (
        "O listener aumenta a superfície de rede; não prova vulnerabilidade do serviço.",
        "Verifique se impressão remota é necessária e restrinja o alcance quando apropriado.",
        "Relacione PID do serviço ao socket e repita a coleta.",
    ),
    "LINUX-FW-001": (
        "Ausência de filtragem pode ampliar exposição de serviços da máquina.",
        "Revise regras e requisitos antes de habilitar o firewall.",
        "Confirme o backend de firewall e repita a auditoria.",
    ),
    "LINUX-SSH-001": (
        "SSH está disponível em uma interface de rede; configuração segura deve ser revisada.",
        "Revise autenticação, origens permitidas e regras de firewall.",
        "Confirme bind, firewall e configuração SSH; o listener não prova falha.",
    ),
}


@dataclass
class CorrelationResult:
    rule_id: str
    triggered: bool
    matched_conditions: list[str]
    missing_conditions: list[str]
    finding: Finding | None = None


class CorrelationEngine:
    def __init__(self):
        self.rules_by_id = {rule.rule_id: rule for rule in RuleRegistry.get_all()}

    def correlate(
        self, matches: list[RuleMatch], all_evidence: list[Evidence]
    ) -> list[CorrelationResult]:
        evidence_by_id = {ev.evidence_id: ev for ev in all_evidence}
        results = []
        for rule_id, rule in sorted(self.rules_by_id.items()):
            groups: dict[str, list[RuleMatch]] = {}
            for match in matches:
                if match.rule_id == rule_id:
                    groups.setdefault(match.asset, []).append(match)
            if not groups:
                groups["localhost"] = []
            for asset, rule_matches in sorted(groups.items()):
                requirements = rule.get_correlation_requirements()
                conditions: dict[str, list[RuleMatch]] = {}
                for match in rule_matches:
                    conditions.setdefault(match.condition_name, []).append(match)
                matched = [
                    req.description for req in requirements if req.condition_name in conditions
                ]
                missing = [
                    req.description for req in requirements if req.condition_name not in conditions
                ]
                triggered = bool(requirements) and all(
                    not req.required or req.condition_name in conditions for req in requirements
                )
                ids = sorted(
                    {
                        key
                        for req in requirements
                        for match in conditions.get(req.condition_name, [])
                        for key in match.evidence_ids
                    }
                )
                # Unknown/missing provenance cannot create a finding.
                triggered = triggered and bool(ids) and all(key in evidence_by_id for key in ids)
                finding = None
                if triggered:
                    linked = [evidence_by_id[key] for key in ids]
                    confidence = min(
                        [ev.confidence for ev in linked]
                        + [match.confidence for match in rule_matches]
                    )
                    identity = f"{rule_id}|{asset}|{'|'.join(ids)}"
                    digest = hashlib.sha256(identity.encode()).hexdigest()[:12].upper()
                    impact, recommendation, verification = LOCAL_DETAILS.get(
                        rule_id,
                        (
                            "Impacto precisa de validação contextual.",
                            "Revise a configuração documentada.",
                            "Repita a coleta após a correção.",
                        ),
                    )
                    finding = Finding(
                        finding_id=f"{rule_id}-{digest}",
                        title=rule.name,
                        category=rule.category,
                        severity=rule.severity,
                        confidence=confidence,
                        asset=asset,
                        component=linked[0].component,
                        description=rule.description,
                        evidence_ids=ids,
                        evidence=linked,
                        rules=[rule_id],
                        status=FindingStatus.OPEN,
                        timestamp=min(ev.timestamp for ev in linked),
                        reasoning=" ".join(sorted({match.explanation for match in rule_matches})),
                        impact=impact,
                        recommendation=recommendation,
                        verification=verification,
                        reproduction_steps=[
                            "Execute solomon audit na máquina autorizada.",
                            "Compare os serviços, listeners e perfis com as evidências vinculadas.",
                            verification,
                        ],
                        limitations="Coleta local não comprova alcance pela Internet, exploração "
                        "ou perfil efetivamente aplicado a cada interface.",
                        classification="observation"
                        if rule.severity.value == "INFORMATIONAL"
                        else "configuration",
                    )
                results.append(CorrelationResult(rule_id, triggered, matched, missing, finding))
        return results
