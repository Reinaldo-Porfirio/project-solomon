import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from solomon.core.evidence import Evidence
from solomon.core.findings import FindingSeverity


@dataclass
class RuleMatch:
    """
    Represents a specific condition matched by a rule, tied to explicit evidence.
    """

    match_id: str = field(default_factory=lambda: f"RM-{uuid.uuid4().hex[:8].upper()}")
    rule_id: str = ""
    condition_name: str = ""
    evidence_ids: list[str] = field(default_factory=list)
    asset: str = "localhost"
    component: str = "system"
    confidence: float = 1.0
    explanation: str = ""


@dataclass
class CorrelationRequirement:
    condition_name: str
    description: str
    required: bool = True


class Rule(ABC):
    """
    Base class for all security rules.
    A rule evaluates raw evidence and outputs RuleMatches. It does NOT generate Findings.
    """

    rule_id: str
    name: str
    description: str
    category: str
    severity: FindingSeverity
    platforms: list[str]

    def __init__(self):
        # Enforce that subclasses define required attributes
        assert hasattr(self, "rule_id"), "Rule must define rule_id"
        assert hasattr(self, "name"), "Rule must define name"
        assert hasattr(self, "category"), "Rule must define category"
        assert hasattr(self, "severity"), "Rule must define severity"

    @abstractmethod
    def evaluate(self, evidence: list[Evidence]) -> list[RuleMatch]:
        """
        Evaluate evidence and return all matches for this rule's conditions.
        """
        pass

    @abstractmethod
    def get_correlation_requirements(self) -> list[CorrelationRequirement]:
        """
        Define the explicit conditions required to trigger a finding for this rule.
        """
        pass


class RuleRegistry:
    """
    Maintains a registry of all available rules.
    """

    _rules: dict[str, Rule] = {}

    @classmethod
    def register(cls, rule_class: type[Rule]):
        rule_instance = rule_class()
        cls._rules[rule_instance.rule_id] = rule_instance
        return rule_class

    @classmethod
    def get_all(cls) -> list[Rule]:
        return list(cls._rules.values())

    @classmethod
    def get_for_platform(cls, platform: str) -> list[Rule]:
        # Simple string matching for platform applicability
        platform_lower = platform.lower()
        applicable = []
        for rule in cls._rules.values():
            if not getattr(rule, "platforms", None):
                applicable.append(rule)  # Applies to all if not specified
                continue

            for p in rule.platforms:
                if p.lower() in platform_lower or platform_lower in p.lower():
                    applicable.append(rule)
                    break
        return applicable


class RuleEngine:
    """
    Executes rules against evidence.
    """

    def __init__(self, rules: list[Rule]):
        self.rules = rules

    def evaluate(self, evidence: list[Evidence]) -> list[RuleMatch]:
        all_matches = []
        for rule in self.rules:
            try:
                matches = rule.evaluate(evidence)
                for m in matches:
                    m.rule_id = rule.rule_id  # Ensure rule_id is attached
                all_matches.extend(matches)
            except Exception as e:
                import logging

                logging.getLogger("solomon").error(f"Rule {rule.rule_id} failed evaluation: {e}")

        return all_matches
