"""
Core domain models for Solomon.
"""

from .evidence import Evidence
from .exceptions import (
    CapabilityError,
    CollectionError,
    ConfigurationError,
    PrivilegeError,
    ScopeError,
    SolomonException,
    ValidationError,
)
from .findings import Finding, FindingSeverity, FindingStatus
from .scope import Asset, EngagementPolicy, Scope
from .scoring import HealthScore, RiskFactor, RiskScore

__all__ = [
    "Evidence",
    "Finding",
    "FindingSeverity",
    "FindingStatus",
    "Scope",
    "Asset",
    "EngagementPolicy",
    "RiskScore",
    "HealthScore",
    "RiskFactor",
    "SolomonException",
    "ConfigurationError",
    "CapabilityError",
    "PrivilegeError",
    "CollectionError",
    "ValidationError",
    "ScopeError",
]
