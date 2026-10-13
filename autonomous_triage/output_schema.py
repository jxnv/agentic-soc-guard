"""
Data contracts and Pydantic v2 schemas for autonomous SOC alert triage.
Enforces zero-hallucination structured outputs and ADS-compliant briefs.
"""
from __future__ import annotations

from typing import List, Literal, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


class TriageVerdict(BaseModel):
    """
    Standardized Tier-1 SOC Triage Verdict output contract.
    Enforces deterministic validation and confidence bounds.
    """
    model_config = ConfigDict(extra="ignore")

    alert_id: str = Field(description="Unique identifier of the investigated alert.")
    verdict: Literal["TRUE_POSITIVE", "FALSE_POSITIVE", "SUSPICIOUS_FURTHER_INVESTIGATION"] = Field(
        description="Final triage classification."
    )
    confidence_score: float = Field(
        ge=0.0, le=1.0, description="Calibrated confidence score between 0.00 and 1.00."
    )
    root_cause_analysis: str = Field(
        description="Factual root-cause analysis based strictly on baseline and telemetry evidence."
    )
    mitre_mapping: List[str] = Field(
        default_factory=list, description="Associated MITRE ATT&CK or MITRE ATLAS technique IDs."
    )
    immediate_containment_action: Optional[str] = Field(
        default=None, description="Recommended containment and response action."
    )
    analyst_investigation_notes: str = Field(
        description="Concise notes for Tier-2 SOC escalation or automated case resolution."
    )


class IOCExtraction(BaseModel):
    """Extracted atomic indicators of compromise from raw alert payload."""
    model_config = ConfigDict(extra="ignore")

    ips: List[str] = Field(default_factory=list)
    hashes: List[str] = Field(default_factory=list)
    commands: List[str] = Field(default_factory=list)
    usernames: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    file_paths: List[str] = Field(default_factory=list)


class BaselineTelemetrySummary(BaseModel):
    """Telemetry baseline comparison results from SQLite history."""
    model_config = ConfigDict(extra="ignore")

    historical_occurrences_30d: int = Field(default=0)
    is_known_service_account: bool = Field(default=False)
    user_activity_profile: str = Field(default="Unknown")
    deviations_observed: List[str] = Field(default_factory=list)


class EnrichmentTelemetry(BaseModel):
    """Deterministic enrichment outputs (Entropy, CIDR, Heuristics)."""
    model_config = ConfigDict(extra="ignore")

    cidr_breakdown: Dict[str, str] = Field(default_factory=dict)
    shannon_entropy_scores: Dict[str, float] = Field(default_factory=dict)
    heuristics_flagged: List[str] = Field(default_factory=list)


class TriageInvestigationBrief(BaseModel):
    """Complete ADS-compliant (Alert Disposition System) investigation dossier."""
    model_config = ConfigDict(extra="ignore")

    alert_id: str
    rule_name: str
    timestamp: str
    verdict: TriageVerdict
    iocs: IOCExtraction
    baseline: BaselineTelemetrySummary
    enrichment: EnrichmentTelemetry
    ads_markdown_brief: str
