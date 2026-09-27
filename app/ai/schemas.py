from typing import List, Optional

from pydantic import BaseModel, Field


# ============================================================
# INPUT SCHEMAS
# ============================================================

class AIEmailMetadata(BaseModel):
    sender: Optional[str] = None
    reply_to: Optional[str] = None
    subject: Optional[str] = None
    date: Optional[str] = None


class AIAuthenticationEvidence(BaseModel):
    spf: Optional[str] = None
    dkim: Optional[str] = None
    dmarc: Optional[str] = None


class AIURL(BaseModel):
    url: str
    hostname: Optional[str] = None


class AIAttachment(BaseModel):
    filename: Optional[str] = None
    content_type: Optional[str] = None
    size: Optional[int] = None


class AIDeterministicAnalysis(BaseModel):
    threat: Optional[str] = None
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None
    findings: List[str] = Field(default_factory=list)


class AIInfrastructure(BaseModel):
    hostname: Optional[str] = None
    ip: Optional[str] = None
    country: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    isp: Optional[str] = None
    organization: Optional[str] = None
    asn: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    vpn: Optional[bool] = None
    proxy: Optional[bool] = None
    tor: Optional[bool] = None
    confidence: Optional[float] = None
    provider: Optional[str] = None


class AIBERTSignal(BaseModel):
    """
    Optional machine-learning signal.

    This is treated as a model signal, NOT as ground truth.
    """

    classification: Optional[str] = None
    confidence: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
    )
    model: Optional[str] = None


class AIInvestigationInput(BaseModel):
    email: AIEmailMetadata
    body: str = ""

    authentication: AIAuthenticationEvidence = Field(
        default_factory=AIAuthenticationEvidence
    )

    urls: List[AIURL] = Field(default_factory=list)

    attachments: List[AIAttachment] = Field(
        default_factory=list
    )

    deterministic_analysis: AIDeterministicAnalysis = Field(
        default_factory=AIDeterministicAnalysis
    )

    infrastructure: List[AIInfrastructure] = Field(
        default_factory=list
    )

    bert_signal: Optional[AIBERTSignal] = None


# ============================================================
# EVIDENCE FUSION INPUT
# ============================================================

class AIEvidenceItem(BaseModel):
    """
    A single observed or derived evidence item.

    source tells Gemini where the evidence came from.
    """

    category: str
    observation: str
    source: str
    significance: Optional[str] = None


class AIEvidenceCorrelation(BaseModel):
    """
    Represents a relationship between multiple pieces of evidence.
    """

    evidence: List[str] = Field(default_factory=list)

    conclusion: str

    confidence: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
    )


class AIEvidenceFusion(BaseModel):
    """
    Unified evidence package supplied to the AI reasoning layer.
    """

    observed_evidence: List[AIEvidenceItem] = Field(
        default_factory=list
    )

    deterministic_findings: List[str] = Field(
        default_factory=list
    )

    infrastructure_evidence: List[AIInfrastructure] = Field(
        default_factory=list
    )

    bert_signal: Optional[AIBERTSignal] = None


# ============================================================
# GEMINI OUTPUT SCHEMAS
# ============================================================

class AIKeyFinding(BaseModel):
    finding: str
    explanation: str
    evidence: Optional[str] = None


class AISocialEngineering(BaseModel):
    technique: str
    confidence: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
    )


class AIInvestigationInput(BaseModel):
    email: AIEmailMetadata
    body: str = ""

    authentication: AIAuthenticationEvidence = Field(
        default_factory=AIAuthenticationEvidence
    )

    urls: List[AIURL] = Field(default_factory=list)

    attachments: List[AIAttachment] = Field(
        default_factory=list
    )

    deterministic_analysis: AIDeterministicAnalysis = Field(
        default_factory=AIDeterministicAnalysis
    )

    infrastructure: List[AIInfrastructure] = Field(
        default_factory=list
    )

    bert_signal: Optional[AIBERTSignal] = None

    evidence_fusion: Optional[AIEvidenceFusion] = None