from typing import List, Optional

from pydantic import BaseModel, Field


# ============================================================
# OBSERVED EMAIL EVIDENCE
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


# ============================================================
# DETERMINISTIC FORENSIC ANALYSIS
# ============================================================

class AIDeterministicAnalysis(BaseModel):
    threat: Optional[str] = None
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None
    findings: List[str] = Field(default_factory=list)


# ============================================================
# INFRASTRUCTURE INTELLIGENCE
# ============================================================

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


# ============================================================
# COMPLETE INPUT SENT TO THE AI LAYER
# ============================================================

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


# ============================================================
# AI INTERPRETATION
# ============================================================

class AIKeyFinding(BaseModel):
    finding: str
    explanation: str
    evidence: Optional[str] = None


class AISocialEngineering(BaseModel):
    technique: str
    confidence: Optional[float] = None


class AIInvestigationOutput(BaseModel):
    classification: str

    confidence: float = Field(
        ge=0.0,
        le=1.0
    )

    summary: str

    key_findings: List[AIKeyFinding] = Field(
        default_factory=list
    )

    social_engineering: List[AISocialEngineering] = Field(
        default_factory=list
    )

    recommended_action: Optional[str] = None

    uncertainties: List[str] = Field(
        default_factory=list
    )