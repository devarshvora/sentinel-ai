from typing import Literal

from pydantic import BaseModel, Field


RiskLevel = Literal[
    "low",
    "moderate",
    "high",
    "critical",
]


class RedFlag(BaseModel):
    category: str = Field(
        description="Machine-readable red-flag category."
    )
    evidence: str = Field(
        description="Short exact evidence fragment from the submitted content."
    )
    severity: RiskLevel
    explanation: str
    confidence: float = Field(
        ge=0.0,
        le=1.0,
    )


class ManipulationProfile(BaseModel):
    urgency: int = Field(
        ge=0,
        le=100,
    )
    authority: int = Field(
        ge=0,
        le=100,
    )
    reward: int = Field(
        ge=0,
        le=100,
    )
    fear: int = Field(
        ge=0,
        le=100,
    )
    secrecy: int = Field(
        ge=0,
        le=100,
    )
    isolation: int = Field(
        ge=0,
        le=100,
    )


class AttackStage(BaseModel):
    stage_number: int = Field(
        ge=1,
    )
    stage_name: str
    description: str
    evidence: str | None = None
    confirmed: bool = False


class FollowUpQuestion(BaseModel):
    question_id: str
    question: str
    reason: str
    impact_if_yes: str
    impact_if_no: str


class ThreatFingerprint(BaseModel):
    primary_pattern: str
    payment_method: str | None = None
    impersonation_target: str | None = None
    requested_assets: list[str] = Field(
        default_factory=list
    )
    signature_tags: list[str] = Field(
        default_factory=list
    )


class InvestigationRequest(BaseModel):
    content: str = Field(
        min_length=10,
    )
    input_type: str = "text"
    source_name: str | None = None
    claimed_company: str | None = None
    sender_email: str | None = None
    follow_up_answers: dict[str, str] = Field(
        default_factory=dict
    )


class InvestigationResult(BaseModel):
    case_id: str
    risk_score: int = Field(
        ge=0,
        le=100,
    )
    risk_level: RiskLevel
    threat_type: str
    confidence: float = Field(
        ge=0.0,
        le=1.0,
    )
    summary: str
    attacker_objectives: list[str] = Field(
        default_factory=list
    )
    red_flags: list[RedFlag] = Field(
        default_factory=list
    )
    manipulation_profile: ManipulationProfile
    attack_path: list[AttackStage] = Field(
        default_factory=list
    )
    missing_evidence: list[str] = Field(
        default_factory=list
    )
    follow_up_questions: list[FollowUpQuestion] = Field(
        default_factory=list
    )
    recommended_actions: list[str] = Field(
        default_factory=list
    )
    threat_fingerprint: ThreatFingerprint