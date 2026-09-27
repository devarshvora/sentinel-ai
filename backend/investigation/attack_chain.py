"""Reconstruct supported observations and explicitly hypothetical consequences."""
from typing import Literal

from pydantic import BaseModel, Field

from backend.investigation.risk_engine import ACTION_RULES


class ChainStage(BaseModel):
    stage_number: int = Field(ge=1)
    name: str
    description: str
    status: Literal["confirmed", "possible", "predicted", "prevented"]
    evidence: str = ""


class ChainReconstruction(BaseModel):
    attack_chain: list[ChainStage]
    current_stage: str
    current_stage_explanation: str
    likely_next_step: str | None


def reconstruct_chain(signals: dict, actions: dict, has_url: bool, model_score: int) -> ChainReconstruction:
    stages = []

    def add(name, description, status, evidence=""):
        stages.append(ChainStage(stage_number=len(stages) + 1, name=name, description=description, status=status, evidence=evidence))

    order = ("brand_impersonation", "impersonation", "urgency", "secrecy", "brand_domain_mismatch", "suspicious_domain", "shortened_url", "credential_request", "payment_request", "identity_request")
    for signal in order:
        if signal not in signals:
            continue
        evidence = signals[signal]
        possible = signal in {"impersonation", "brand_impersonation"}
        add(signal.replace("_", " ").title(),
            "Possible impersonation inferred from submitted evidence." if possible else "Observed indicator; its presence alone does not prove fraud.",
            "possible" if possible else "confirmed", evidence)
    for action in ACTION_RULES:
        if actions.get(action) is True:
            add(action.replace("_", " ").title(), "User reports this interaction occurred; downstream harm is not established.", "confirmed", "User answered yes")
    reported = [key for key in ACTION_RULES if actions.get(key) is True]
    current = reported[-1] if reported else "before_interaction" if all(value is False for value in actions.values()) else "unknown"
    explanation = (
        "Reported interactions: " + ", ".join(key.replace("_", " ") for key in reported) + ". Multiple exposure types can coexist."
        if reported else "User explicitly reports no listed interactions."
        if current == "before_interaction" else "Interaction history is incomplete. No click, disclosure, or payment is assumed."
    )
    next_step = None
    if signals or model_score >= 40 or reported:
        if actions.get("credentials_entered") or actions.get("otp_shared"):
            next_step = "account_takeover"
            add("Account takeover", "An attacker could attempt to use the disclosed credentials or code.", "predicted")
        elif "credential_request" in signals or has_url:
            next_step = "credential_capture"
            add("Credential capture", "A linked page could request login details; its contents have not been verified.", "predicted")
            add("Account takeover", "If credentials are captured, an attacker could attempt to access the account.", "predicted")
        if "payment_request" in signals or actions.get("money_sent"):
            next_step = next_step or "financial_loss"
            add("Financial loss", "The requested payment or deposited check could lead to loss; no loss is confirmed here.", "predicted")
        if "identity_request" in signals or actions.get("identity_shared"):
            next_step = next_step or "identity_misuse"
            add("Identity misuse", "Shared identity documents could be misused; misuse is not established.", "predicted")
    return ChainReconstruction(attack_chain=stages, current_stage=current, current_stage_explanation=explanation, likely_next_step=next_step)
