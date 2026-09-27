"""Rule-based scenarios reuse the risk engine and never erase existing exposure."""
from pydantic import BaseModel, Field

from backend.investigation.risk_engine import assess_risk


class Simulation(BaseModel):
    action: str
    label: str
    projected_risk: int = Field(ge=0, le=100)
    exposure_impact: int = Field(ge=0)
    score_ceiling_reached: bool = False
    explanation: str


def simulate(model_score: int, signals: dict, actions: dict, has_url: bool) -> list[Simulation]:
    current = assess_risk(model_score, signals, actions).final_score
    scenarios = []
    candidates = []
    suspicious = bool(signals) or model_score >= 40 or any(value is True for value in actions.values())
    if suspicious:
        if has_url:
            candidates.append(("link_clicked", "click_link", "If you click the link", "You could be exposed to an unverified page."))
        if has_url or "credential_request" in signals or actions.get("credentials_entered"):
            candidates.extend([
                ("credentials_entered", "enter_credentials", "If you enter credentials", "Login details could become available to an attacker."),
                ("otp_shared", "share_otp", "If you share an OTP", "An attacker could use the code to complete a login or transaction."),
            ])
        if "payment_request" in signals:
            candidates.append(("money_sent", "send_money", "If you send money", "Funds could be lost or a deposited check could be reversed."))
        if "identity_request" in signals:
            candidates.append(("identity_shared", "share_identity", "If you share identity documents", "The documents could be reused for impersonation."))
    for stage, action, label, explanation in candidates:
        if actions.get(stage) is True:
            continue
        hypothetical = {**actions, stage: True}
        score = assess_risk(model_score, signals, hypothetical).final_score
        added_exposure = {
            "link_clicked": 10,
            "credentials_entered": 25,
            "otp_shared": 30,
            "money_sent": 30,
            "identity_shared": 25,
        }[stage]
        scenarios.append(Simulation(
            action=action,
            label=label,
            projected_risk=score,
            exposure_impact=added_exposure,
            score_ceiling_reached=current + added_exposure > 100,
            explanation=explanation,
        ))
    compromised = any(actions.get(key) is True for key in ("credentials_entered", "otp_shared", "money_sent", "identity_shared"))
    unknown = any(value is None for value in actions.values())
    if compromised or unknown:
        stopped = current
        reason = "Stopping prevents further engagement but does not undo disclosed information or payments." if compromised else "Interaction history is incomplete; no reduction is assumed until exposure is clarified."
    else:
        stopped = min(current, 30 if actions.get("link_clicked") else 15)
        reason = "Assumes no information or money was shared and engagement stops. This reduces future exposure, not the suspiciousness of the original message."
    scenarios.append(Simulation(
        action="ignore_block",
        label="If you stop and block",
        projected_risk=stopped,
        exposure_impact=0,
        explanation=reason,
    ))
    return scenarios
