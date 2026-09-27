"""One post-processing pipeline for model text and image reports."""
from copy import deepcopy

from backend.investigation.attack_chain import reconstruct_chain
from backend.investigation.risk_engine import ACTION_RULES, assess_risk, collect_signals, extract_entities, reported_actions
from backend.investigation.simulator import simulate


def build_safety_playbook(actions: dict[str, bool | None], signals: dict[str, str]) -> list[dict[str, str]]:
    """Return concrete, stage-aware actions without treating exposure as harm."""
    playbook = []
    if signals:
        playbook.extend([
            {
                "priority": "now",
                "title": "Do not use message links or contact details",
                "action": "Open the official app or type the organization's known address yourself.",
            },
            {
                "priority": "now",
                "title": "Preserve the evidence, then block the sender",
                "action": "Keep the screenshot or message for reporting; do not reply or forward the link.",
            },
        ])
    if actions.get("link_clicked") is True:
        playbook.append({
            "priority": "today",
            "title": "Close the page and check the official account",
            "action": "Do not enter further details. Use the official app or typed address to review account activity.",
        })
    if actions.get("credentials_entered") is True:
        playbook.append({
            "priority": "urgent",
            "title": "Change the password from the official service",
            "action": "Change it now, end unfamiliar sessions, and use a unique password.",
        })
    if actions.get("otp_shared") is True:
        playbook.append({
            "priority": "urgent",
            "title": "Contact the provider through official support",
            "action": "Tell them a one-time code was disclosed and secure the affected account.",
        })
    if actions.get("money_sent") is True:
        playbook.append({
            "priority": "urgent",
            "title": "Contact the payment provider immediately",
            "action": "Report the suspicious payment through the provider's official fraud channel.",
        })
    if actions.get("identity_shared") is True:
        playbook.append({
            "priority": "today",
            "title": "Get guidance for the exposed document",
            "action": "Contact the document issuer through its official support channel.",
        })
    return playbook


def enrich_report(report: dict, content: str, answers: dict | None = None, claimed_company: str | None = None) -> dict:
    result = deepcopy(report)
    actions = reported_actions(answers or {})
    result["entities"] = extract_entities(content, result.get("entities"))
    signals = collect_signals(content, result, claimed_company)
    # Idempotent enrichment: never feed a previously fused score back as model risk.
    model_score = (result.get("risk_assessment") or {}).get("model_score", result["risk_score"])
    risk = assess_risk(model_score, signals, actions)
    result["risk_assessment"] = risk.model_dump()
    result["risk_score"] = risk.final_score
    result["risk_level"] = risk.risk_level
    result["verdict"] = "likely_safe" if risk.final_score < 20 else "suspicious" if risk.final_score < 40 else "likely_scam"
    has_url = bool(result["entities"].get("urls"))
    result.update(reconstruct_chain(signals, actions, has_url, model_score).model_dump())
    result["user_actions"] = actions
    result["simulations"] = [s.model_dump() for s in simulate(model_score, signals, actions, has_url)]
    result["safety_playbook"] = build_safety_playbook(actions, signals)
    recovery = {
        "credentials_entered": "Change the exposed password through the official app or site and review active sessions.",
        "otp_shared": "Contact the account provider through its official support channel and secure the affected account.",
        "money_sent": "Contact your payment provider promptly through its official channel to report the suspicious payment.",
        "identity_shared": "Contact the document issuer through its official channel for guidance on exposed identity documents.",
    }
    original_actions = result.get("recommended_actions") or [result.get("recommended_action", "")]
    result["recommended_actions"] = list(dict.fromkeys(
        [text for key, text in recovery.items() if actions.get(key) is True] + [text for text in original_actions if text and text not in recovery.values()]
    ))
    existing = result.get("follow_up_questions", [])
    # Preserve model questions while supplying stable, single-action questions.
    questions = []
    for index, question in enumerate(existing):
        if isinstance(question, str):
            question = {"question_id": f"image_Q{index + 1}", "question": question,
                        "reason": "Clarify image evidence", "impact_if_yes": "Reassess evidence", "impact_if_no": "Reassess evidence"}
        if question.get("question_id") not in ACTION_RULES:
            questions.append(question)
    result["follow_up_questions"] = [
        {"question_id": key, "question": question, "reason": "Establish your current exposure without assuming an action.",
         "impact_if_yes": "Update the current stage and risk score.", "impact_if_no": "Do not add exposure for this action."}
        for key, (_, question) in ACTION_RULES.items()
    ] + questions
    return result
