"""Transparent heuristics: a bounded risk index, never a probability.

Score = clamp(model score + unique evidence increments + action increments).
Evidence bonuses are capped at 35 to limit correlated-signal double counting.
"""
import re
from urllib.parse import urlsplit

from pydantic import BaseModel, Field


class RiskFactor(BaseModel):
    factor: str
    impact: int
    source: str
    evidence: str = ""


class RiskAssessment(BaseModel):
    model_score: int = Field(ge=0, le=100)
    final_score: int = Field(ge=0, le=100)
    risk_level: str
    risk_factors: list[RiskFactor]
    methodology: str = "Model score + evidence (capped at 35) + reported actions; capped at 100. Heuristic risk score, not probability."


# Stable IDs are also the keys of the follow-up safety questions.
ACTION_RULES = {
    "link_clicked": (10, "Did you click the link?"),
    "credentials_entered": (25, "Did you enter or share your password or login credentials?"),
    "otp_shared": (30, "Did you share a one-time code (OTP)?"),
    "money_sent": (30, "Did you send money or make the requested payment?"),
    "identity_shared": (25, "Did you share identity documents?"),
}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy"}
# Deliberately small curated map; unknown companies are never guessed.
BRAND_DOMAINS = {"paypal": "paypal.com", "microsoft": "microsoft.com", "amazon": "amazon.com", "apple": "apple.com"}
SIGNALS = {
    "urgency": (6, r"\b(urgent|immediately|within \d+ hours?|account.{0,15}(locked|suspended))\b"),
    "secrecy": (8, r"\b(keep.{0,25}(secret|confidential)|do not tell|don't tell|do not share this with anyone)\b"),
    "credential_request": (12, r"\b(enter|share|verify|confirm|provide).{0,35}\b(password|credentials|login|otp|one.time code)\b"),
    "payment_request": (12, r"\b(send|pay|transfer|return|deposit|buy).{0,40}\b(money|payment|fee|balance|check|equipment|gift cards?|crypto)\b"),
    "identity_request": (12, r"\b(send|share|upload|provide).{0,35}\b(passport|identity|driver.s license|social security)\b"),
}


def risk_level(score: int) -> str:
    return "low" if score < 20 else "moderate" if score < 40 else "high" if score < 70 else "critical"


def extract_entities(content: str, existing: dict | None = None) -> dict:
    entities = {key: list(values) for key, values in (existing or {}).items() if isinstance(values, list)}
    patterns = {
        "urls": r"(?:https?://|www\.)[^\s<>\"']+|\b(?:bit\.ly|tinyurl\.com|t\.co)/[^\s<>]+",
        "emails": r"\b[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}\b",
        "phone_numbers": r"(?<!\w)\+?\d[\d ()-]{7,}\d(?!\w)",
    }
    for key, pattern in patterns.items():
        entities[key] = sorted(set(entities.get(key, []) + [s.rstrip(".,;!?)") for s in re.findall(pattern, content)]))
    return entities


def reported_actions(answers: dict[str, str]) -> dict[str, bool | None]:
    """Only explicit answers to stable action questions establish user actions.

    Free text, negation and uncertainty are not interpreted by keyword guessing.
    """
    result = {}
    for action in ACTION_RULES:
        answer = answers.get(action, "").strip().lower().rstrip(".! ")
        positive = answer in {"yes", "true"} or (answer.startswith("yes,") and not re.search(r"\b(no|not|never|unsure|maybe|might|but)\b|n.t\b", answer))
        negative = answer in {"no", "false"} or (answer.startswith("no,") and not re.search(r"\b(but|yes)\b", answer))
        result[action] = True if positive else False if negative else None
    return result


def collect_signals(content: str, report: dict, claimed_company: str | None = None) -> dict[str, str]:
    signals = {}
    for name, (_, pattern) in SIGNALS.items():
        match = re.search(pattern, content, re.I)
        if match:
            # Suppress explicit safety advice/negated requests in the same clause.
            prefix = content[max(0, match.start() - 35):match.start()].lower()
            if not re.search(r"\b(never|don't|do not|avoid|not to)\b[^.!?;]*$", prefix):
                signals[name] = match.group()
    entities = extract_entities(content, report.get("entities"))
    brands = [b for b in BRAND_DOMAINS if re.search(rf"\b{b}\b", (claimed_company or "") + " " + content, re.I)]
    for url in entities["urls"]:
        try:
            host = (urlsplit(url if "://" in url else "https://" + url).hostname or "").lower().rstrip(".")
        except ValueError:
            continue
        if host in SHORTENERS:
            signals["shortened_url"] = url
        elif any(b in host and host != domain and not host.endswith("." + domain) for b, domain in BRAND_DOMAINS.items() if b in brands):
            signals["brand_domain_mismatch"] = url
            signals["impersonation"] = "Brand-like domain does not belong to the claimed brand"
        if host.startswith("xn--") or re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host):
            signals["suspicious_domain"] = url
    if brands and "shortened_url" in signals:
        brand = brands[0].title()
        signals.setdefault(
            "brand_impersonation",
            f"{brand} name is paired with an obscured shortened link",
        )
    # Model interpretations remain labeled as such and require an exact source quote.
    for flag in report.get("red_flags", report.get("evidence", [])):
        quote = flag.get("evidence", "")
        category = (flag.get("category", "") + " " + flag.get("label", "")).lower()
        if quote and quote.lower() in content.lower() and "impersonation" in category:
            signals.setdefault("impersonation", quote)
    return signals


def assess_risk(model_score: int, signals: dict[str, str], actions: dict[str, bool | None]) -> RiskAssessment:
    base = max(0, min(100, int(model_score)))
    weights = {**{key: value[0] for key, value in SIGNALS.items()}, "shortened_url": 8,
               "brand_domain_mismatch": 18, "suspicious_domain": 8,
               "impersonation": 8, "brand_impersonation": 8}
    factors = []
    remaining = 35
    score = base
    for key, evidence in signals.items():
        impact = min(weights.get(key, 0), remaining, 100 - score)
        factors.append(RiskFactor(factor=key, impact=impact, source="model_evidence" if key == "impersonation" and "brand_domain_mismatch" not in signals else "deterministic", evidence=evidence))
        score += impact
        remaining -= impact
    for action, (weight, _) in ACTION_RULES.items():
        if actions.get(action) is True:
            impact = min(weight, 100 - score)
            factors.append(RiskFactor(factor=action, impact=impact, source="user_follow_up", evidence="User answered yes"))
            score += impact
    return RiskAssessment(model_score=base, final_score=score, risk_level=risk_level(score), risk_factors=factors)
