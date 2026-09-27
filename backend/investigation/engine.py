import hashlib
import json
import os
from typing import Any

from dotenv import load_dotenv
from google import genai
from google.genai import types
from pydantic import ValidationError

from backend.investigation.types import (
    InvestigationRequest,
    InvestigationResult,
    RiskLevel,
    ModelInvestigationResult,
)
from backend.investigation.enrichment import enrich_report


load_dotenv()

gemini_api_key = os.getenv("GEMINI_API_KEY")

if not gemini_api_key:
    raise ValueError(
        "GEMINI_API_KEY is missing. Add it to your .env file."
    )

gemini_client = genai.Client(api_key=gemini_api_key)

GENERATION_MODEL = "gemini-flash-latest"


SYSTEM_INSTRUCTION = """
You are Sentinel AI, a specialized digital-safety investigation engine.

Analyze suspicious messages, emails, job offers, conversations,
invoices, documents, and other user-submitted material.

Produce a structured, evidence-based investigation.

Rules:

1. Use only submitted content and supplied metadata.
2. Do not claim fraud with certainty unless evidence is strong.
3. Separate direct evidence from inference.
4. Do not invent identities, domains, companies, links, or payment details.
5. Reduce confidence when important evidence is missing.
6. Ask follow-up questions when answers could change the risk assessment.
7. Recommend safe actions only.
8. Return only the required structured result.

Risk guidance:

0-19: low
20-39: moderate
40-69: high
70-100: critical
""".strip()


def create_case_id(
    request: InvestigationRequest,
) -> str:
    normalized_content = " ".join(
        request.content.lower().split()
    )

    identity_material = "|".join(
        [
            normalized_content,
            str(request.input_type),
            request.source_name or "",
            request.claimed_company or "",
            request.sender_email or "",
        ]
    )

    digest = hashlib.sha256(
        identity_material.encode("utf-8")
    ).hexdigest()[:10].upper()

    return f"CASE-{digest}"


def build_investigation_prompt(
    request: InvestigationRequest,
    case_id: str,
) -> str:
    metadata: dict[str, Any] = {
        "case_id": case_id,
        "input_type": request.input_type,
        "source_name": request.source_name,
        "claimed_company": request.claimed_company,
        "sender_email": request.sender_email,
        "follow_up_answers": request.follow_up_answers,
    }

    metadata_json = json.dumps(
        metadata,
        indent=2,
        ensure_ascii=False,
    )

    return f"""
Perform a digital-safety investigation.

CASE METADATA
{metadata_json}

SUBMITTED CONTENT
--- BEGIN USER EVIDENCE ---
{request.content}
--- END USER EVIDENCE ---

Requirements:

1. Use this case ID exactly:
   {case_id}

2. Determine the most likely threat type.

3. Identify likely attacker objectives.

4. Extract red flags using short evidence fragments from the content.

5. Score these manipulation dimensions from 0 to 100:
   - urgency
   - authority
   - reward
   - fear
   - secrecy
   - isolation

6. Describe a likely attack path only when supported by evidence.

7. List missing evidence.

8. Ask no more than five useful follow-up questions.

9. Recommend safe immediate actions.

10. Create a reusable threat fingerprint.

11. Calibrate risk carefully and account for uncertainty.

12. Use supplied follow-up answers as evidence, but do not invent answers.
""".strip()


def normalize_result(
    result: InvestigationResult,
    expected_case_id: str,
) -> InvestigationResult:
    result.case_id = expected_case_id

    result.risk_score = max(
        0,
        min(100, result.risk_score),
    )

    result.confidence = max(
        0.0,
        min(1.0, result.confidence),
    )

    expected_level: RiskLevel

    if result.risk_score <= 19:
        expected_level = "low"
    elif result.risk_score <= 39:
        expected_level = "moderate"
    elif result.risk_score <= 69:
        expected_level = "high"
    else:
        expected_level = "critical"

    result.risk_level = expected_level

    result.threat_fingerprint.signature_tags = list(
        dict.fromkeys(
            tag.strip().lower().replace(" ", "_")
            for tag in result.threat_fingerprint.signature_tags
            if tag.strip()
        )
    )

    result.recommended_actions = list(
        dict.fromkeys(
            action.strip()
            for action in result.recommended_actions
            if action.strip()
        )
    )

    result.missing_evidence = list(
        dict.fromkeys(
            item.strip()
            for item in result.missing_evidence
            if item.strip()
        )
    )

    return result


def investigate_content(
    request: InvestigationRequest,
) -> InvestigationResult:
    case_id = create_case_id(request)

    prompt = build_investigation_prompt(
        request=request,
        case_id=case_id,
    )

    response = gemini_client.models.generate_content(
        model=GENERATION_MODEL,
        contents=prompt,
        config=types.GenerateContentConfig(
            system_instruction=SYSTEM_INSTRUCTION,
            response_mime_type="application/json",
            response_schema=ModelInvestigationResult,
            temperature=0.2,
            max_output_tokens=8192,
        ),
    )

    if not response.text:
        raise RuntimeError(
            "Gemini returned an empty investigation response."
        )

    try:
        result = InvestigationResult.model_validate_json(
            response.text
        )
    except ValidationError as error:
        raise RuntimeError(
            "Gemini returned output that did not match "
            "the InvestigationResult schema."
        ) from error

    result = normalize_result(
        result=result,
        expected_case_id=case_id,
    )
    raw = result.model_dump(exclude={"risk_assessment"})
    return InvestigationResult.model_validate(enrich_report(raw, request.content, request.follow_up_answers, request.claimed_company))
