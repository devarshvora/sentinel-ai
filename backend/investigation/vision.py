import json
import mimetypes
import os
import time

from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field
from backend.investigation.types import ExtractedEntities, FollowUpQuestion

from dotenv import load_dotenv
from google import genai
from google.genai import errors, types
from backend.investigation.enrichment import enrich_report


load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

if not GEMINI_API_KEY:
    raise RuntimeError(
        "GEMINI_API_KEY is missing from the environment."
    )


gemini_client = genai.Client(
    api_key=GEMINI_API_KEY
)

VISION_MODEL = "gemini-3.6-flash"


class ImageEvidence(BaseModel):
    label: str
    evidence: str
    reason: str
    severity: str


class ImageReport(BaseModel):
    verdict: Literal["likely_safe", "suspicious", "likely_scam"]
    risk_score: int = Field(ge=0, le=100)
    confidence: float = Field(ge=0, le=1)
    summary: str
    extracted_text: str
    entities: ExtractedEntities = Field(default_factory=ExtractedEntities)
    evidence: list[ImageEvidence] = Field(default_factory=list)
    recommended_action: str = ""
    follow_up_questions: list[str | FollowUpQuestion] = Field(default_factory=list)


def _read_image(
    image_path: str,
) -> tuple[bytes, str]:
    """
    Read an image from disk and determine its MIME type.
    """

    path = Path(image_path)

    if not path.exists():
        raise FileNotFoundError(
            f"Image not found: {image_path}"
        )

    mime_type, _ = mimetypes.guess_type(
        path.name
    )

    supported_types = {
        "image/png",
        "image/jpeg",
        "image/webp",
    }

    if mime_type not in supported_types:
        raise ValueError(
            "Only PNG, JPEG, JPG, and WEBP images are supported."
        )

    return path.read_bytes(), mime_type


def _generate_with_retry(
    *,
    contents,
    config,
    max_attempts: int = 4,
):
    """
    Call Gemini with retry handling for temporary 503 errors.

    Retries use exponential backoff:
    1 sec -> 2 sec -> 4 sec
    """

    last_error = None

    for attempt in range(max_attempts):
        try:
            return gemini_client.models.generate_content(
                model=VISION_MODEL,
                contents=contents,
                config=config,
            )

        except errors.ServerError as error:
            last_error = error

            status_code = getattr(
                error,
                "code",
                None,
            )

            if status_code != 503:
                raise

            if attempt == max_attempts - 1:
                break

            delay = 2 ** attempt

            print(
                f"Gemini temporarily unavailable. "
                f"Retrying in {delay} second(s)..."
            )

            time.sleep(delay)

    raise RuntimeError(
        "Gemini is temporarily unavailable after multiple attempts. "
        "Please try again shortly."
    ) from last_error


def analyze_screenshot(
    image_path: str,
) -> dict[str, Any]:
    """
    Analyze a screenshot or image for scam indicators.

    This performs multimodal evidence extraction only.
    It does not save anything to Supabase.
    """

    image_bytes, mime_type = _read_image(
        image_path
    )

    prompt = """
You are Sentinel AI, a digital safety image-analysis system.

Analyze the supplied screenshot or image.

Your job is to identify evidence that may indicate:
- phishing
- employment scams
- payment fraud
- impersonation
- marketplace scams
- credential theft
- suspicious links
- social engineering

Extract only information visible or strongly supported by the image.

Return valid JSON with exactly this structure:

{
  "verdict": "likely_safe | suspicious | likely_scam",
  "risk_score": 0,
  "confidence": 0.0,
  "summary": "",
  "extracted_text": "",
  "entities": {
    "emails": [],
    "urls": [],
    "phone_numbers": [],
    "companies": [],
    "people": [],
    "payment_methods": []
  },
  "evidence": [
    {
      "label": "",
      "evidence": "",
      "reason": "",
      "severity": "low | medium | high | critical"
    }
  ],
  "recommended_action": "",
  "follow_up_questions": []
}

Rules:

1. Do not invent text that is not visible.
2. Do not invent URLs, companies, phone numbers, or email addresses.
3. A Gmail/Yahoo/Outlook address alone does not prove fraud.
4. Urgency alone does not prove fraud.
5. Use calibrated language.
6. Keep follow-up questions to a maximum of 3.
7. Ask follow-up questions only if the answer could change the user's immediate safety action.
8. risk_score must be between 0 and 100.
9. confidence must be between 0 and 1.
10. Return JSON only.
""".strip()

    response = _generate_with_retry(
        contents=[
            prompt,
            types.Part.from_bytes(
                data=image_bytes,
                mime_type=mime_type,
            ),
        ],
        config=types.GenerateContentConfig(
            temperature=0.1,
            response_mime_type="application/json",
        ),
    )

    if not response.text:
        raise RuntimeError(
            "Gemini returned an empty image-analysis response."
        )

    try:
        result = json.loads(
            response.text
        )

    except json.JSONDecodeError as error:
        raise RuntimeError(
            "Gemini returned invalid JSON."
        ) from error

    validated = ImageReport.model_validate(result).model_dump()
    return enrich_report(validated, validated["extracted_text"])
