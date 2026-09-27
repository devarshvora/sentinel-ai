from pathlib import Path
from typing import Any
import uuid

from fastapi import (
    APIRouter,
    File,
    HTTPException,
    Query,
    UploadFile,
    status,
)
from pydantic import BaseModel, Field

from backend.services.investigation_service import (
    investigation_service,
)


router = APIRouter(
    prefix="/api/investigations",
    tags=["Investigations"],
)


# ---------------------------------------------------------
# Request / response models
# ---------------------------------------------------------

class CreateInvestigationRequest(BaseModel):
    """
    Request body for creating a text investigation.
    """

    content: str = Field(
        min_length=10,
        max_length=20_000,
        description="Suspicious content submitted for analysis.",
    )

    input_type: str = Field(
        default="text",
        max_length=50,
        description=(
            "Evidence category such as text, email, "
            "job_offer, sms, chat, or payment_request."
        ),
    )

    source_name: str | None = Field(
        default=None,
        max_length=200,
    )

    sender_email: str | None = Field(
        default=None,
        max_length=320,
    )

    claimed_company: str | None = Field(
        default=None,
        max_length=200,
    )


class FollowUpAnswersRequest(BaseModel):
    """
    Answers supplied for Sentinel's follow-up questions.
    """

    answers: dict[str, str] = Field(
        min_length=1,
        description="Mapping of question IDs to user answers.",
        examples=[
            {
                "Q1": "Yes, I clicked the link.",
                "Q2": "No, I did not send any money.",
                "Q3": "I shared a copy of my driver's license.",
            }
        ],
    )


class InvestigationSummaryResponse(BaseModel):
    """
    Lightweight investigation information for history lists.
    """

    id: str
    created_at: str
    updated_at: str
    status: str
    input_type: str
    source_name: str | None = None
    risk_score: int | None = None
    risk_level: str | None = None
    confidence: float | None = None


# ---------------------------------------------------------
# TEXT INVESTIGATION
# ---------------------------------------------------------

@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    summary="Create and analyze a text investigation",
)
def create_investigation(
    request: CreateInvestigationRequest,
) -> dict[str, Any]:

    try:
        return investigation_service.create_and_investigate(
            content=request.content,
            input_type=request.input_type,
            source_name=request.source_name,
            sender_email=request.sender_email,
            claimed_company=request.claimed_company,
        )

    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(error),
        ) from error

    except Exception as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                "Sentinel could not complete the investigation. "
                "The failed case was recorded for review."
            ),
        ) from error


# ---------------------------------------------------------
# IMAGE / SCREENSHOT INVESTIGATION
# ---------------------------------------------------------

@router.post(
    "/image",
    summary="Analyze a screenshot or image",
)
async def analyze_image(
    file: UploadFile = File(...),
) -> dict[str, Any]:
    """
    Analyze a screenshot using Gemini Vision.

    The image is stored only temporarily and deleted after analysis.
    """

    allowed_types = {
        "image/png",
        "image/jpeg",
        "image/webp",
    }

    if file.content_type not in allowed_types:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=(
                "Only PNG, JPEG, JPG, and WEBP images "
                "are supported."
            ),
        )

    image_bytes = await file.read()

    if not image_bytes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded image is empty.",
        )

    # Prevent very large uploads.
    max_file_size = 10 * 1024 * 1024

    if len(image_bytes) > max_file_size:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Image must be smaller than 10 MB.",
        )

    uploads_dir = Path("uploads")

    uploads_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    original_name = (
        file.filename or "image.png"
    )

    extension = Path(
        original_name
    ).suffix.lower()

    if extension not in {
        ".png",
        ".jpg",
        ".jpeg",
        ".webp",
    }:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Unsupported image extension.",
        )

    temp_filename = (
        f"{uuid.uuid4()}{extension}"
    )

    temp_path = (
        uploads_dir / temp_filename
    )

    try:
        temp_path.write_bytes(
            image_bytes
        )

        result = investigation_service.create_image_investigation(
            str(temp_path)
        )

        return result

    except HTTPException:
        raise

    except Exception as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                "Sentinel could not analyze the uploaded image."
            ),
        ) from error

    finally:
        # Don't permanently store user screenshots.
        if temp_path.exists():
            temp_path.unlink()


# ---------------------------------------------------------
# FOLLOW-UP INVESTIGATION
# ---------------------------------------------------------

@router.post(
    "/{investigation_id}/follow-up",
    summary="Submit follow-up evidence",
)
def submit_follow_up_answers(
    investigation_id: str,
    request: FollowUpAnswersRequest,
) -> dict[str, Any]:

    try:
        return investigation_service.submit_follow_up_answers(
            investigation_id=investigation_id,
            answers=request.answers,
        )

    except LookupError as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(error),
        ) from error

    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(error),
        ) from error

    except Exception as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                "Sentinel could not update the investigation."
            ),
        ) from error


# ---------------------------------------------------------
# GET ONE INVESTIGATION
# ---------------------------------------------------------

@router.get(
    "/{investigation_id}",
    summary="Get one investigation",
)
def get_investigation(
    investigation_id: str,
) -> dict[str, Any]:

    try:
        return investigation_service.get_investigation(
            investigation_id
        )

    except LookupError as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(error),
        ) from error


# ---------------------------------------------------------
# LIST INVESTIGATIONS
# ---------------------------------------------------------

@router.get(
    "",
    response_model=list[InvestigationSummaryResponse],
    summary="List recent investigations",
)
def list_investigations(
    limit: int = Query(
        default=20,
        ge=1,
        le=100,
        description=(
            "Maximum number of recent investigations "
            "to return."
        ),
    ),
) -> list[dict[str, Any]]:

    return investigation_service.list_recent_investigations(
        limit=limit
    )
