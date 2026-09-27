from typing import Any
import json
import logging

from backend.investigation.risk_engine import ACTION_RULES

from backend.investigation.engine import investigate_content
from backend.investigation.enrichment import enrich_report
from backend.investigation.vision import analyze_screenshot
from backend.investigation.types import (
    InvestigationRequest,
    InvestigationResult,
)
from backend.repositories.investigation_repository import (
    investigation_repository,
)


logger = logging.getLogger(__name__)


class InvestigationService:
    """
    Coordinates Sentinel's investigation workflows.

    The service combines:
    - Gemini investigation logic
    - Supabase persistence
    - follow-up evidence
    - failure handling
    """

    def create_image_investigation(self, image_path: str) -> dict[str, Any]:
        """Analyze an image even when persistence is temporarily unavailable.

        Image analysis was available before case persistence was introduced. A
        Supabase outage must not turn a successful Gemini Vision result into a
        failed user-facing analysis. The response names that limitation so the
        client does not offer follow-up persistence for this transient case.
        """
        report = analyze_screenshot(image_path)

        try:
            investigation = investigation_repository.create(
                content=(
                    report.get("extracted_text")
                    or "[Image with no readable text]"
                ),
                input_type="image",
                source_name="Screenshot",
            )
            stored = investigation_repository.save_initial_report(
                investigation_id=investigation["id"], report=report,
            )
        except Exception as error:
            logger.warning(
                "Image analysis completed but could not be persisted: %s",
                error,
            )
            return {
                **report,
                "persistence_status": "unavailable",
                "persistence_message": (
                    "Analysis completed, but this case could not be saved. "
                    "Follow-up answers are unavailable until database "
                    "connectivity is restored."
                ),
            }

        # Preserve the existing image endpoint's root report fields.
        return {**report, **stored}

    def create_and_investigate(
        self,
        *,
        content: str,
        input_type: str = "text",
        source_name: str | None = None,
        sender_email: str | None = None,
        claimed_company: str | None = None,
    ) -> dict[str, Any]:
        """
        Create a new persistent investigation and generate
        its initial Sentinel report.
        """

        cleaned_content = content.strip()

        if len(cleaned_content) < 10:
            raise ValueError(
                "Content must contain at least 10 characters."
            )

        investigation = investigation_repository.create(
            content=cleaned_content,
            input_type=input_type,
            source_name=source_name,
            sender_email=sender_email,
            claimed_company=claimed_company,
        )

        investigation_id = investigation["id"]

        try:
            request = InvestigationRequest(
                content=cleaned_content,
                input_type=input_type,
                source_name=source_name,
                sender_email=sender_email,
                claimed_company=claimed_company,
                follow_up_answers={},
            )

            report: InvestigationResult = investigate_content(
                request
            )

            return investigation_repository.save_initial_report(
                investigation_id=investigation_id,
                report=report.model_dump(
                    mode="json"
                ),
            )

        except Exception as error:
            self._record_failure(
                investigation_id=investigation_id,
                error=error,
            )

            raise RuntimeError(
                "Sentinel failed to complete the investigation."
            ) from error

    def submit_follow_up_answers(
        self,
        *,
        investigation_id: str,
        answers: dict[str, str],
    ) -> dict[str, Any]:
        """
        Re-run an existing investigation using additional
        evidence supplied through follow-up answers.
        """

        if not answers:
            raise ValueError(
                "At least one follow-up answer is required."
            )

        cleaned_answers: dict[str, str] = {}

        for question_id, answer in answers.items():
            cleaned_question_id = str(
                question_id
            ).strip()

            cleaned_answer = str(
                answer
            ).strip()

            if not cleaned_question_id:
                raise ValueError(
                    "Follow-up question IDs cannot be empty."
                )

            if not cleaned_answer:
                raise ValueError(
                    f"Answer for {cleaned_question_id} cannot be empty."
                )

            cleaned_answers[
                cleaned_question_id
            ] = cleaned_answer

        investigation = (
            investigation_repository.get_by_id(
                investigation_id
            )
        )

        if investigation is None:
            raise LookupError(
                f"Investigation not found: {investigation_id}"
            )

        if investigation.get("status") == "failed":
            raise ValueError(
                "Follow-up answers cannot be submitted "
                "for a failed investigation."
            )

        cleaned_answers = {**(investigation.get("follow_up_answers") or {}), **cleaned_answers}
        initial = investigation.get("initial_report") or {}
        current = investigation.get("final_report") or initial
        allowed_ids = {
            q["question_id"] for report in (initial, current)
            for q in report.get("follow_up_questions", [])
            if isinstance(q, dict) and "question_id" in q
        }
        if any(key not in allowed_ids for key in answers):
            raise ValueError("Answer IDs must match the investigation's follow-up questions.")

        content = str(
            investigation.get("content") or ""
        ).strip()

        if not content:
            raise RuntimeError(
                "The stored investigation has no evidence content."
            )

        try:
            # Preserve the original multimodal evidence and model score. User
            # actions change deterministic exposure without an extra model call.
            if initial.get("risk_assessment") and all(key in ACTION_RULES for key in answers):
                updated = enrich_report(current, content, cleaned_answers, investigation.get("claimed_company"))
                return investigation_repository.save_follow_up_result(
                    investigation_id=investigation_id, answers=cleaned_answers, report=updated,
                )
            contextual_answers = dict(cleaned_answers)
            for source_report in (initial, current):
                for question in source_report.get("follow_up_questions", []):
                    if isinstance(question, dict) and question.get("question_id") in cleaned_answers:
                        contextual_answers[question["question"]] = cleaned_answers[question["question_id"]]
            analysis_content = content
            if investigation.get("input_type") == "image":
                analysis_content += "\nPrevious image evidence (model interpretation):\n" + json.dumps({
                    "summary": initial.get("summary"), "evidence": initial.get("evidence"),
                    "entities": initial.get("entities"),
                })
            request = InvestigationRequest(
                content=analysis_content,
                input_type=(
                    investigation.get("input_type")
                    or "text"
                ),
                source_name=investigation.get(
                    "source_name"
                ),
                sender_email=investigation.get(
                    "sender_email"
                ),
                claimed_company=investigation.get(
                    "claimed_company"
                ),
                follow_up_answers=contextual_answers,
            )

            updated_report: InvestigationResult = (
                investigate_content(request)
            )

            return (
                investigation_repository.save_follow_up_result(
                    investigation_id=investigation_id,
                    answers=cleaned_answers,
                    report=enrich_report(
                        updated_report.model_dump(mode="json"), content, cleaned_answers,
                        investigation.get("claimed_company"),
                    ),
                )
            )

        except (ValueError, LookupError):
            raise

        except Exception as error:
            self._record_failure(
                investigation_id=investigation_id,
                error=error,
            )

            raise RuntimeError(
                "Sentinel failed to update the investigation."
            ) from error

    def get_investigation(
        self,
        investigation_id: str,
    ) -> dict[str, Any]:
        """
        Retrieve one complete investigation.
        """

        investigation = (
            investigation_repository.get_by_id(
                investigation_id
            )
        )

        if investigation is None:
            raise LookupError(
                f"Investigation not found: {investigation_id}"
            )

        return investigation

    def list_recent_investigations(
        self,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """
        Return lightweight information for recent investigations.
        """

        return investigation_repository.list_recent(
            limit=limit
        )

    def _record_failure(
        self,
        *,
        investigation_id: str,
        error: Exception,
    ) -> None:
        """
        Record workflow failures without hiding the original error.
        """

        try:
            investigation_repository.mark_failed(
                investigation_id=investigation_id,
                error_message=str(error),
            )
        except Exception:
            pass


investigation_service = InvestigationService()
