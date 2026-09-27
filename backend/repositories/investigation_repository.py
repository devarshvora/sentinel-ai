from typing import Any

from backend.database.postgres import supabase


TABLE_NAME = "investigations"


class InvestigationRepository:
    """
    Handles all database operations for Sentinel investigations.

    Other parts of the application should use this repository
    instead of accessing Supabase directly.
    """

    def create(
        self,
        *,
        content: str,
        input_type: str = "text",
        source_name: str | None = None,
        sender_email: str | None = None,
        claimed_company: str | None = None,
    ) -> dict[str, Any]:
        payload = {
            "status": "pending",
            "content": content,
            "input_type": input_type,
            "source_name": source_name,
            "sender_email": sender_email,
            "claimed_company": claimed_company,
        }

        response = (
            supabase.table(TABLE_NAME)
            .insert(payload)
            .execute()
        )

        if not response.data:
            raise RuntimeError(
                "Supabase did not return the created investigation."
            )

        return response.data[0]

    def get_by_id(
        self,
        investigation_id: str,
    ) -> dict[str, Any] | None:
        response = (
            supabase.table(TABLE_NAME)
            .select("*")
            .eq("id", investigation_id)
            .limit(1)
            .execute()
        )

        if not response.data:
            return None

        return response.data[0]

    def save_initial_report(
        self,
        *,
        investigation_id: str,
        report: dict[str, Any],
    ) -> dict[str, Any]:
        follow_up_questions = report.get(
            "follow_up_questions",
            [],
        )

        status = (
            "awaiting_follow_up"
            if follow_up_questions
            else "completed"
        )

        updates = {
            "initial_report": report,
            "risk_score": report.get("risk_score"),
            "risk_level": report.get("risk_level"),
            "confidence": report.get("confidence"),
            "status": status,
            "error_message": None,
        }

        return self._update(
            investigation_id=investigation_id,
            updates=updates,
        )

    def save_follow_up_result(
        self,
        *,
        investigation_id: str,
        answers: dict[str, str],
        report: dict[str, Any],
    ) -> dict[str, Any]:
        updates = {
            "follow_up_answers": answers,
            "final_report": report,
            "risk_score": report.get("risk_score"),
            "risk_level": report.get("risk_level"),
            "confidence": report.get("confidence"),
            "status": "updated",
            "error_message": None,
        }

        return self._update(
            investigation_id=investigation_id,
            updates=updates,
        )

    def mark_failed(
        self,
        *,
        investigation_id: str,
        error_message: str,
    ) -> dict[str, Any]:
        return self._update(
            investigation_id=investigation_id,
            updates={
                "status": "failed",
                "error_message": error_message,
            },
        )

    def list_recent(
        self,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        safe_limit = max(1, min(limit, 100))

        response = (
            supabase.table(TABLE_NAME)
            .select(
                "id, created_at, updated_at, status, "
                "input_type, source_name, risk_score, "
                "risk_level, confidence"
            )
            .order(
                "created_at",
                desc=True,
            )
            .limit(safe_limit)
            .execute()
        )

        return response.data or []

    def _update(
        self,
        *,
        investigation_id: str,
        updates: dict[str, Any],
    ) -> dict[str, Any]:
        response = (
            supabase.table(TABLE_NAME)
            .update(updates)
            .eq("id", investigation_id)
            .execute()
        )

        if not response.data:
            raise LookupError(
                f"Investigation not found: {investigation_id}"
            )

        return response.data[0]


investigation_repository = InvestigationRepository()