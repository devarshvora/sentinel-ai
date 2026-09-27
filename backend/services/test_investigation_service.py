from backend.services.investigation_service import (
    investigation_service,
)


def main() -> None:
    result = investigation_service.create_and_investigate(
        content=(
            "Congratulations. You have been hired for a remote "
            "data analyst position without an interview. We will "
            "email you a check for office equipment. Deposit it "
            "today, buy equipment from our approved vendor, and "
            "return the remaining balance immediately. Keep these "
            "instructions confidential."
        ),
        input_type="job_offer",
        source_name="Service workflow test",
        sender_email="example.hr@gmail.com",
        claimed_company="Example Technologies",
    )

    print("Investigation completed and saved.")
    print("ID:", result.get("id"))
    print("Status:", result.get("status"))
    print("Risk score:", result.get("risk_score"))
    print("Risk level:", result.get("risk_level"))
    print("Confidence:", result.get("confidence"))

    report = result.get("initial_report") or {}

    print("Threat type:", report.get("threat_type"))
    print("Summary:", report.get("summary"))


if __name__ == "__main__":
    main()