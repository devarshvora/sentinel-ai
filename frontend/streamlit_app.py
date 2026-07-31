import asyncio
import json
import os
import time
from typing import Any

import inngest
import requests
import streamlit as st
from dotenv import load_dotenv


load_dotenv()

st.set_page_config(
    page_title="Sentinel AI",
    page_icon="🛡️",
    layout="wide",
)


# ---------------------------------------------------------
# Inngest client
# ---------------------------------------------------------

@st.cache_resource
def get_inngest_client() -> inngest.Inngest:
    """
    Create one reusable Inngest client for Sentinel AI.
    """

    return inngest.Inngest(
        app_id="sentinel_ai",
        is_production=False,
    )


async def send_investigation_event(
    content: str,
    input_type: str,
    source_name: str | None,
    claimed_company: str | None,
    sender_email: str | None,
    follow_up_answers: dict[str, str] | None = None,
) -> str:
    """
    Send suspicious content to the Sentinel investigation workflow.
    """

    client = get_inngest_client()

    result = await client.send(
        inngest.Event(
            name="sentinel/investigate",
            data={
                "content": content,
                "input_type": input_type,
                "source_name": source_name or None,
                "claimed_company": claimed_company or None,
                "sender_email": sender_email or None,
                "follow_up_answers": follow_up_answers or {},
            },
        )
    )

    if not result:
        raise RuntimeError(
            "Inngest did not return an investigation event ID."
        )

    return result[0]


# ---------------------------------------------------------
# Inngest run polling
# ---------------------------------------------------------

def inngest_api_base() -> str:
    """
    Return the local Inngest REST API base URL.
    """

    return os.getenv(
        "INNGEST_API_BASE",
        "http://127.0.0.1:8288/v1",
    ).rstrip("/")


def fetch_runs(event_id: str) -> list[dict[str, Any]]:
    """
    Retrieve all function runs associated with an Inngest event.
    """

    url = f"{inngest_api_base()}/events/{event_id}/runs"

    response = requests.get(
        url,
        timeout=15,
    )

    response.raise_for_status()

    response_data = response.json()

    return response_data.get("data", [])


def wait_for_run_output(
    event_id: str,
    timeout_s: float = 180.0,
    poll_interval_s: float = 0.75,
) -> dict[str, Any]:
    """
    Poll Inngest until the investigation succeeds, fails,
    or reaches the timeout.
    """

    start_time = time.time()
    last_status: str | None = None

    successful_statuses = {
        "Completed",
        "Succeeded",
        "Success",
        "Finished",
    }

    failed_statuses = {
        "Failed",
        "Cancelled",
        "Canceled",
    }

    while True:
        runs = fetch_runs(event_id)

        if runs:
            run = runs[0]
            status = run.get("status")

            if status:
                last_status = status

            if status in successful_statuses:
                output = run.get("output")

                if isinstance(output, dict):
                    return output

                if isinstance(output, str):
                    try:
                        parsed_output = json.loads(output)

                        if isinstance(parsed_output, dict):
                            return parsed_output

                    except json.JSONDecodeError:
                        pass

                return {}

            if status in failed_statuses:
                error_message = (
                    run.get("error")
                    or run.get("failure")
                    or run.get("output")
                    or "No detailed error was returned."
                )

                raise RuntimeError(
                    f"Investigation run {status}: {error_message}"
                )

        elapsed_time = time.time() - start_time

        if elapsed_time > timeout_s:
            raise TimeoutError(
                "Timed out waiting for the Sentinel investigation. "
                f"Last status: {last_status}"
            )

        time.sleep(poll_interval_s)


# ---------------------------------------------------------
# Display helpers
# ---------------------------------------------------------

def format_label(value: str | None) -> str:
    """
    Convert values such as FAKE_CHECK_PAYMENT into readable text.
    """

    if not value:
        return "Unknown"

    return value.replace("_", " ").replace("-", " ").title()


def risk_icon(risk_level: str) -> str:
    """
    Return an icon matching the calculated risk level.
    """

    icons = {
        "low": "🟢",
        "moderate": "🟡",
        "high": "🟠",
        "critical": "🔴",
    }

    return icons.get(risk_level.lower(), "⚪")


def render_red_flags(
    red_flags: list[dict[str, Any]],
) -> None:
    """
    Render detected red flags.
    """

    st.subheader("🚩 Detected Red Flags")

    if not red_flags:
        st.info("No specific red flags were returned.")
        return

    for index, red_flag in enumerate(red_flags, start=1):
        category = format_label(
            red_flag.get("category")
        )

        severity = format_label(
            red_flag.get("severity")
        )

        confidence = red_flag.get("confidence", 0)

        try:
            confidence_percent = round(float(confidence) * 100)
        except (TypeError, ValueError):
            confidence_percent = 0

        with st.expander(
            f"{index}. {category} · {severity}",
            expanded=index <= 3,
        ):
            st.markdown(
                f"**Confidence:** {confidence_percent}%"
            )

            evidence = red_flag.get("evidence")

            if evidence:
                st.markdown("**Evidence**")
                st.code(
                    str(evidence),
                    language=None,
                )

            explanation = red_flag.get("explanation")

            if explanation:
                st.markdown("**Why this matters**")
                st.write(explanation)


def render_manipulation_profile(
    profile: dict[str, Any],
) -> None:
    """
    Render manipulation-technique scores.
    """

    st.subheader("🧠 Manipulation Profile")

    dimensions = [
        ("Urgency", "urgency"),
        ("Authority", "authority"),
        ("Reward", "reward"),
        ("Fear", "fear"),
        ("Secrecy", "secrecy"),
        ("Isolation", "isolation"),
    ]

    for label, key in dimensions:
        raw_score = profile.get(key, 0)

        try:
            score = max(
                0,
                min(100, int(raw_score)),
            )
        except (TypeError, ValueError):
            score = 0

        st.markdown(f"**{label}: {score}/100**")
        st.progress(score)


def render_attack_path(
    attack_path: list[dict[str, Any]],
) -> None:
    """
    Render confirmed and predicted attack stages.
    """

    st.subheader("🧭 Attack Path")

    if not attack_path:
        st.info("No attack path was returned.")
        return

    sorted_stages = sorted(
        attack_path,
        key=lambda stage: stage.get(
            "stage_number",
            999,
        ),
    )

    for stage in sorted_stages:
        stage_number = stage.get(
            "stage_number",
            "?",
        )

        stage_name = stage.get(
            "stage_name",
            "Unknown Stage",
        )

        confirmed = bool(
            stage.get("confirmed")
        )

        status = (
            "Confirmed by evidence"
            if confirmed
            else "Possible or predicted stage"
        )

        icon = "✅" if confirmed else "◻️"

        st.markdown(
            f"### {icon} Stage {stage_number}: {stage_name}"
        )

        st.caption(status)

        description = stage.get("description")

        if description:
            st.write(description)

        evidence = stage.get("evidence")

        if evidence:
            st.markdown("**Supporting evidence**")
            st.code(
                str(evidence),
                language=None,
            )


def render_recommended_actions(
    actions: list[str],
) -> None:
    """
    Render immediate safety recommendations.
    """

    st.subheader("✅ Recommended Actions")

    if not actions:
        st.info("No recommended actions were returned.")
        return

    for index, action in enumerate(actions, start=1):
        st.markdown(f"**{index}.** {action}")


def render_threat_fingerprint(
    fingerprint: dict[str, Any],
) -> None:
    """
    Render reusable threat-pattern information.
    """

    st.subheader("🧬 Threat Fingerprint")

    first_column, second_column = st.columns(2)

    with first_column:
        st.markdown("**Primary Pattern**")
        st.write(
            fingerprint.get("primary_pattern")
            or "Unknown"
        )

        st.markdown("**Payment Method**")
        st.write(
            fingerprint.get("payment_method")
            or "Not directly identified"
        )

    with second_column:
        st.markdown("**Impersonation Target**")
        st.write(
            fingerprint.get("impersonation_target")
            or "Not directly identified"
        )

        st.markdown("**Requested Assets**")

        requested_assets = fingerprint.get(
            "requested_assets",
            [],
        )

        if requested_assets:
            for asset in requested_assets:
                st.write(f"• {asset}")
        else:
            st.write("None directly identified")

    signature_tags = fingerprint.get(
        "signature_tags",
        [],
    )

    if signature_tags:
        st.markdown("**Signature Tags**")
        st.write(
            " · ".join(
                f"`{tag}`"
                for tag in signature_tags
            )
        )


def render_follow_up_questions(
    questions: list[dict[str, Any]],
) -> None:
    """
    Render questions that could materially change the assessment.
    """

    st.subheader("❓ Follow-up Questions")

    if not questions:
        st.info(
            "No additional questions are needed for this assessment."
        )
        return

    for question_data in questions:
        question_id = question_data.get(
            "question_id",
            "Question",
        )

        question = question_data.get(
            "question",
            "Question unavailable",
        )

        with st.expander(
            f"{question_id}: {question}"
        ):
            reason = question_data.get("reason")

            if reason:
                st.markdown("**Why Sentinel is asking**")
                st.write(reason)

            impact_if_yes = question_data.get(
                "impact_if_yes"
            )

            if impact_if_yes:
                st.markdown("**If the answer is Yes**")
                st.write(impact_if_yes)

            impact_if_no = question_data.get(
                "impact_if_no"
            )

            if impact_if_no:
                st.markdown("**If the answer is No**")
                st.write(impact_if_no)


def render_investigation_report(
    report: dict[str, Any],
) -> None:
    """
    Render the complete structured investigation report.
    """

    st.divider()
    st.header("Investigation Report")

    risk_level = str(
        report.get("risk_level", "unknown")
    ).lower()

    risk_score = report.get("risk_score", 0)
    confidence = report.get("confidence", 0)

    try:
        risk_score = max(
            0,
            min(100, int(risk_score)),
        )
    except (TypeError, ValueError):
        risk_score = 0

    try:
        confidence_percent = round(
            float(confidence) * 100
        )
    except (TypeError, ValueError):
        confidence_percent = 0

    metric_one, metric_two, metric_three, metric_four = (
        st.columns(4)
    )

    metric_one.metric(
        "Risk Score",
        f"{risk_score}/100",
    )

    metric_two.metric(
        "Risk Level",
        (
            f"{risk_icon(risk_level)} "
            f"{risk_level.upper()}"
        ),
    )

    metric_three.metric(
        "Threat Type",
        report.get("threat_type") or "Unknown",
    )

    metric_four.metric(
        "Confidence",
        f"{confidence_percent}%",
    )

    st.progress(risk_score)

    case_id = report.get("case_id")

    if case_id:
        st.caption(f"Case ID: {case_id}")

    st.subheader("📋 Executive Summary")
    st.write(
        report.get("summary")
        or "No summary was generated."
    )

    attacker_objectives = report.get(
        "attacker_objectives",
        [],
    )

    if attacker_objectives:
        st.subheader("🎯 Possible Attacker Objectives")

        for objective in attacker_objectives:
            st.write(f"• {objective}")

    left_column, right_column = st.columns(
        [1.2, 1]
    )

    with left_column:
        render_red_flags(
            report.get("red_flags", [])
        )

    with right_column:
        render_manipulation_profile(
            report.get(
                "manipulation_profile",
                {},
            )
        )

    st.divider()

    render_attack_path(
        report.get("attack_path", [])
    )

    st.divider()

    action_column, fingerprint_column = st.columns(2)

    with action_column:
        render_recommended_actions(
            report.get(
                "recommended_actions",
                [],
            )
        )

    with fingerprint_column:
        render_threat_fingerprint(
            report.get(
                "threat_fingerprint",
                {},
            )
        )

    missing_evidence = report.get(
        "missing_evidence",
        [],
    )

    if missing_evidence:
        st.divider()
        st.subheader("🔎 Missing Evidence")

        st.write(
            "The following information could improve verification:"
        )

        for evidence in missing_evidence:
            st.write(f"• {evidence}")

    st.divider()

    render_follow_up_questions(
        report.get(
            "follow_up_questions",
            [],
        )
    )

    with st.expander("View Raw Investigation JSON"):
        st.json(report)


# ---------------------------------------------------------
# Session state
# ---------------------------------------------------------

if "investigation_report" not in st.session_state:
    st.session_state.investigation_report = None

if "investigation_event_id" not in st.session_state:
    st.session_state.investigation_event_id = None


# ---------------------------------------------------------
# Application header
# ---------------------------------------------------------

st.title("🛡️ Sentinel AI")

st.markdown(
    """
    **AI Digital Safety Investigator**

    Analyze suspicious job offers, emails, text messages,
    payment requests, phishing attempts, and online conversations.
    """
)

st.info(
    "Do not paste passwords, Social Security numbers, bank account "
    "numbers, authentication codes, or other highly sensitive data."
)


# ---------------------------------------------------------
# Investigation form
# ---------------------------------------------------------

with st.form("sentinel_investigation_form"):
    st.subheader("Submit Suspicious Content")

    input_type = st.selectbox(
        "Evidence type",
        options=[
            "text",
            "email",
            "job_offer",
            "chat",
            "sms",
            "payment_request",
            "other",
        ],
        format_func=format_label,
        help=(
            "Choose the format that most closely matches "
            "the content being investigated."
        ),
    )

    content = st.text_area(
        "Message or content",
        height=260,
        placeholder=(
            "Paste the suspicious email, job offer, text message, "
            "payment request, or conversation here..."
        ),
    )

    metadata_column_one, metadata_column_two = st.columns(2)

    with metadata_column_one:
        sender_email = st.text_input(
            "Sender email or identifier",
            placeholder="example: recruiter@example.com",
            help="Optional",
        )

        source_name = st.text_input(
            "Evidence name",
            placeholder="example: Remote job offer email",
            help="Optional",
        )

    with metadata_column_two:
        claimed_company = st.text_input(
            "Claimed company or organization",
            placeholder="example: Example Technologies",
            help="Optional",
        )

    submitted = st.form_submit_button(
        "🔍 Investigate Content",
        type="primary",
        use_container_width=True,
    )


# ---------------------------------------------------------
# Run investigation
# ---------------------------------------------------------

if submitted:
    cleaned_content = content.strip()

    if not cleaned_content:
        st.warning(
            "Paste suspicious content before starting "
            "the investigation."
        )

    elif len(cleaned_content) < 20:
        st.warning(
            "The submitted content is too short for a reliable "
            "investigation. Add more of the original message."
        )

    else:
        try:
            status_box = st.status(
                "Sentinel is investigating the evidence...",
                expanded=True,
            )

            with status_box:
                st.write(
                    "Submitting evidence to the investigation workflow..."
                )

                investigation_event_id = asyncio.run(
                    send_investigation_event(
                        content=cleaned_content,
                        input_type=input_type,
                        source_name=source_name.strip() or None,
                        claimed_company=(
                            claimed_company.strip() or None
                        ),
                        sender_email=(
                            sender_email.strip() or None
                        ),
                    )
                )

                st.session_state.investigation_event_id = (
                    investigation_event_id
                )

                st.write(
                    "Analyzing suspicious indicators and "
                    "manipulation patterns..."
                )

                investigation_output = wait_for_run_output(
                    investigation_event_id
                )

                if not investigation_output:
                    raise RuntimeError(
                        "The investigation completed but returned "
                        "an empty report."
                    )

                st.session_state.investigation_report = (
                    investigation_output
                )

                status_box.update(
                    label="Investigation completed",
                    state="complete",
                    expanded=False,
                )

        except requests.ConnectionError:
            st.error(
                "Sentinel could not connect to Inngest. Confirm that "
                "the Inngest development server is running on port 8288."
            )

        except requests.HTTPError as error:
            st.error(
                f"Inngest returned an HTTP error: {error}"
            )

        except TimeoutError as error:
            st.error(str(error))

        except Exception as error:
            st.error(
                f"Investigation failed: {error}"
            )


# ---------------------------------------------------------
# Report
# ---------------------------------------------------------

if st.session_state.investigation_report:
    render_investigation_report(
        st.session_state.investigation_report
    )