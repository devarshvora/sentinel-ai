import os

import requests
import streamlit as st
from dotenv import load_dotenv

load_dotenv()
API_URL = os.getenv("SENTINEL_API_URL", "http://127.0.0.1:8000")
st.set_page_config(page_title="Sentinel AI", page_icon="🛡️", layout="centered")


def display_result(result: dict, slot: str) -> None:
    report = result.get("final_report") or result.get("initial_report") or result

    if result.get("persistence_status") == "unavailable":
        st.warning(result["persistence_message"])
    score = report.get("risk_score", 0)
    verdict = report.get("verdict") or ("likely_scam" if score >= 40 else "suspicious" if score >= 20 else "likely_safe")
    st.divider()
    st.subheader(verdict.replace("_", " ").title())
    left, right = st.columns(2)
    left.metric("Risk score", f"{score}/100")
    right.metric("Gemini confidence", f"{report.get('confidence', 0) * 100:.0f}%")
    st.write(report.get("summary", ""))
    risk = report.get("risk_assessment")
    if risk:
        with st.expander(f"Why risk is {score}", expanded=True):
            st.write(f"Model starting score: **{risk['model_score']}**")
            for factor in risk["risk_factors"]:
                st.write(f"+{factor['impact']} · {factor['factor'].replace('_', ' ').capitalize()}")
                st.caption(f"{factor['source'].replace('_', ' ')} · {factor.get('evidence', '')}")
            st.caption(risk["methodology"])
    evidence = report.get("evidence") or report.get("red_flags", [])
    if evidence:
        with st.expander("Why Sentinel flagged it"):
            for item in evidence:
                st.write(f"**{item.get('label') or item.get('category', 'Indicator')}**")
                st.write(item.get("evidence", ""))
                st.caption(item.get("reason") or item.get("explanation", ""))
    with st.expander("Extracted entities"):
        entities = report.get("entities", {})
        if not any(entities.values()):
            st.caption("No structured indicators were extracted.")
        for kind, values in entities.items():
            if values:
                st.write(f"**{kind.replace('_', ' ').title()}**")
                # Render potentially malicious URLs as inert text, not links.
                st.code("\n".join(values), language=None)
    st.subheader("Scam chain")
    chain = report.get("attack_chain", [])
    if not chain:
        st.caption("Insufficient evidence to reconstruct a scam chain.")
    for stage in chain:
        st.write(f"**{stage['stage_number']}. {stage['name']}** · {stage['status'].upper()}")
        st.caption(stage["description"])
    st.info("You are here: " + report.get("current_stage", "unknown").replace("_", " "))
    st.caption(report.get("current_stage_explanation", ""))
    next_step = report.get("likely_next_step")
    if next_step:
        st.write("**What may happen next:** " + next_step.replace("_", " ") + " (predicted)")
    simulations = report.get("simulations", [])
    if simulations:
        st.subheader("What if?")
        st.caption("Rule-based hypothetical exposure scores, not probabilities or guarantees. Each scenario changes one action while retaining reported exposure.")
        for scenario in simulations:
            st.write(f"**{scenario['label']} → {scenario['projected_risk']}/100**")
            if scenario.get("score_ceiling_reached"):
                st.caption(
                    f"Risk score is already capped at 100. This action adds "
                    f"{scenario['exposure_impact']} exposure points before the cap."
                )
            st.caption(scenario["explanation"])
    playbook = report.get("safety_playbook", [])
    if playbook:
        st.subheader("Your safety playbook")
        for step in playbook:
            st.write(f"**{step['priority'].upper()} · {step['title']}**")
            st.caption(step["action"])
    actions = report.get("recommended_actions") or [report.get("recommended_action", "")]
    if any(actions):
        st.subheader("Recommended actions")
        for action in actions:
            if action:
                st.write("• " + action)
    questions = report.get("follow_up_questions", [])
    if questions and result.get("id"):
        with st.expander("Update your safety answers"):
            with st.form(f"follow_up_{slot}_{result['id']}"):
                answers = {}
                previous = result.get("follow_up_answers") or {}
                for index, question in enumerate(questions):
                    if not isinstance(question, dict):
                        st.caption(str(question))
                        continue
                    key = question["question_id"]
                    widget_key = f"{slot}_{result['id']}_{key}_{index}"
                    if key in report.get("user_actions", {}):
                        options = ["Not sure", "No", "Yes"]
                        prior = previous.get(key, "Not sure").capitalize()
                        answers[key] = st.selectbox(question["question"], options, index=options.index(prior) if prior in options else 0, key=widget_key)
                    else:
                        value = st.text_input(question["question"], value=previous.get(key, ""), key=widget_key)
                        if value.strip():
                            answers[key] = value.strip()
                submitted = st.form_submit_button("Update investigation")
            if submitted:
                try:
                    with st.spinner("Updating your investigation..."):
                        response = requests.post(f"{API_URL}/api/investigations/{result['id']}/follow-up", json={"answers": answers}, timeout=120)
                        response.raise_for_status()
                    st.session_state[slot] = response.json()
                    st.rerun()
                except requests.RequestException as error:
                    st.error("Could not update the investigation. Your previous result is preserved.")
                    st.caption(str(error))


st.title("🛡️ Sentinel AI")
st.write("Check suspicious messages, emails, job offers, payment requests, and screenshots before you act.")
st.caption("Multimodal evidence, explainable risk, and practical next steps.")
text_tab, image_tab = st.tabs(["Paste message", "Upload screenshot"])
with text_tab:
    suspicious_text = st.text_area("Message, email, job offer, or chat", height=220)
    claimed_company = st.text_input("Claimed company (optional)")
    sender_email = st.text_input("Sender email (optional)")
    if st.button("Analyze Message", type="primary", use_container_width=True):
        if len(suspicious_text.strip()) < 10:
            st.warning("Please enter at least 10 characters.")
        else:
            try:
                with st.spinner("Sentinel is investigating..."):
                    response = requests.post(f"{API_URL}/api/investigations", json={"content": suspicious_text, "input_type": "text", "source_name": "Streamlit", "claimed_company": claimed_company or None, "sender_email": sender_email or None}, timeout=120)
                    response.raise_for_status()
                st.session_state["text_result"] = response.json()
            except requests.RequestException as error:
                st.error("Sentinel could not complete the analysis.")
                st.caption(str(error))
    if st.session_state.get("text_result"):
        display_result(st.session_state["text_result"], "text_result")
with image_tab:
    uploaded_file = st.file_uploader("PNG, JPG, JPEG, or WEBP", type=["png", "jpg", "jpeg", "webp"])
    if uploaded_file:
        st.image(uploaded_file, caption="Uploaded screenshot", use_container_width=True)
        if st.button("Analyze Screenshot", type="primary", use_container_width=True):
            try:
                with st.spinner("Sentinel is reading the screenshot..."):
                    response = requests.post(f"{API_URL}/api/investigations/image", files={"file": (uploaded_file.name, uploaded_file.getvalue(), uploaded_file.type)}, timeout=120)
                    response.raise_for_status()
                st.session_state["image_result"] = response.json()
            except requests.RequestException as error:
                st.error("Sentinel could not analyze this image.")
                st.caption(str(error))
    if st.session_state.get("image_result"):
        display_result(st.session_state["image_result"], "image_result")
