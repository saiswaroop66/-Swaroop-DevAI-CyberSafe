import os
import streamlit as st

from agents.threat_agent import ThreatAgent
from agents.rag_agent import RAGAgent
from agents.report_agent import ReportAgent

# -----------------------------
# Page Config
# -----------------------------

st.set_page_config(
    page_title="SentinelAI",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡 Swaroop DevAI-CyberSafe")
st.caption("AI-Powered Cybersecurity Threat Detection & Security Intelligence Platform")

UPLOAD_FOLDER = "data/uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

threat_agent = ThreatAgent()
rag_agent = RAGAgent()
report_agent = ReportAgent()

# -----------------------------
# Sidebar
# -----------------------------

menu = st.sidebar.radio(
    "Navigation",
    [
        "Threat Detection",
        "AI Chat",
        "Generate Report"
    ]
)

# ====================================================
# Threat Detection
# ====================================================

if menu == "Threat Detection":

    st.header("📂 Upload Security Log")

    uploaded_file = st.file_uploader(
        "Choose a log file",
        type=["log", "txt"]
    )

    if uploaded_file:

        file_path = os.path.join(
            UPLOAD_FOLDER,
            uploaded_file.name
        )

        with open(file_path, "wb") as f:
            f.write(uploaded_file.read())

        st.success("Log uploaded successfully.")

        if st.button("Analyze Threats"):

            with st.spinner("Analyzing logs..."):

                result = threat_agent.analyze(file_path)

            st.subheader("AI Security Analysis")

            st.write(result["analysis"])

            st.subheader("Detected Threats")

            if len(result["threats"]) == 0:

                st.success("No threats detected.")

            else:

                st.json(result["threats"])

# ====================================================
# AI Chat
# ====================================================

elif menu == "AI Chat":

    st.header("📚 Upload Cybersecurity PDF")

    pdf = st.file_uploader(
        "Upload PDF",
        type=["pdf"]
    )

    if pdf:

        pdf_path = os.path.join(
            UPLOAD_FOLDER,
            pdf.name
        )

        with open(pdf_path, "wb") as f:
            f.write(pdf.read())

        with st.spinner("Creating Knowledge Base..."):

            rag_agent.ingest_pdf(pdf_path)

        st.success("Knowledge Base Created.")

    question = st.text_input(
        "Ask a cybersecurity question"
    )

    if st.button("Ask AI"):

        answer = rag_agent.ask(question)

        st.write(answer)

# ====================================================
# Report
# ====================================================

elif menu == "Generate Report":

    st.header("📄 Generate Security Report")

    uploaded_file = st.file_uploader(
        "Upload log",
        type=["log", "txt"]
    )

    if uploaded_file:

        file_path = os.path.join(
            UPLOAD_FOLDER,
            uploaded_file.name
        )

        with open(file_path, "wb") as f:
            f.write(uploaded_file.read())

        if st.button("Generate PDF"):

            result = threat_agent.analyze(file_path)

            pdf_path = report_agent.generate_report(
                result["threats"],
                result["analysis"]
            )

            st.success("Report Generated.")

            with open(pdf_path, "rb") as pdf_file:

                st.download_button(
                    label="⬇ Download Report",
                    data=pdf_file,
                    file_name=os.path.basename(pdf_path),
                    mime="application/pdf"
                )