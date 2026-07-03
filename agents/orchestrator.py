from agents.threat_agent import ThreatAgent
from agents.rag_agent import RAGAgent
from agents.report_agent import ReportAgent


class Orchestrator:

    def __init__(self):

        self.threat_agent = ThreatAgent()
        self.rag_agent = RAGAgent()
        self.report_agent = ReportAgent()

    # ----------------------------------------
    # Analyze Uploaded Log File
    # ----------------------------------------

    def analyze_log(self, file_path):

        return self.threat_agent.analyze(file_path)

    # ----------------------------------------
    # Ask Cybersecurity Question
    # ----------------------------------------

    def ask_question(self, question):

        return self.rag_agent.ask(question)

    # ----------------------------------------
    # Upload Knowledge PDF
    # ----------------------------------------

    def upload_pdf(self, pdf_path):

        self.rag_agent.ingest_pdf(pdf_path)

        return {
            "status": "success",
            "message": "Knowledge Base Updated Successfully."
        }

    # ----------------------------------------
    # Generate Security Report
    # ----------------------------------------

    def generate_report(self, threats, analysis):

        return self.report_agent.generate_report(
            threats,
            analysis
        )


# ----------------------------------------
# Testing
# ----------------------------------------

if __name__ == "__main__":

    ai = Orchestrator()

    result = ai.analyze_log("sample_logs/auth.log")

    print(result["analysis"])

    pdf = ai.generate_report(
        result["threats"],
        result["analysis"]
    )

    print("\nPDF Saved At:")

    print(pdf)
