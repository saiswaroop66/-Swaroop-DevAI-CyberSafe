from utils.log_parser import LogParser
from utils.detector import ThreatDetector
from utils.llm import llm


class ThreatAgent:

    def __init__(self):

        self.parser = LogParser()
        self.detector = ThreatDetector()

    def analyze(self, file_path):

        # Step 1: Parse Logs
        logs = self.parser.parse_file(file_path)

        # Step 2: Detect Threats
        threats = self.detector.detect(logs)

        # No threats found
        if not threats:
            return {
                "status": "safe",
                "analysis": "No significant security threats were detected.",
                "threats": []
            }

        # Step 3: Create Prompt

        prompt = f"""
You are a Senior Cybersecurity Analyst.

Analyze the detected threats below.

Threats:

{threats}

Generate a professional report using this format.

# Security Analysis Report

## Executive Summary

## Threat Analysis

## Risk Level

## Recommendations

## Conclusion

Keep the response professional and concise.
"""

        # Step 4: AI Analysis
        response = llm.invoke(prompt)

        return {
            "status": "success",
            "analysis": response.content,
            "threats": threats
        }


# ----------------------------
# Testing
# ----------------------------

if __name__ == "__main__":

    agent = ThreatAgent()

    result = agent.analyze("../sample_logs/auth.log")

    print(result["analysis"])

    print("\nDetected Threats:\n")

    for threat in result["threats"]:
        print(threat)