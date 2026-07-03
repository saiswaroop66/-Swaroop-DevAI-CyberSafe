from collections import Counter
import re


class ThreatDetector:

    def __init__(self):
        self.results = []

    # ---------------------------------
    # Main Detection Function
    # ---------------------------------

    def detect(self, logs):

        self.results = []

        self.detect_bruteforce(logs)
        self.detect_sql_injection(logs)
        self.detect_xss(logs)
        self.detect_port_scan(logs)

        return self.results

    # ---------------------------------
    # Brute Force Detection
    # ---------------------------------

    def detect_bruteforce(self, logs):

        failed_ips = []

        for log in logs:

            if log.get("type") == "auth":
                failed_ips.append(log["ip"])

        counter = Counter(failed_ips)

        for ip, count in counter.items():

            if count >= 5:

                self.results.append({
                    "Threat": "Brute Force Attack",
                    "Severity": "High",
                    "IP": ip,
                    "Attempts": count,
                    "Description": "Multiple failed login attempts detected."
                })

    # ---------------------------------
    # SQL Injection Detection
    # ---------------------------------

    def detect_sql_injection(self, logs):

        patterns = [
            "union select",
            "or 1=1",
            "' or '1'='1",
            "--",
            "drop table",
            "information_schema"
        ]

        for log in logs:

            request = log.get("request", "").lower()

            for pattern in patterns:

                if pattern in request:

                    self.results.append({
                        "Threat": "SQL Injection",
                        "Severity": "Critical",
                        "IP": log.get("ip"),
                        "Request": request,
                        "Description": "Possible SQL Injection attack."
                    })

                    break

    # ---------------------------------
    # XSS Detection
    # ---------------------------------

    def detect_xss(self, logs):

        patterns = [
            "<script>",
            "%3cscript%3e",
            "javascript:",
            "onerror=",
            "onload="
        ]

        for log in logs:

            request = log.get("request", "").lower()

            for pattern in patterns:

                if pattern in request:

                    self.results.append({
                        "Threat": "Cross Site Scripting (XSS)",
                        "Severity": "High",
                        "IP": log.get("ip"),
                        "Request": request,
                        "Description": "Possible XSS attack detected."
                    })

                    break

    # ---------------------------------
    # Port Scan Detection
    # ---------------------------------

    def detect_port_scan(self, logs):

        ips = []

        for log in logs:

            if log.get("type") == "firewall":
                ips.append(log["ip"])

        counter = Counter(ips)

        for ip, count in counter.items():

            if count >= 10:

                self.results.append({
                    "Threat": "Port Scanning",
                    "Severity": "Medium",
                    "IP": ip,
                    "Connections": count,
                    "Description": "Large number of firewall connections detected."
                })


# ---------------------------------
# Testing
# ---------------------------------

if __name__ == "__main__":

    from log_parser import LogParser

    parser = LogParser()

    logs = parser.parse_file("../sample_logs/auth.log")

    detector = ThreatDetector()

    threats = detector.detect(logs)

    print("\nDetected Threats\n")

    for threat in threats:
        print(threat)