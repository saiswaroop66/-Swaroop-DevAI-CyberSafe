from collections import Counter


class ThreatDetector:

    def __init__(self):
        self.results = []

    # ============================================
    # Main Detection Function
    # ============================================

    def detect(self, logs):

        self.results = []

        self.detect_bruteforce(logs)
        self.detect_invalid_users(logs)
        self.detect_sql_injection(logs)
        self.detect_xss(logs)
        self.detect_port_scan(logs)

        return self.results

    # ============================================
    # Brute Force Detection
    # ============================================

    def detect_bruteforce(self, logs):

        failed_ips = []

        for log in logs:

            if (
                log.get("type") == "auth"
                and log.get("event") in [
                    "Failed Login",
                    "Invalid User",
                    "Authentication Failure"
                ]
            ):

                failed_ips.append(log["ip"])

        counter = Counter(failed_ips)

        for ip, count in counter.items():

            if count >= 5:

                self.results.append({

                    "Threat": "Brute Force Attack",

                    "Severity": "High",

                    "IP": ip,

                    "Attempts": count,

                    "Description":
                        f"{count} failed authentication attempts detected."

                })

    # ============================================
    # Invalid User Detection
    # ============================================

    def detect_invalid_users(self, logs):

        for log in logs:

            if (
                log.get("type") == "auth"
                and log.get("event") == "Invalid User"
            ):

                self.results.append({

                    "Threat": "Invalid User Login",

                    "Severity": "Medium",

                    "IP": log["ip"],

                    "Description":
                        "Login attempt using an invalid username."

                })

    # ============================================
    # SQL Injection Detection
    # ============================================

    def detect_sql_injection(self, logs):

        patterns = [

            "union select",

            "or 1=1",

            "' or '1'='1",

            "drop table",

            "information_schema",

            "sleep(",

            "benchmark(",

            "--"

        ]

        for log in logs:

            if log.get("type") != "apache":
                continue

            request = log.get("request", "").lower()

            for pattern in patterns:

                if pattern in request:

                    self.results.append({

                        "Threat": "SQL Injection",

                        "Severity": "Critical",

                        "IP": log["ip"],

                        "Request": request,

                        "Description":
                            "Possible SQL Injection payload detected."

                    })

                    break

    # ============================================
    # XSS Detection
    # ============================================

    def detect_xss(self, logs):

        patterns = [

            "<script>",

            "%3cscript%3e",

            "javascript:",

            "onerror=",

            "onload="

        ]

        for log in logs:

            if log.get("type") != "apache":
                continue

            request = log.get("request", "").lower()

            for pattern in patterns:

                if pattern in request:

                    self.results.append({

                        "Threat": "Cross Site Scripting (XSS)",

                        "Severity": "High",

                        "IP": log["ip"],

                        "Request": request,

                        "Description":
                            "Potential XSS payload detected."

                    })

                    break

    # ============================================
    # Port Scan Detection
    # ============================================

    def detect_port_scan(self, logs):

        firewall_ips = []

        for log in logs:

            if log.get("type") == "firewall":

                firewall_ips.append(log["ip"])

        counter = Counter(firewall_ips)

        for ip, count in counter.items():

            if count >= 10:

                self.results.append({

                    "Threat": "Port Scan",

                    "Severity": "Medium",

                    "IP": ip,

                    "Connections": count,

                    "Description":
                        "Possible port scanning activity detected."

                })


# ============================================
# Testing
# ============================================

if __name__ == "__main__":

    from log_parser import LogParser

    parser = LogParser()

    logs = parser.parse_file("../sample_logs/auth.log")

    detector = ThreatDetector()

    threats = detector.detect(logs)

    print("\nDetected Threats\n")

    for threat in threats:

        print(threat)
