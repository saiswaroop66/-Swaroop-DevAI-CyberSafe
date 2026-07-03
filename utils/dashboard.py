import re


class Dashboard:

    def __init__(self):
        pass

    # -----------------------------
    # Calculate Dashboard Metrics
    # -----------------------------

    def calculate_metrics(self, threats):

        metrics = {
            "total": len(threats),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "risk_score": 0
        }

        for threat in threats:

            severity = threat.get("severity", "Low").lower()

            if severity == "critical":
                metrics["critical"] += 1

            elif severity == "high":
                metrics["high"] += 1

            elif severity == "medium":
                metrics["medium"] += 1

            else:
                metrics["low"] += 1

        # -----------------------------
        # Calculate Risk Score
        # -----------------------------

        score = (
            metrics["critical"] * 25 +
            metrics["high"] * 15 +
            metrics["medium"] * 8 +
            metrics["low"] * 3
        )

        metrics["risk_score"] = min(score, 100)

        return metrics

    # -----------------------------
    # Count Threat Types
    # -----------------------------

    def threat_distribution(self, threats):

        distribution = {}

        for threat in threats:

            name = threat.get("type", "Unknown")

            distribution[name] = distribution.get(name, 0) + 1

        return distribution

    # -----------------------------
    # Extract Source IPs
    # -----------------------------

    def top_ips(self, threats):

        ip_count = {}

        for threat in threats:

            ip = threat.get("ip", "Unknown")

            ip_count[ip] = ip_count.get(ip, 0) + 1

        return ip_count

    # -----------------------------
    # Parse IPs directly from log
    # -----------------------------

    def extract_ips_from_log(self, file_path):

        pattern = r"(?:\d{1,3}\.){3}\d{1,3}"

        ip_count = {}

        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:

            for line in file:

                ips = re.findall(pattern, line)

                for ip in ips:

                    ip_count[ip] = ip_count.get(ip, 0) + 1

        return ip_count