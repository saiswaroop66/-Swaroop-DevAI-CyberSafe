import re


class LogParser:

    def parse_file(self, file_path):
        logs = []

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:

                line = line.strip()

                if not line:
                    continue

                parsed = (
                    self.parse_auth(line)
                    or self.parse_apache(line)
                    or self.parse_firewall(line)
                )

                if parsed:
                    logs.append(parsed)

        return logs

    # ====================================================
    # Linux Authentication Logs
    # ====================================================

    def parse_auth(self, line):

        auth_keywords = [
            "Failed password",
            "Accepted password",
            "Invalid user",
            "authentication failure"
        ]

        if not any(keyword in line for keyword in auth_keywords):
            return None

        ip_match = re.search(r"from\s+(\d+\.\d+\.\d+\.\d+)", line)

        ip = ip_match.group(1) if ip_match else "Unknown"

        if "Failed password" in line:
            event = "Failed Login"

        elif "Invalid user" in line:
            event = "Invalid User"

        elif "Accepted password" in line:
            event = "Successful Login"

        elif "authentication failure" in line.lower():
            event = "Authentication Failure"

        else:
            event = "Authentication Event"

        return {
            "type": "auth",
            "ip": ip,
            "event": event,
            "raw": line
        }

    # ====================================================
    # Apache / Nginx Access Logs
    # ====================================================

    def parse_apache(self, line):

        pattern = (
            r'(?P<ip>\d+\.\d+\.\d+\.\d+) '
            r'.*?'
            r'"(?P<request>.*?)" '
            r'(?P<status>\d{3})'
        )

        match = re.search(pattern, line)

        if not match:
            return None

        return {
            "type": "apache",
            "ip": match.group("ip"),
            "request": match.group("request"),
            "status": int(match.group("status")),
            "raw": line
        }

    # ====================================================
    # Firewall Logs
    # ====================================================

    def parse_firewall(self, line):

        if "SRC=" not in line:
            return None

        ip_match = re.search(r"SRC=(\d+\.\d+\.\d+\.\d+)", line)

        if not ip_match:
            return None

        return {
            "type": "firewall",
            "ip": ip_match.group(1),
            "event": "Firewall Event",
            "raw": line
        }


# ====================================================
# Testing
# ====================================================

if __name__ == "__main__":

    parser = LogParser()

    logs = parser.parse_file("sample_auth.log")

    print(f"Total Parsed Logs: {len(logs)}")

    for log in logs:
        print(log)
