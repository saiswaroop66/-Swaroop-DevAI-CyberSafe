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

    # ---------------------------------------
    # Linux Authentication Logs
    # ---------------------------------------

    def parse_auth(self, line):

        ip = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)

        if not ip:
            return None

        event = "Unknown"

        if "Failed password" in line:
            event = "Failed Login"

        elif "Invalid user" in line:
            event = "Invalid User"

        elif "Accepted password" in line:
            event = "Successful Login"

        elif "authentication failure" in line.lower():
            event = "Authentication Failure"

        return {
            "type": "auth",
            "ip": ip.group(1),
            "event": event,
            "raw": line
        }

    # ---------------------------------------
    # Apache / Nginx
    # ---------------------------------------

    def parse_apache(self, line):

        pattern = (
            r'(?P<ip>\S+) \S+ \S+ '
            r'\[(?P<time>.*?)\] '
            r'"(?P<request>.*?)" '
            r'(?P<status>\d{3})'
        )

        match = re.match(pattern, line)

        if not match:
            return None

        return {
            "type": "apache",
            "ip": match.group("ip"),
            "request": match.group("request"),
            "status": int(match.group("status")),
            "raw": line
        }

    # ---------------------------------------
    # Firewall
    # ---------------------------------------

    def parse_firewall(self, line):

        ip = re.search(r"SRC=(\d+\.\d+\.\d+\.\d+)", line)

        if not ip:
            return None

        return {
            "type": "firewall",
            "ip": ip.group(1),
            "raw": line
        }


if __name__ == "__main__":

    parser = LogParser()

    logs = parser.parse_file("sample_auth.log")

    print("Parsed Logs:", len(logs))

    for log in logs[:10]:
        print(log)
