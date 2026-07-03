import re


class LogParser:

    def parse_file(self, file_path):
        """
        Detect log type and parse.
        """

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        logs = []

        for line in lines:

            line = line.strip()

            if not line:
                continue

            parsed = (
                self.parse_apache(line)
                or self.parse_auth(line)
                or self.parse_firewall(line)
            )

            if parsed:
                logs.append(parsed)

        return logs

    # ---------------------------------------
    # Apache / Nginx Logs
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
            "time": match.group("time"),
            "request": match.group("request"),
            "status": int(match.group("status")),
            "raw": line
        }

    # ---------------------------------------
    # Linux auth.log
    # ---------------------------------------

    def parse_auth(self, line):

        pattern = (
            r'(?P<month>\w+)'
            r'\s+(?P<day>\d+)'
            r'\s+(?P<time>\S+)'
            r'.*Failed password.*from (?P<ip>\S+)'
        )

        match = re.search(pattern, line)

        if not match:
            return None

        return {
            "type": "auth",
            "ip": match.group("ip"),
            "time": f"{match.group('month')} {match.group('day')} {match.group('time')}",
            "event": "Failed Login",
            "raw": line
        }

    # ---------------------------------------
    # Firewall Logs
    # ---------------------------------------

    def parse_firewall(self, line):

        ip_match = re.search(r"SRC=(\S+)", line)

        if not ip_match:
            return None

        return {
            "type": "firewall",
            "ip": ip_match.group(1),
            "event": "Firewall Event",
            "raw": line
        }


# ---------------------------------------
# Testing
# ---------------------------------------

if __name__ == "__main__":

    parser = LogParser()

    logs = parser.parse_file("../sample_logs/apache.log")

    for log in logs:
        print(log)