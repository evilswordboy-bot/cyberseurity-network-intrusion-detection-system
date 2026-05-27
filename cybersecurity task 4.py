import re
from collections import defaultdict


class LogIntrusionDetector:

    def __init__(self):

        self.failed_logins = defaultdict(int)

        self.attack_patterns = [
            "failed login",
            "unauthorized",
            "access denied",
            "sql injection",
            "malware",
            "attack detected",
            "ddos",
            "brute force"
        ]

    def analyze_log(self, log_path):

        print("\n[+] Analyzing Log File:", log_path)

        try:
            with open(log_path, "r", encoding="utf-8") as file:

                for line in file:

                    line_lower = line.lower()

                    # Detect attack keywords
                    for pattern in self.attack_patterns:

                        if pattern in line_lower:

                            print("\n[ALERT] Suspicious Activity Found")
                            print("Pattern:", pattern)
                            print("Log:", line.strip())

                    # Detect brute-force attacks
                    if "failed login" in line_lower:

                        ip_match = re.search(
                            r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
                            line
                        )

                        if ip_match:

                            ip = ip_match.group()

                            self.failed_logins[ip] += 1

                            if self.failed_logins[ip] >= 3:

                                print("\n[CRITICAL] Possible Brute Force Attack")
                                print("IP Address:", ip)
                                print(
                                    "Failed Attempts:",
                                    self.failed_logins[ip]
                                )

        except FileNotFoundError:
            print("[ERROR] Log file not found")

        except Exception as e:
            print("[ERROR]", e)


# MAIN

detector = LogIntrusionDetector()

log_path = input("Enter log file path: ")

detector.analyze_log(log_path)
