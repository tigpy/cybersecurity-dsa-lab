# Day 02 - Failed Login Detector
# DSA: Hash Maps / Dictionaries
# Cybersecurity: Authentication Monitoring & Alerting

import os

# Locate log file relative to script location or working directory
LOG_FILE = "auth_logs.txt"
if not os.path.exists(LOG_FILE):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    LOG_FILE = os.path.join(base_dir, "auth_logs.txt")

THRESHOLD = 5
failed_attempts = {}

# Ingest and parse authentication logs
with open(LOG_FILE, "r", encoding="utf-8") as file:
    for line in file:
        line = line.strip()

        # Handle empty lines
        if not line:
            continue

        parts = line.split()

        # Handle malformed lines missing expected fields
        if len(parts) != 5:
            continue

        status = parts[2]

        # Safely extract source IP
        if not parts[4].startswith("ip="):
            continue
        ip = parts[4].split("=")[1]

        # Core DSA: Hash Map frequency counting
        if status == "FAILED":
            failed_attempts[ip] = failed_attempts.get(ip, 0) + 1

# Display summary statistics
print("===== FAILED LOGIN DETECTOR =====")
print(f"Total failed logins: {sum(failed_attempts.values())}")
print(f"Unique source IPs: {len(failed_attempts)}")
print()

print("Failed attempts by IP:")
for ip, count in failed_attempts.items():
    print(f"{ip:<16} {count} failed attempts")

print()
print(f"===== ALERTS: {THRESHOLD}+ FAILED LOGINS =====")

alerts = 0
for ip, count in failed_attempts.items():
    if count >= THRESHOLD:
        print(f"[ALERT] {ip} -> {count} failed login attempts")
        alerts += 1

if alerts == 0:
    print("No IP crossed the detection threshold.")

print()
print("Detection complete.")