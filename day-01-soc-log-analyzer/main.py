# Day 01 - SOC Log Analyzer
# DSA: Arrays + Strings

LOG_FILE = "sample_logs.txt"
events = []

# Read and parse logs
with open(LOG_FILE, "r", encoding="utf-8") as file:
    for line in file:
        line = line.strip()

        if not line:
            continue

        parts = line.split()

        if len(parts) != 5:
            continue

        timestamp = parts[0] + " " + parts[1]
        status = parts[2]
        user = parts[3].split("=")[1]
        ip = parts[4].split("=")[1]

        events.append({
            "time": timestamp,
            "status": status,
            "user": user,
            "ip": ip
        })


# Analyze events
successful = 0
failed = 0
users = []
ips = []

for event in events:
    if event["status"] == "SUCCESS":
        successful += 1
    elif event["status"] == "FAILED":
        failed += 1

    users.append(event["user"])
    ips.append(event["ip"])


# Display results
print("===== SOC LOG ANALYZER =====")
print("Total events:", len(events))
print("Successful logins:", successful)
print("Failed logins:", failed)
print("Unique users:", len(set(users)))
print("Unique IPs:", len(set(ips)))