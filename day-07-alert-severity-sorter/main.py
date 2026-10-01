# Day 07 - Alert Severity Sorter
# DSA: Sorting
# Cybersecurity: Security Alert Prioritization and Ordering

import os

# Ensure script runs seamlessly whether launched from project dir or repo root
if not os.path.exists("alerts.txt"):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if os.path.exists(os.path.join(script_dir, "alerts.txt")):
        os.chdir(script_dir)

# Severity priority mapping (CRITICAL = 4, HIGH = 3, MEDIUM = 2, LOW = 1)
SEVERITY_RANK = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1
}


def parse_alert(line):
    """
    Safely parses an alert record from a raw log line.
    Expected format: ALERT-ID severity=LEVEL source=IP
    Returns a dictionary if valid, or None if malformed.
    """
    line = line.strip()
    if not line:
        return None

    parts = line.split()
    if len(parts) < 3:
        return None

    alert_id = parts[0]
    severity = None
    source_ip = None

    for part in parts[1:]:
        if part.startswith("severity="):
            severity = part.split("=", 1)[1].upper()
        elif part.startswith("source="):
            source_ip = part.split("=", 1)[1]

    # Validate all required fields and valid severity level
    if not alert_id or not severity or not source_ip:
        return None

    if severity not in SEVERITY_RANK:
        return None

    return {
        "id": alert_id,
        "severity": severity,
        "source": source_ip
    }


def load_alerts(filepath):
    """
    Reads alerts from file and applies defensive parsing.
    Returns list of parsed alert dictionaries.
    """
    alerts = []
    with open(filepath, "r", encoding="utf-8") as file:
        for line in file:
            raw = line.strip()
            # Ignore empty lines
            if not raw:
                continue

            alert = parse_alert(raw)
            if alert:
                alerts.append(alert)
            else:
                # Safely handle malformed lines without crashing
                print(f"[WARN] Skipping malformed alert line: {raw}")

    return alerts


def main():
    print("===== ALERT SEVERITY SORTER =====")

    # 1. Load and parse alerts safely from alerts.txt
    alerts = load_alerts("alerts.txt")
    print(f"Total alerts loaded: {len(alerts)}")

    # 2. Display original alert order
    print("\nOriginal alert order:")
    for alert in alerts:
        print(f"{alert['id']} | {alert['severity']} | {alert['source']}")

    # 3. Sort alerts from highest severity to lowest severity
    # Python's built-in sorted() utilizes Timsort (O(n log n) average & worst case)
    sorted_alerts = sorted(
        alerts,
        key=lambda alert: SEVERITY_RANK[alert["severity"]],
        reverse=True
    )

    # 4. Display prioritized alert queue with position/rank
    print("\n===== PRIORITIZED ALERT QUEUE =====")
    for position, alert in enumerate(sorted_alerts, start=1):
        print(f"{position} | {alert['id']} | {alert['severity']} | {alert['source']}")

    # 5. Clear completion message
    print("\nSorting complete. All alerts prioritized successfully.")


if __name__ == "__main__":
    main()