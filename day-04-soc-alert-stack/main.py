# Day 04 - SOC Alert Stack
# DSA: Stack (LIFO)
# Cybersecurity: SOC Alert Handling / Investigation Workflow

import os

# Ensure script runs seamlessly whether launched from project dir or repo root
if not os.path.exists("alerts.txt"):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if os.path.exists(os.path.join(script_dir, "alerts.txt")):
        os.chdir(script_dir)


def main():
    # Initialize Stack data structure
    alert_stack = []

    # File ingestion
    with open("alerts.txt", "r", encoding="utf-8") as file:
        for line in file:
            alert = line.strip()

            # Ignore empty lines
            if not alert:
                continue

            # Defensive parsing: validate basic format (ALERT-ID | ALERT-TYPE | SOURCE)
            parts = alert.split("|")
            if len(parts) != 3:
                continue

            # PUSH operation onto Stack
            alert_stack.append(alert)

    # Output stack status after ingestion
    print("===== SOC ALERT STACK =====\n")
    print(f"Alerts loaded: {len(alert_stack)}\n")
    print(f"Stack size after loading: {len(alert_stack)}\n")

    # Processing alerts in LIFO (Last-In, First-Out) order
    print("===== PROCESSING ALERTS - LIFO =====\n")
    while alert_stack:
        # POP operation from Stack (removes and returns newest element)
        alert = alert_stack.pop()
        print(f"[POP] {alert}")

    # Output final stack status
    print("\n===== STACK STATUS =====\n")
    print(f"Remaining alerts: {len(alert_stack)}")
    print(f"Stack empty: {len(alert_stack) == 0}\n")
    print("Alert processing complete.")


if __name__ == "__main__":
    main()