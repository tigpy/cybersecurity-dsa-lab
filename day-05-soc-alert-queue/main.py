# Day 05 - SOC Alert Queue
# DSA: Queue (FIFO)
# Cybersecurity: SOC Alert Processing / FIFO Event Handling

import os
from collections import deque

# Ensure script runs seamlessly whether launched from project dir or repo root
if not os.path.exists("alerts.txt"):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if os.path.exists(os.path.join(script_dir, "alerts.txt")):
        os.chdir(script_dir)


def main():
    # Initialize Queue data structure
    alert_queue = deque()

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

            # ENQUEUE operation onto Queue (adds to the rear)
            alert_queue.append(alert)

    # Output queue status after ingestion
    print("===== SOC ALERT QUEUE =====\n")
    print(f"Alerts loaded: {len(alert_queue)}\n")
    print(f"Queue size after loading: {len(alert_queue)}\n")

    # Processing alerts in FIFO (First-In, First-Out) order
    print("===== PROCESSING ALERTS - FIFO =====\n")
    while alert_queue:
        # DEQUEUE operation from Queue (removes and returns oldest element from the front)
        alert = alert_queue.popleft()
        print(f"[DEQUEUE] {alert}")

    # Output final queue status
    print("\n===== QUEUE STATUS =====\n")
    print(f"Remaining alerts: {len(alert_queue)}")
    print(f"Queue empty: {len(alert_queue) == 0}\n")
    print("Alert processing complete.")


if __name__ == "__main__":
    main()
