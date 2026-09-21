# Day 06 - Security Event Timeline
# DSA: Singly Linked List
# Cybersecurity: Security Event Timeline / Chronological Event Tracking

import os

# Ensure script runs seamlessly whether launched from project dir or repo root
if not os.path.exists("events.txt"):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if os.path.exists(os.path.join(script_dir, "events.txt")):
        os.chdir(script_dir)


class Node:
    """
    Represents an individual node in the singly linked list.
    Contains the security event data and a reference to the next node.
    """
    def __init__(self, event):
        self.event = event
        self.next = None


class EventTimeline:
    """
    Represents a chronological security event timeline implemented as a singly linked list.
    Maintains a head pointer referencing the initial event in the timeline.
    """
    def __init__(self):
        self.head = None

    def add_event(self, event):
        """
        Appends a new security event to the end of the timeline.
        Demonstrates linked list node creation and full traversal to the tail.
        """
        new_node = Node(event)

        # Case 1: Linked list is empty -> head points to new node
        if self.head is None:
            self.head = new_node
            return

        # Case 2: Linked list is non-empty -> traverse until current.next is None
        current = self.head
        while current.next is not None:
            current = current.next

        # Link the last node's next pointer to the new node
        current.next = new_node

    def display(self):
        """
        Traverses and displays all security events in stored chronological order.
        Returns the total number of events traversed.
        """
        current = self.head
        count = 0

        while current is not None:
            print(current.event)
            current = current.next
            count += 1

        return count

    def is_empty(self):
        """Checks if the linked list timeline contains no nodes."""
        return self.head is None


def main():
    timeline = EventTimeline()
    valid_events = 0
    skipped_invalid = 0

    # Ingest and validate synthetic events file
    with open("events.txt", "r", encoding="utf-8") as file:
        for line in file:
            cleaned = line.strip()

            # Ignore empty or whitespace-only lines
            if not cleaned:
                skipped_invalid += 1
                continue

            # Defensive parsing: validate TIME | EVENT TYPE | SOURCE format
            parts = [part.strip() for part in cleaned.split("|")]
            if len(parts) != 3 or not all(parts):
                skipped_invalid += 1
                continue

            # Append validated event to custom linked list
            timeline.add_event(cleaned)
            valid_events += 1

    # Ingestion metrics
    print("===== SECURITY EVENT TIMELINE =====\n")
    print(f"Events loaded: {valid_events}")
    print(f"Events stored: {valid_events}")
    print(f"Valid events: {valid_events}")
    print(f"Skipped invalid lines: {skipped_invalid}\n")

    # Chronological traversal through linked list
    print("===== TIMELINE =====\n")
    traversed_count = timeline.display()

    # Traversal summary & list verification
    print("\n===== SUMMARY =====\n")
    print(f"Total events: {traversed_count}")
    print("Timeline traversal complete.")
    print(f"Linked list empty: {timeline.is_empty()}")


if __name__ == "__main__":
    main()
