# Day 09: Traffic Pair Analyzer
# DSA: Two Pointers Technique (O(n) on sorted data)
# Cybersecurity: Network Traffic Relationship & Flow Volume Correlation Analysis

import os
import sys

# Ensure script runs seamlessly whether launched from project dir or repo root
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DATASET = os.path.join(SCRIPT_DIR, "traffic.txt")


def parse_record(line: str) -> int | None:
    """
    Safely parses a single line from the traffic dataset.
    
    Expected format: record_id | packet_count
    Filters out comments, empty lines, and malformed/non-integer records.
    Returns positive integer packet count if valid, otherwise None.
    """
    cleaned = line.strip()
    if not cleaned or cleaned.startswith("#"):
        return None
    
    if "|" not in cleaned:
        return None
    
    parts = cleaned.split("|", 1)
    if len(parts) != 2:
        return None
    
    count_str = parts[1].strip()
    if not count_str.isdigit():
        return None
    
    count = int(count_str)
    # Require strictly positive packet counts (> 0)
    if count <= 0:
        return None
    
    return count


def load_traffic_dataset(filepath: str) -> tuple[list[int], int]:
    """
    Loads traffic records from file, validating format and extracting packet counts.
    
    Returns:
        tuple: (list of valid packet counts, count of skipped/malformed records)
    """
    if not os.path.exists(filepath):
        print(f"[!] Error: Dataset file '{filepath}' not found.")
        return [], 0
    
    valid_counts = []
    skipped_count = 0
    
    with open(filepath, "r", encoding="utf-8") as file:
        for line in file:
            count = parse_record(line)
            if count is not None:
                valid_counts.append(count)
            else:
                skipped_count += 1
                
    return valid_counts, skipped_count


def two_pointer_traffic_analyzer(traffic: list[int], target: int) -> tuple[bool, tuple[int, int] | None, int]:
    """
    Explicit Two Pointers algorithm for locating a pair with a target sum.
    
    Prerequisite: 'traffic' must be sorted in ascending order.
    
    Pointer mechanics:
        - left pointer starts at index 0 (smallest packet count)
        - right pointer starts at index len(traffic) - 1 (largest packet count)
        - Loop condition: left < right (ensures distinct elements, never pairing an element with itself)
        - If sum < target: move left pointer forward (left += 1) to increase the total
        - If sum > target: move right pointer backward (right -= 1) to decrease the total
        - If sum == target: matching pair found
        
    Returns:
        tuple: (found: bool, pair: tuple[int, int] | None, comparisons: int)
    """
    if len(traffic) < 2:
        print("[!] Insufficient data: At least 2 traffic records are required to analyze pairs.")
        return False, None, 0

    left = 0
    right = len(traffic) - 1
    comparisons = 0
    found = False
    pair = None

    while left < right:
        comparisons += 1
        total = traffic[left] + traffic[right]
        
        print(f"LEFT: {traffic[left]} RIGHT: {traffic[right]} TOTAL: {total}")
        
        if total == target:
            found = True
            pair = (traffic[left], traffic[right])
            print(f"MATCH FOUND: {traffic[left]} + {traffic[right]}")
            break
        elif total < target:
            left += 1
        else:
            right -= 1

    if not found:
        print(f"NO MATCH FOUND: No pair of distinct packet counts sums to target {target}.")

    print("Analysis complete.")
    return found, pair, comparisons


def get_user_target(default: int = 500) -> int:
    """
    Prompts the user for a target total packet count.
    Falls back to a sensible default if the user presses Enter or provides empty input.
    Gracefully handles non-numeric input and EOF without crashing.
    """
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        return int(sys.argv[1])
        
    try:
        user_input = input(f"Enter target packet sum [default: {default}]: ").strip()
        if not user_input:
            print(f"Using default target: {default}")
            return default
        target = int(user_input)
        if target <= 0:
            print(f"[!] Warning: Target must be a positive integer. Using default: {default}")
            return default
        return target
    except ValueError:
        print(f"[!] Invalid input. Non-numeric value entered. Using default target: {default}")
        return default
    except (EOFError, KeyboardInterrupt):
        print(f"\nUsing default target: {default}")
        return default


def main():
    print("===== TRAFFIC PAIR ANALYZER =====\n")
    
    # 1. Read and validate dataset
    raw_counts, skipped_count = load_traffic_dataset(DEFAULT_DATASET)
    valid_count = len(raw_counts)
    
    print(f"Dataset File: {DEFAULT_DATASET}")
    print(f"Valid Records Parsed: {valid_count}")
    print(f"Skipped Lines (Comments/Malformed/Empty): {skipped_count}\n")
    
    if valid_count < 2:
        print("[!] Error: Insufficient valid records in dataset to perform pair analysis.")
        sys.exit(1)
        
    # 2. Store and sort packet counts in ascending order
    # Note: Sorting transforms the input collection to establish monotonic ordering.
    # The two-pointer search operates on sorted packet-count values, not original flow arrival sequences.
    traffic = sorted(raw_counts)
    
    # 3. Ask user for target total with sensible default
    target = get_user_target(default=500)
    print(f"Target total: {target}\n")
    
    # 4-10. Execute explicit two-pointer analysis
    found, pair, comparisons = two_pointer_traffic_analyzer(traffic, target)
    
    print("\n===== SUMMARY =====")
    print(f"Target: {target}")
    print(f"Pair Found: {found}")
    if found and pair:
        print(f"Matching Values: {pair[0]} and {pair[1]}")
    print(f"Comparisons Evaluated: {comparisons}")
    print(f"Active Search Space: {len(traffic)} records")
    print("===================\n")


if __name__ == "__main__":
    main()
