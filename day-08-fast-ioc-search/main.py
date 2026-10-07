# Day 08 - Fast IOC Search
# DSA: Binary Search
# Cybersecurity: Efficient Sorted IOC Lookup

import os
import sys

# Ensure script runs seamlessly whether launched from project dir or repo root
if not os.path.exists("iocs.txt"):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if os.path.exists(os.path.join(script_dir, "iocs.txt")):
        os.chdir(script_dir)


def is_valid_ioc(token: str) -> bool:
    """
    Performs safe, lightweight validation on IOC candidate strings.
    Filters out comments, internal whitespace, and malformed syntax.
    """
    if not token or token.startswith("#"):
        return False
    # Reject strings with internal spaces or control characters
    if any(c.isspace() for c in token):
        return False
    # Reject malformed tokens containing illegal delimiter brackets or colons
    if any(c in token for c in ["[", "]", "{", "}", ":", ";"]):
        return False
    return True


def load_iocs(filepath: str):
    """
    Reads IOC values from the specified file.
    Normalizes whitespace, removes empty lines, and filters malformed records.
    """
    valid_iocs = []
    skipped_count = 0

    with open(filepath, "r", encoding="utf-8") as file:
        for line in file:
            cleaned = line.strip()
            if is_valid_ioc(cleaned):
                valid_iocs.append(cleaned)
            else:
                skipped_count += 1

    return valid_iocs, skipped_count


def binary_search(iocs: list, target: str):
    """
    Explicit Binary Search algorithm implementation.
    
    Searches for 'target' inside the pre-sorted 'iocs' list by iteratively
    halving the search window boundaries (left and right).
    Logs each search step showing current boundaries, middle index, and checked value.
    
    Returns:
        tuple: (found: bool, position: int or None, comparisons: int)
    """
    left = 0
    right = len(iocs) - 1
    step = 1

    while left <= right:
        middle = (left + right) // 2
        current = iocs[middle]

        print(f"Search step {step}:")
        print(f"LEFT={left}")
        print(f"MIDDLE={middle}")
        print(f"RIGHT={right}")
        print(f"CHECK={current}\n")

        if current == target:
            return True, middle, step
        elif current < target:
            left = middle + 1
        else:
            right = middle - 1

        step += 1

    return False, None, step - 1


def search_and_report(iocs: list, target: str):
    """
    Executes binary search for a given target and formats output according to specification.
    """
    print("==================================================")
    print(f"Target: {target}\n")

    found, position, comparisons = binary_search(iocs, target)

    print("===== RESULT =====\n")
    if found:
        print("IOC FOUND")
        print(f"Position: {position}")
        print(f"Comparisons: {comparisons}")
    else:
        print("IOC NOT FOUND")
        print(f"Comparisons: {comparisons}")
    print()
    return found


def main():
    filepath = "iocs.txt"
    if not os.path.exists(filepath):
        print(f"Error: {filepath} not found.")
        sys.exit(1)

    # 1. Read IOCs and sanitize
    raw_iocs, skipped_count = load_iocs(filepath)
    loaded_count = len(raw_iocs)

    # 2. Sort the collection (Binary Search prerequisite)
    iocs = sorted(raw_iocs)
    sorted_count = len(iocs)

    # 3. Output header and dataset statistics
    print("===== FAST IOC SEARCH =====\n")
    print(f"Valid IOCs: {loaded_count}")
    print(f"Skipped lines: {skipped_count}")
    print(f"Loaded IOCs: {loaded_count}")
    print(f"Sorted IOCs: {sorted_count}\n")

    # 4. Execute search tests
    # Support command-line target or run standard educational test suite
    if len(sys.argv) > 1:
        custom_target = sys.argv[1].strip()
        search_and_report(iocs, custom_target)
    else:
        # Test Case 1: Known IOC that exists
        search_and_report(iocs, "10.0.0.61")

        # Test Case 2: IOC that does not exist
        search_and_report(iocs, "10.0.0.250")


if __name__ == "__main__":
    main()
