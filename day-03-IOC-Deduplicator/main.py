# Day 03 - IOC Deduplicator
# DSA: Sets
# Cybersecurity: IOC Management / Deduplication

def main():
    total_entries = 0
    unique_iocs = set()

    with open("iocs.txt", "r", encoding="utf-8") as file:
        for line in file:
            ioc = line.strip()
            if not ioc:
                continue
            total_entries += 1
            unique_iocs.add(ioc)

    duplicates_removed = total_entries - len(unique_iocs)

    print("===== IOC DEDUPLICATOR =====\n")
    print(f"Total IOC entries: {total_entries}")
    print(f"Unique IOCs: {len(unique_iocs)}")
    print(f"Duplicates removed: {duplicates_removed}")

    print("\n===== UNIQUE IOCs =====\n")
    for ioc in sorted(unique_iocs):
        print(ioc)

    print("\n===== SUMMARY =====\n")
    print("Deduplication complete.")


if __name__ == "__main__":
    main()