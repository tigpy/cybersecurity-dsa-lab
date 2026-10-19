"""
Day 10 - Brute-Force Detector
DSA: Sliding Window Technique (O(n) two-pointer chronological scan)
Cybersecurity Application: Time-Window Authentication Attack Detection

This module implements an enterprise-grade defensive authentication log analyzer
that inspects authentication telemetry to detect brute-force, password-spraying,
and credential-stuffing attacks within configurable, timestamp-based sliding windows.
"""

from __future__ import annotations

import argparse
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
import ipaddress
import os
import sys
from typing import NamedTuple, Optional


# ==============================================================================
# Configuration & Data Structures
# ==============================================================================

DEFAULT_WINDOW_SECONDS: int = 300  # 5-minute sliding time window
DEFAULT_FAILURE_THRESHOLD: int = 5  # Alert when >= 5 failures occur in window
VALID_STATUSES = {"FAIL", "SUCCESS"}


@dataclass(frozen=True)
class AuthEvent:
    """Represents a validated authentication telemetry event."""
    timestamp: datetime
    source_ip: str
    status: str
    line_number: int


@dataclass
class BruteForceAlert:
    """Represents a detected brute-force alert trigger."""
    source_ip: str
    failure_count: int
    threshold: int
    window_start: datetime
    window_end: datetime
    first_failure: datetime
    trigger_time: datetime
    window_duration_seconds: float


class ParseResult(NamedTuple):
    """Holds parsed valid events and parsing diagnostics."""
    events: list[AuthEvent]
    total_lines: int
    skipped_count: int
    skipped_reasons: list[tuple[int, str, str]]


# ==============================================================================
# Input Parsing & Validation
# ==============================================================================

def validate_ip_address(ip_str: str) -> bool:
    """
    Validates that a string is a valid IPv4 private address.
    Accepts RFC 1918 private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
    and loopback addresses for synthetic lab security testing.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        return ip_obj.version == 4 and (ip_obj.is_private or ip_obj.is_loopback)
    except ValueError:
        return False


def parse_auth_line(line: str, line_num: int) -> tuple[Optional[AuthEvent], Optional[str]]:
    """
    Parses and validates a single log entry from auth_events.txt.
    Format: timestamp | source_ip | status
    Example: 2026-10-19T10:01:00 | 10.0.0.5 | FAIL

    Returns:
        (AuthEvent, None) if valid.
        (None, reason_string) if malformed or skipped.
    """
    stripped = line.strip()

    # Skip empty lines
    if not stripped:
        return None, "Empty line"

    # Skip comments
    if stripped.startswith("#"):
        return None, "Comment line"

    # Verify delimiter presence
    if "|" not in stripped:
        return None, "Missing pipe delimiter '|'"

    parts = [part.strip() for part in stripped.split("|")]
    if len(parts) != 3:
        return None, f"Expected 3 pipe-delimited fields, found {len(parts)}"

    ts_str, ip_str, status_str = parts

    # Validate timestamp (ISO 8601: YYYY-MM-DDTHH:MM:SS)
    try:
        timestamp = datetime.fromisoformat(ts_str)
    except (ValueError, TypeError):
        return None, f"Invalid ISO 8601 timestamp: '{ts_str}'"

    # Validate IP address
    if not validate_ip_address(ip_str):
        return None, f"Invalid or non-private IPv4 address: '{ip_str}'"

    # Validate status (strictly FAIL or SUCCESS)
    status_upper = status_str.upper()
    if status_upper not in VALID_STATUSES:
        return None, f"Invalid status: '{status_str}' (expected FAIL or SUCCESS)"

    return AuthEvent(
        timestamp=timestamp,
        source_ip=ip_str,
        status=status_upper,
        line_number=line_num
    ), None


def load_auth_events(filepath: str) -> ParseResult:
    """
    Reads an authentication log file, validates each entry, and returns
    chronologically sorted events along with diagnostics on skipped records.
    """
    if not os.path.exists(filepath):
        print(f"[!] Error: Telemetry file '{filepath}' not found.")
        return ParseResult(events=[], total_lines=0, skipped_count=0, skipped_reasons=[])

    valid_events: list[AuthEvent] = []
    skipped_reasons: list[tuple[int, str, str]] = []
    total_lines = 0

    with open(filepath, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f, start=1):
            total_lines += 1
            event, reason = parse_auth_line(line, idx)
            if event is not None:
                valid_events.append(event)
            else:
                skipped_reasons.append((idx, line.strip(), reason or "Malformed"))

    # Assumption documentation: Verify chronological ordering
    # If the dataset is already chronological, sorted() is a stable O(n) Timsort pass.
    valid_events.sort(key=lambda ev: ev.timestamp)

    return ParseResult(
        events=valid_events,
        total_lines=total_lines,
        skipped_count=len(skipped_reasons),
        skipped_reasons=skipped_reasons
    )


# ==============================================================================
# DSA Implementation: Timestamp-Based Sliding Window Algorithm
# ==============================================================================

def detect_brute_force(
    events: list[AuthEvent],
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
    threshold: int = DEFAULT_FAILURE_THRESHOLD,
    verbose: bool = True
) -> list[BruteForceAlert]:
    """
    Analyzes authentication events using an explicit two-pointer sliding window.

    Algorithmic Mechanics:
    ----------------------
    - Input: Array of chronological events sorted by timestamp t_0 <= t_1 <= ... <= t_{n-1}.
    - Moving Pointers:
        - `right`: Advances through every event sequentially, representing the leading window edge.
        - `left`: Advances forward to evict events that have fallen outside the active time window:
                  `events[left].timestamp < events[right].timestamp - window_seconds`.
    - State Tracking:
        - `active_fails[ip]`: A hash map maintaining the exact count of FAIL events
          for each source IP inside the current [left, right] window.
        - `fail_deques[ip]`: A double-ended queue storing the timestamps of failures
          within the window for that IP, allowing O(1) query of the burst start time.
    - Alert Trigger:
        - Only triggered when `events[right].status == 'FAIL'`.
        - Successful logins are ingested into the window timeline but NEVER increment
          failure counts, ensuring legitimate users are not penalized.
        - When `active_fails[ip] >= threshold`, an alert is recorded with its exact
          time window [first_failure_in_window, trigger_time].

    Complexity Analysis:
    --------------------
    - Time Complexity: O(n)
        - `right` moves from 0 to n-1 (n steps).
        - `left` moves strictly monotonically forward from 0 to n (at most n steps total).
        - Each event enters the active window once and is evicted at most once.
        - Dictionary lookups and deque append/popleft operations are O(1) amortized.
        - Total time is strictly O(n) linear in the number of events.
    - Space Complexity: O(u) <= O(n)
        - Where `u` is the number of unique active source IPs with failures in the window.
    """
    # Defensive parameter validation
    if window_seconds <= 0:
        raise ValueError(f"Window duration must be positive (received {window_seconds})")
    if threshold <= 0:
        raise ValueError(f"Failure threshold must be positive (received {threshold})")
    if not events:
        return []

    alerts: list[BruteForceAlert] = []
    active_fails: dict[str, int] = defaultdict(int)
    fail_deques: dict[str, deque[datetime]] = defaultdict(deque)

    left = 0
    window_delta = timedelta(seconds=window_seconds)

    for right in range(len(events)):
        curr_event = events[right]
        cutoff_time = curr_event.timestamp - window_delta

        # Shrink window from the left: evict events older than curr_event.timestamp - window_delta
        while left <= right and events[left].timestamp < cutoff_time:
            evicted = events[left]
            if evicted.status == "FAIL":
                active_fails[evicted.source_ip] -= 1
                if active_fails[evicted.source_ip] == 0:
                    del active_fails[evicted.source_ip]

                if fail_deques[evicted.source_ip]:
                    fail_deques[evicted.source_ip].popleft()
                    if not fail_deques[evicted.source_ip]:
                        del fail_deques[evicted.source_ip]
            left += 1

        # Ingest current event
        if curr_event.status == "FAIL":
            ip = curr_event.source_ip
            active_fails[ip] += 1
            fail_deques[ip].append(curr_event.timestamp)

            current_count = active_fails[ip]
            if current_count >= threshold:
                first_fail = fail_deques[ip][0]
                burst_duration = (curr_event.timestamp - first_fail).total_seconds()
                global_window_start = events[left].timestamp

                alert = BruteForceAlert(
                    source_ip=ip,
                    failure_count=current_count,
                    threshold=threshold,
                    window_start=global_window_start,
                    window_end=curr_event.timestamp,
                    first_failure=first_fail,
                    trigger_time=curr_event.timestamp,
                    window_duration_seconds=burst_duration
                )
                alerts.append(alert)

                if verbose:
                    if current_count == threshold:
                        print(
                            f"[ALERT TRIGGERED] Source: {ip:15} | Failed Attempts: {current_count}/{threshold} "
                            f"| Window: {first_fail.strftime('%H:%M:%S')} -> {curr_event.timestamp.strftime('%H:%M:%S')} "
                            f"({burst_duration:.1f}s)"
                        )
                    else:
                        print(
                            f"  |-- [ESCALATION] Source: {ip:15} | Consecutive Failures: {current_count} "
                            f"| Time: {curr_event.timestamp.strftime('%H:%M:%S')}"
                        )

    return alerts


# ==============================================================================
# Reporting & Visual Summary
# ==============================================================================

def print_execution_report(
    parse_result: ParseResult,
    alerts: list[BruteForceAlert],
    window_seconds: int,
    threshold: int
) -> None:
    """Formats and prints an enterprise SOC incident report."""
    print("\n" + "=" * 78)
    print("           DEFENSIVE SECURITY OPERATIONS - BRUTE-FORCE DETECTOR           ")
    print("=" * 78)

    print("\n[+] CONFIGURATION PARAMETERS:")
    print(f"    - Sliding Window Duration : {window_seconds} seconds ({window_seconds / 60:.1f} minutes)")
    print(f"    - Failure Alert Threshold : {threshold} failed attempts")
    print(f"    - Detection Algorithm     : Monotonic Two-Pointer Sliding Window (O(n))")

    print("\n[+] TELEMETRY INGESTION SUMMARY:")
    print(f"    - Total Lines Read        : {parse_result.total_lines}")
    print(f"    - Valid Chronological Evts: {len(parse_result.events)}")
    print(f"    - Skipped / Corrupted Rows: {parse_result.skipped_count}")

    if parse_result.skipped_reasons:
        print("\n[!] SKIPPED RECORDS BREAKDOWN (Defensive Error Recovery):")
        for line_num, content, reason in parse_result.skipped_reasons[:5]:
            display_content = (content[:35] + "...") if len(content) > 35 else content
            print(f"    - Line {line_num:3d} | Reason: {reason:32} | Content: '{display_content}'")
        if len(parse_result.skipped_reasons) > 5:
            print(f"    - ... and {len(parse_result.skipped_reasons) - 5} additional skipped lines.")

    print("\n[+] DETECTION RESULTS & INCIDENT ANALYSIS:")
    if not alerts:
        print("    [OK] No brute-force activity detected. All failure volumes remained within normal baseline.")
    else:
        # Group alerts by unique attacker IP
        incidents: dict[str, list[BruteForceAlert]] = defaultdict(list)
        for alert in alerts:
            incidents[alert.source_ip].append(alert)

        print(f"    [!] High-priority alerts generated: {len(alerts)} alert events across {len(incidents)} suspicious IPs.\n")
        print(f"    {'SOURCE IP':<16} {'PEAK FAILS':<12} {'FIRST ALERT':<20} {'BURST SPAN':<14} {'SEVERITY'}")
        print("    " + "-" * 72)

        for ip, ip_alerts in incidents.items():
            peak_fails = max(a.failure_count for a in ip_alerts)
            first_alert = ip_alerts[0]
            burst_span = f"{first_alert.window_duration_seconds:.1f}s"
            severity = "CRITICAL" if peak_fails >= threshold * 1.4 else "HIGH"

            print(
                f"    {ip:<16} {f'{peak_fails} / {threshold}':<12} "
                f"{first_alert.trigger_time.strftime('%Y-%m-%d %H:%M:%S'):<20} "
                f"{burst_span:<14} {severity}"
            )

    print("\n[+] SECURITY ADVISORY:")
    print("    - Repeated authentication failures provide a strong detection signal of automated")
    print("      credential attacks, but do not constitute forensic proof of compromise.")
    print("    - Recommended Response: Validate against external threat intelligence, correlate with")
    print("      account lockout telemetry, and apply MFA step-up rather than auto-banning internal IPs.")
    print("=" * 78 + "\n")


# ==============================================================================
# Automated Verification Test Suite
# ==============================================================================

def run_synthetic_tests() -> bool:
    """
    Runs deterministic synthetic unit tests verifying all 7 required criteria:
    1. Normal login activity below threshold produces 0 alerts.
    2. Repeated failed attempts within window trigger an alert.
    3. Failures spread beyond window duration are not incorrectly combined.
    4. Successful logins are not counted as failures.
    5. Malformed records are skipped safely and counted.
    6. Empty input handles gracefully without crashes.
    7. Configurable threshold and window duration operate as documented.
    """
    print("\n" + "=" * 65)
    print("            RUNNING AUTOMATED VERIFICATION TESTS            ")
    print("=" * 65)

    base_time = datetime(2026, 10, 19, 10, 0, 0)
    tests_passed = 0
    total_tests = 7

    # Test 1: Normal login activity below threshold
    t1_events = [
        AuthEvent(base_time + timedelta(seconds=10 * i), "10.0.0.1", "FAIL", i + 1)
        for i in range(3)  # 3 failures, threshold is 5
    ]
    alerts_t1 = detect_brute_force(t1_events, window_seconds=300, threshold=5, verbose=False)
    assert len(alerts_t1) == 0, "Test 1 Failed: Sub-threshold activity triggered alert"
    print("[PASS] Test 1: Normal login activity below threshold produces 0 alerts.")
    tests_passed += 1

    # Test 2: Repeated failed attempts within window trigger alert
    t2_events = [
        AuthEvent(base_time + timedelta(seconds=20 * i), "10.0.0.2", "FAIL", i + 1)
        for i in range(5)  # 5 failures in 80s (window 300s, threshold 5)
    ]
    alerts_t2 = detect_brute_force(t2_events, window_seconds=300, threshold=5, verbose=False)
    assert len(alerts_t2) == 1, f"Test 2 Failed: Expected 1 alert, got {len(alerts_t2)}"
    assert alerts_t2[0].source_ip == "10.0.0.2"
    assert alerts_t2[0].failure_count == 5
    print("[PASS] Test 2: Repeated failed attempts within window trigger alert.")
    tests_passed += 1

    # Test 3: Failures spread beyond configured window are not incorrectly combined
    # 5 failures spaced 400 seconds apart (window is 300 seconds)
    t3_events = [
        AuthEvent(base_time + timedelta(seconds=400 * i), "10.0.0.3", "FAIL", i + 1)
        for i in range(5)
    ]
    alerts_t3 = detect_brute_force(t3_events, window_seconds=300, threshold=3, verbose=False)
    assert len(alerts_t3) == 0, "Test 3 Failed: Spread failures incorrectly combined"
    print("[PASS] Test 3: Failures spread beyond window duration are not combined.")
    tests_passed += 1

    # Test 4: Successful logins are not counted as failures
    # 2 failures and 6 successes for the same IP within 60s (threshold 4)
    t4_events = [
        AuthEvent(base_time + timedelta(seconds=5), "10.0.0.4", "FAIL", 1),
        AuthEvent(base_time + timedelta(seconds=10), "10.0.0.4", "SUCCESS", 2),
        AuthEvent(base_time + timedelta(seconds=15), "10.0.0.4", "SUCCESS", 3),
        AuthEvent(base_time + timedelta(seconds=20), "10.0.0.4", "FAIL", 4),
        AuthEvent(base_time + timedelta(seconds=25), "10.0.0.4", "SUCCESS", 5),
        AuthEvent(base_time + timedelta(seconds=30), "10.0.0.4", "SUCCESS", 6),
    ]
    alerts_t4 = detect_brute_force(t4_events, window_seconds=300, threshold=4, verbose=False)
    assert len(alerts_t4) == 0, "Test 4 Failed: Successful logins counted as failures"
    print("[PASS] Test 4: Successful logins are not counted as failures.")
    tests_passed += 1

    # Test 5: Malformed records are safely skipped
    malformed_lines = [
        "",  # empty
        "# comment",
        "2026-10-19T10:00:00 10.0.0.5 FAIL",  # missing pipe
        "bad-date | 10.0.0.5 | FAIL",  # bad date
        "2026-10-19T10:00:00 | 999.999.1.1 | FAIL",  # invalid IP
        "2026-10-19T10:00:00 | 10.0.0.5 | UNKNOWN",  # bad status
        "2026-10-19T10:00:00 | 10.0.0.5 | FAIL"  # only valid one
    ]
    parsed_valid = []
    skipped_count = 0
    for idx, l in enumerate(malformed_lines, start=1):
        ev, r = parse_auth_line(l, idx)
        if ev is not None:
            parsed_valid.append(ev)
        else:
            skipped_count += 1
    assert len(parsed_valid) == 1, f"Expected 1 valid event, got {len(parsed_valid)}"
    assert skipped_count == 6, f"Expected 6 skipped lines, got {skipped_count}"
    print("[PASS] Test 5: Malformed records are safely skipped with correct counts.")
    tests_passed += 1

    # Test 6: Empty input handles safely without crash
    alerts_t6 = detect_brute_force([], window_seconds=300, threshold=5, verbose=False)
    assert len(alerts_t6) == 0, "Test 6 Failed: Empty input returned non-empty alerts"
    print("[PASS] Test 6: Empty input handles gracefully without crashes.")
    tests_passed += 1

    # Test 7: Threshold and window settings work as documented
    # 4 failures in 200s
    t7_events = [
        AuthEvent(base_time + timedelta(seconds=50 * i), "10.0.0.7", "FAIL", i + 1)
        for i in range(4)
    ]
    # With threshold 4 -> should alert
    alerts_strict = detect_brute_force(t7_events, window_seconds=300, threshold=4, verbose=False)
    # With threshold 5 -> should NOT alert
    alerts_lenient = detect_brute_force(t7_events, window_seconds=300, threshold=5, verbose=False)
    # With window 100s -> only events within 100s (max 3 events) -> should NOT alert at threshold 4
    alerts_short_win = detect_brute_force(t7_events, window_seconds=100, threshold=4, verbose=False)

    assert len(alerts_strict) == 1, "Test 7 Failed: Strict threshold did not alert"
    assert len(alerts_lenient) == 0, "Test 7 Failed: Lenient threshold alerted unexpectedly"
    assert len(alerts_short_win) == 0, "Test 7 Failed: Short window failed to evict older events"
    print("[PASS] Test 7: Configurable threshold and window duration operate as documented.")
    tests_passed += 1

    print("=" * 65)
    print(f"       ALL {tests_passed}/{total_tests} VERIFICATION TESTS PASSED SUCCESSFULLY!       ")
    print("=" * 65 + "\n")
    return True


# ==============================================================================
# CLI Entry Point
# ==============================================================================

def main() -> None:
    """CLI orchestrator for brute-force detection analysis."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_dataset = os.path.join(script_dir, "auth_events.txt")

    parser = argparse.ArgumentParser(
        description="Defensive Authentication Brute-Force Detector (Sliding Window Algorithm)"
    )
    parser.add_argument(
        "-f", "--file",
        default=default_dataset,
        help="Path to authentication telemetry log file (default: auth_events.txt)"
    )
    parser.add_argument(
        "-w", "--window",
        type=int,
        default=DEFAULT_WINDOW_SECONDS,
        help=f"Sliding window size in seconds (default: {DEFAULT_WINDOW_SECONDS}s / 5 mins)"
    )
    parser.add_argument(
        "-t", "--threshold",
        type=int,
        default=DEFAULT_FAILURE_THRESHOLD,
        help=f"Failure count threshold to trigger an alert (default: {DEFAULT_FAILURE_THRESHOLD})"
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Execute synthetic unit test verification suite"
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress real-time event streaming output"
    )

    args = parser.parse_args()

    # If --test flag provided, run unit test suite
    if args.test:
        run_synthetic_tests()
        return

    # Validate parameters
    if args.window <= 0 or args.threshold <= 0:
        print("[!] Error: Window duration and threshold must both be positive integers.")
        sys.exit(1)

    print("===== STARTING BRUTE-FORCE DETECTOR ANALYSIS =====")
    print(f"Target Telemetry File : {args.file}")
    print(f"Sliding Window Size   : {args.window} seconds ({args.window / 60:.1f} minutes)")
    print(f"Failure Alert Cutoff  : {args.threshold} failed logins\n")

    # Ingest and validate logs
    parse_result = load_auth_events(args.file)

    if not parse_result.events:
        print("[!] No valid authentication events found to analyze.")
        print_execution_report(parse_result, [], args.window, args.threshold)
        return

    print("[*] Processing events chronologically through sliding window...")
    alerts = detect_brute_force(
        events=parse_result.events,
        window_seconds=args.window,
        threshold=args.threshold,
        verbose=not args.quiet
    )

    # Print comprehensive SOC report
    print_execution_report(parse_result, alerts, args.window, args.threshold)


if __name__ == "__main__":
    main()