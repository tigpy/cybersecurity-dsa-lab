# Cybersecurity + DSA Project Lab

> A hands-on laboratory exploring practical Data Structures and Algorithms (DSA) implemented through real-world defensive cybersecurity, SOC automation, and security engineering use cases.

[![Python](https://img.shields.io/badge/Python-3.x-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Focus](https://img.shields.io/badge/Focus-Cybersecurity%20%2B%20DSA-blue)](#laboratory-structure)
[![Progress](https://img.shields.io/badge/Progress-Day%2006%20Completed-success)](#daily-curriculum--lab-directory) <!-- Day 06 Completed -->

---

## Overview

Security engineers and SOC analysts constantly process massive volumes of telemetry—system logs, network packets, authentication records, and threat intelligence indicators. Writing efficient, scalable defensive tools requires an intimate understanding of foundational computer science: data structures, algorithmic complexity, memory representation, and data normalization.

This repository documents daily defensive security tools built from scratch in Python, pairing theoretical DSA concepts with authentic blue-team engineering challenges.

---

## Learning Method

Each lab follows a disciplined, engineering-first methodology:

```text
DSA Concept ──▶ Cybersecurity Problem ──▶ Python Implementation ──▶ Execution Visualization ──▶ Documentation ──▶ Version Control Tracking
```

---

## Daily Curriculum & Lab Directory

| Day | Project | Core DSA Concept | Cybersecurity Application | Status |
| :---: | :--- | :--- | :--- | :---: |
| **01** | [**SOC Log Analyzer**](day-01-soc-log-analyzer/) | Arrays / Dynamic Lists, Strings | Authentication log ingestion, record normalization, and SOC summary generation | Completed |
| **02** | [**Failed Login Detector**](day-02-failed-login-detector/) | Hash Maps | Authentication failure aggregation and suspicious login detection | Completed |
| **03** | [**IOC Deduplicator**](day-03-IOC-Deduplicator/) | Sets | Threat intelligence IOC deduplication and normalization | Completed |
| **04** | [**SOC Alert Stack**](day-04-soc-alert-stack/) | Stack | LIFO-based SOC alert handling and investigation workflow | Completed |
| **05** | [**SOC Alert Processing Queue**](day-05-soc-alert-queue/) | Queue | FIFO-based SOC alert processing and event handling | Completed |
| **06** | [**Security Event Timeline**](day-06-security-event-timeline/) | Linked List | Chronological security event tracking and event timeline traversal | Completed |
| **07** | Alert Severity Sorter | Sorting | Security alert prioritization and ordering | Planned |
| **08** | Fast IOC Search | Binary Search | Efficient sorted IOC lookup | Planned |
| **09** | Traffic Pair Analyzer | Two Pointers | Network traffic relationship analysis | Planned |
| **10** | Brute-Force Detector | Sliding Window | Time-window authentication attack detection | Planned |
| **11** | SOC Alert Prioritizer | Heap / Priority Queue | Alert severity prioritization | Planned |
| **12** | Process Tree Analyzer | Binary Tree | Process hierarchy analysis | Planned |
| **13** | Security Event BST | Binary Search Tree | Ordered security event lookup | Planned |
| **14** | Network Topology Mapper | Graph | Network relationship modeling | Planned |
| **15** | Network Discovery Tool | BFS | Network topology discovery | Planned |
| **16** | Attack Path Investigator | DFS | Attack-path exploration | Planned |
| **17** | Network Path Analyzer | Dijkstra | Shortest-path network analysis | Planned |
| **18** | IOC Prefix Matcher | Trie | Prefix-based IOC lookup | Planned |
| **19** | Network Traffic Analyzer | Prefix Sum | Efficient traffic aggregation | Planned |
| **20** | Recursive Process Investigator | Recursion | Recursive process investigation | Planned |
| **21** | Incident Scheduler | Greedy | Incident response scheduling | Planned |
| **22** | Security Optimization Engine | Dynamic Programming | Security resource optimization | Planned |
| **23** | Permission Analyzer | Bit Manipulation | Permission and access analysis | Planned |
| **24** | Network Segment Analyzer | Union-Find | Network segment connectivity analysis | Planned |
| **25** | Attack Chain Dependency Analyzer | Topological Sort | Attack-chain dependency analysis | Planned |
| **26** | Threat Intel Cache | LRU Cache | Threat intelligence cache management | Planned |
| **27** | Security Configuration Generator | Backtracking | Security configuration generation | Planned |
| **28** | Evidence Integrity Tool | Hashing | Evidence integrity verification | Planned |
| **29** | Security Data Complexity Analyzer | Big-O | Algorithmic complexity analysis | Planned |
| **30** | Mini SOC Detection Engine | Combined DSA | Integrated security detection workflow | Planned |

---

## Getting Started

### Prerequisites

- Python 3.8 or higher installed on your system.
- Standard terminal or PowerShell shell (no external dependencies required for foundational labs).

### Quickstart

Clone the repository and run any daily lab:

```bash
# Clone the repository
git clone https://github.com/tigpy/cybersecurity-dsa-lab.git
cd cybersecurity-dsa-lab

# Example: Run Day 01
cd day-01-soc-log-analyzer
python main.py

# Example: Run Day 06
cd ../day-06-security-event-timeline
python main.py
```

---

## Repository Structure

```text
cybersecurity-dsa-lab/
├── .gitignore
├── README.md
├── day-01-soc-log-analyzer/
│   ├── main.py
│   ├── sample_logs.txt
│   ├── soc_log.png
│   └── README.md
├── day-02-failed-login-detector/
│   ├── auth_logs.txt
│   ├── failed_login.png
│   ├── main.py
│   └── README.md
├── day-03-IOC-Deduplicator/
│   ├── iocs.txt
│   ├── ioc_deduplication.png
│   ├── main.py
│   └── README.md
├── day-04-soc-alert-stack/
│   ├── alerts.txt
│   ├── alert_stack.png
│   ├── main.py
│   └── README.md
├── day-05-soc-alert-queue/
│   ├── alerts.txt
│   ├── alert_queue.png
│   ├── main.py
│   └── README.md
└── day-06-security-event-timeline/
    ├── events.txt
    ├── event_timeline.png
    ├── main.py
    └── README.md
```

---

## Author

**Aryan Singh**  
Cybersecurity & Software Engineering Lab  
GitHub: [@tigpy](https://github.com/tigpy)

---

## License & Security Disclaimer

All log datasets, scenarios, and artifacts provided in this repository are synthetic and created solely for defensive education, algorithmic analysis, and training purposes. Do not execute against unauthorized systems or import real corporate credentials or sensitive personal identifiable information (PII).
