# Cybersecurity + DSA Project Lab

> A hands-on laboratory exploring practical Data Structures and Algorithms (DSA) implemented through real-world defensive cybersecurity, SOC automation, and security engineering use cases.

[![Python](https://img.shields.io/badge/Python-3.x-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Focus](https://img.shields.io/badge/Focus-Cybersecurity%20%2B%20DSA-blue)](#laboratory-structure)
[![Progress](https://img.shields.io/badge/Progress-Day%2001%20Completed-success)](#daily-curriculum--lab-directory)

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

# Run Day 01
cd day-01-soc-log-analyzer
python main.py
```

---

## Repository Structure

```text
cybersecurity-dsa-lab/
├── .gitignore
├── README.md
└── day-01-soc-log-analyzer/
    ├── main.py
    ├── sample_logs.txt
    ├── soc_log.png
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
