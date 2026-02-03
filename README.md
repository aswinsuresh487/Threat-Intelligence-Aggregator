# 🛡️ Threat Intelligence Aggregator

![Python](https://img.shields.io/badge/Python-3.13-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen)

A lightweight, modular Python tool for collecting, normalizing, correlating, and operationalizing **Indicators of Compromise (IOCs)** from multiple threat feeds into actionable intelligence for SOC operations.

## 📋 Overview

This tool automates the threat intelligence workflow by:
- Parsing IOCs from multiple threat feeds (IPs, domains, URLs, hashes, emails)
- Normalizing and validating indicators into a unified format
- Storing data in a SQLite database for correlation and analysis
- Generating deployment-ready blocklists for firewalls, web filters, and EDR tools
- Producing comprehensive threat reports in HTML, CSV, and JSON formats

**Perfect for:** Security analysts, SOC teams, blue teams, threat hunters, and cybersecurity students.

---

## ✨ Features

- **Multi-Feed IOC Ingestion** – Supports malicious IPs, domains, URLs, file hashes, and phishing emails
- **Normalization & Validation** – Ensures consistent data formatting using regex and Python libraries
- **Correlation Engine** – Identifies unique IOCs and tracks frequency across feeds
- **Blocklist Generation** – Creates ready-to-deploy lists for:
  - Firewall IP blocking (`firewall_ips.txt`)
  - Web filtering (`web_filter_domains.txt`)
  - EDR hash blacklisting (`edr_hashes.txt`)
- **Comprehensive Reporting** – Exports data as:
  - HTML threat report (analyst-friendly)
  - CSV dataset (SIEM integration)
  - JSON dataset (API/automation)
- **Detailed Logging** – Full audit trail of all operations

---


---

## 🚀 Quick Start

### Prerequisites

- **Python 3.13+**
- **Kali Linux / Ubuntu / macOS** (tested on Kali Linux)
- **Git**

### Installation

bash
# Clone the repository
git clone https://github.com/aswinsuresh487/Threat-Intelligence-Aggregator.git
cd Threat-Intelligence-Aggregator

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

Run Full Workflow (Recommended)
python3 main.py --full-workflow

# Process sample feeds only
python3 main.py --process-samples

# Display database statistics
python3 main.py --stats

# Run correlation analysis
python3 main.py --correlate

# Generate blocklists
python3 main.py --blocklists

# Generate reports
python3 main.py --reports

# Show help
python3 main.py --help

📂 Project Structure

threat-intelligence-aggregator/
├── main.py                      # CLI orchestrator
├── config.py                    # Configuration settings
├── requirements.txt             # Python dependencies
│
├── database/
│   └── db_manager.py            # SQLite database management
│
├── feeds/
│   └── sample_feeds.py          # Sample threat feed data
│
├── parsers/
│   └── feed_parser.py           # IOC parsing logic
│
├── processors/
│   ├── normalizer.py            # Data normalization
│   ├── validator.py             # IOC validation
│   └── enricher.py              # Metadata enrichment
│
├── correlation/
│   └── engine.py                # Correlation analysis
│
├── blocklist/
│   └── generator.py             # Blocklist generation
│
├── reporting/
│   └── reporter.py              # Report & export generation
│
└── output/
    ├── blocklists/              # Generated blocklists
    ├── datasets/                # CSV & JSON exports
    └── reports/                 # HTML threat reports



🔧 Configuration
Edit config.py to customize:


# Database settings
DATABASE_PATH = "database/threat_intelligence.db"

# Output directories
OUTPUT_DIR = "output/"
BLOCKLIST_DIR = "output/blocklists/"
REPORTS_DIR = "output/reports/"
DATASETS_DIR = "output/datasets/"

# Logging
LOG_LEVEL = "INFO"
LOG_FILE = "logs/app.log"




