# Threat Intelligence Aggregator

> A lightweight, modular Python tool for collecting, normalizing, correlating, and operationalizing Indicators of Compromise (IOCs) from multiple threat feeds into actionable intelligence for SOC operations.

[![Python](https://img.shields.io/badge/Python-3.13-blue?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Production%20Ready-success)]()

---

## 🎯 Overview

Modern security teams face a critical challenge: threat intelligence arrives from multiple sources in inconsistent formats. Manual correlation is slow, error-prone, and doesn't scale during active incidents.

**Threat Intelligence Aggregator** solves this by:
- **Ingesting** IOCs from multiple feeds (IPs, domains, URLs, hashes, emails)
- **Normalizing** data into a unified SQLite database
- **Correlating** indicators across sources to identify high-confidence threats
- **Generating** deployment-ready blocklists and human-friendly reports

Perfect for SOC analysts, threat intelligence teams, and blue team operations.

---

## ✨ Key Features

| Feature | Capability |
|---------|-----------|
| **Multi-Feed Ingestion** | Parses IPs, domains, URLs, hashes, emails from 5+ sources |
| **Data Normalization** | Validates and standardizes indicators for consistent storage |
| **Correlation Engine** | Tracks frequency across feeds; identifies high-confidence IOCs |
| **Blocklist Generation** | Produces 3 enforcement-ready lists (firewall, DNS filter, EDR) |
| **Multi-Format Reporting** | HTML (analyst-friendly), CSV (SIEM-ready), JSON (programmatic) |
| **Audit Logging** | Complete execution trace for compliance and debugging |
| **CLI-Driven** | Simple commands: `--process-samples`, `--correlate`, `--full-workflow` |

---

## 📊 Quick Stats

```
Total IOCs Processed:   21
Feed Sources:           5
Unique Indicators:      21

Breakdown:
├── IPv4 Addresses:     5
├── Domains:            5
├── URLs:               5
├── File Hashes:        3
└── Email Addresses:    3

Output Artifacts:
├── 3 Blocklists (firewall IPs, domain URLs, EDR hashes)
├── CSV Dataset (SIEM import-ready)
├── JSON Export (programmatic integration)
└── HTML Report (analyst review)
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.13+
- SQLite3 (built-in with Python)
- Virtual environment (recommended)

### Installation

```bash
# Clone the repository
git clone https://github.com/aswinsuresh487/threat-intelligence-aggregator.git
cd threat-intelligence-aggregator

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Basic Usage

```bash
# Show all available commands
python main.py --help

# Process sample threat feeds
python main.py --process-samples

# Run correlation analysis
python main.py --correlate

# Generate blocklists and reports
python main.py --blocklists
python main.py --reports

# Run complete workflow (recommended)
python main.py --full-workflow
```

---

## 📁 Project Structure

```
threat-intelligence-aggregator/
├── main.py                      # CLI orchestrator
├── requirements.txt             # Python dependencies
│
├── database/
│   └── db_manager.py           # SQLite database layer
│
├── correlation/
│   └── engine.py               # IOC correlation logic
│
├── blocklist/
│   └── generator.py            # Blocklist generation
│
├── reporting/
│   └── reporter.py             # HTML, CSV, JSON exports
│
├── sample_feeds/               # Sample threat data
│   ├── malicious_ips.txt
│   ├── malicious_domains.txt
│   ├── malicious_urls.txt
│   ├── malicious_hashes.txt
│   └── phishing_emails.txt
│
├── output/                      # Generated outputs
│   ├── blocklists/             # Firewall, DNS, EDR lists
│   ├── datasets/               # CSV and JSON exports
│   └── reports/                # HTML threat report
│
├── database/
│   └── threat_intelligence.db  # SQLite database
│
└── logs/
    └── app.log                 # Execution trace
```

---

## 🔧 Architecture

The system follows a **linear pipeline** architecture:

```
Sample Feeds
    ↓
[Feed Parser] → Extracts IOCs
    ↓
[Normalization] → Validates & cleans data
    ↓
[Database Layer] → Persists to SQLite
    ↓
[Correlation Engine] → Computes frequency & severity
    ↓
[Blocklist Generator] ──→ Firewall IPs
                       ├─→ Web Filter Domains
                       └─→ EDR Hashes
    ↓
[Reporting Module] ──→ HTML Report
                    ├─→ CSV Export
                    └─→ JSON Export
```

**Modular Design:**
- Each component has single responsibility
- Database abstraction prevents tight coupling
- Easy to extend with new feed types or correlation strategies

---

## 📈 Features Deep Dive

### IOC Parsing & Validation
- Regex-based pattern matching for each IOC type
- IP validation via `ipaddress` library
- Hash format validation via `hashlib`
- Automatic normalization (lowercase domains, trim whitespace)

### Correlation Engine
Aggregates IOCs across feeds and computes:
- **Frequency**: How many feeds contain each IOC
- **Severity**: Risk level (currently MEDIUM, extensible)
- **Risk Score**: Base score 50, adjustable by correlation logic

### Blocklist Generation
Produces three distinct enforcement lists:
- **Firewall IPs**: Plain-text IPs for firewall IP sets
- **Web Filter Domains**: URLs for DNS/web filters
- **EDR Hashes**: File hashes for endpoint detection/response

### Reporting
- **HTML**: Interactive table with IOC details, type, source, severity, timestamp
- **CSV**: Machine-readable for SIEM ingest and further analysis
- **JSON**: Programmatic integration with other tools

---

## 🛡️ Real-World Use Cases

### Use Case 1: Rapid Incident Response
```bash
# New malware outbreak detected
python main.py --full-workflow

# Instantly get:
# ✓ Unified IOC database
# ✓ Blocklists for immediate deployment
# ✓ HTML report for analyst review
# ✓ CSV for SIEM ingestion
```

### Use Case 2: Continuous Monitoring
```bash
# Extend sample_feeds/ with live OSINT sources
# Run on schedule (cron/Windows Task Scheduler)
# Auto-deploy blocklists to security controls
```

### Use Case 3: Threat Intelligence Research
```bash
# Export JSON dataset for further analysis
# Track IOC frequency over time
# Correlate with external reputation sources
```

---

## 📊 Sample Output

### HTML Threat Report
```
Threat Intelligence Report
Generated: 2025-12-16 22:37:05
Total IOCs: 21

IOC Summary Table:
┌─────────────────────────┬────────┬──────────────────┬──────────┐
│ IOC Value               │ Type   │ Source           │ Severity │
├─────────────────────────┼────────┼──────────────────┼──────────┤
│ 192.168.1.100          │ ipv4   │ MalwareIPs Feed  │ MEDIUM   │
│ malware.example.com    │ domain │ Domains Feed     │ MEDIUM   │
│ http://malware...      │ url    │ URLBlacklist     │ MEDIUM   │
│ d41d8cd98f00b2...      │ hash   │ FileHashBlacklist│ MEDIUM   │
└─────────────────────────┴────────┴──────────────────┴──────────┘
```

### Blocklists
```
# firewall_ips.txt
192.168.1.100
10.0.0.50
172.16.0.25

# web_filter_domains.txt
malware.example.com
phishing.test.org
botnet.evil.net

# edr_hashes.txt
d41d8cd98f00b204e9800998ecf8427e
5d41402abc4b2a76b9719d911017c592
```

---

## 🔍 Database Schema

```sql
CREATE TABLE iocs (
    id INTEGER PRIMARY KEY,
    ioc_value TEXT NOT NULL,       -- IP, domain, URL, hash, or email
    ioc_type TEXT NOT NULL,        -- ipv4, domain, url, hash, email
    source TEXT,                   -- Feed source name
    severity TEXT DEFAULT 'MEDIUM', -- CRITICAL, HIGH, MEDIUM, LOW
    frequency INTEGER DEFAULT 1,   -- Occurrence count
    risk_score INTEGER DEFAULT 50, -- 0-100
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

---

## 📝 Learning Outcomes

This project demonstrates mastery of:

- **Threat Intelligence**: IOC formats, validation, normalization
- **Data Pipeline**: Multi-source ingestion, transformation, enrichment
- **Database Design**: SQLite schema, normalization, query optimization
- **Blue Team Automation**: Blocklists, reporting, SOC workflows
- **Python Best Practices**: Modular design, logging, error handling

---

## 🚧 Future Enhancements

- [ ] Live OSINT feed integration (AbuseIPDB, URLhaus, etc.)
- [ ] STIX/TAXII support for standardized threat data
- [ ] Dynamic risk scoring based on external reputation sources
- [ ] Geolocation enrichment for IOCs
- [ ] Real-time stream processing (Kafka/Redis)
- [ ] REST API for SOC platform integration
- [ ] Web dashboard for visualization
- [ ] YARA rule generation from file hashes

---

## 🤝 Contributing

Contributions are welcome! To contribute:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**Aswin Suresh**  
Cybersecurity Intern @ Unified Mentor  
[![GitHub](https://img.shields.io/badge/GitHub-aswinsuresh487-181717?logo=github)](https://github.com/aswinsuresh487) | [![LinkedIn](https://img.shields.io/badge/LinkedIn-aswin--suresh487-0A66C2?logo=linkedin)](https://www.linkedin.com/in/aswin-suresh487/)

---

## 🙏 Acknowledgments

- **Unified Mentor** for the mentorship and project opportunity
- **NIST** for threat intelligence best practices (SP 800-150)
- **MISP Project** for threat intelligence frameworks
- **OffSec** community for security research resources

---

## 📚 References

- NIST Cybersecurity Framework (CSF)
- MITRE ATT&CK Framework
- OWASP Top 10
- Python 3.13 Documentation
- SQLite Best Practices

---

**Last Updated**: December 17, 2025  
**Version**: 1.0.0 Production Ready  
**Questions?** Open an issue or reach out!
