# config.py should contain:
import os
from pathlib import Path

# Project paths
PROJECT_ROOT = Path(__file__).parent
DATABASE_PATH = PROJECT_ROOT / 'database' / 'threat_intelligence.db'
OUTPUT_DIR = PROJECT_ROOT / 'output'
LOGS_DIR = PROJECT_ROOT / 'logs'

# Create directories if not exist
OUTPUT_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)
(OUTPUT_DIR / 'blocklists').mkdir(exist_ok=True)
(OUTPUT_DIR / 'reports').mkdir(exist_ok=True)
(OUTPUT_DIR / 'datasets').mkdir(exist_ok=True)

# Logging config
LOG_FILE = LOGS_DIR / 'app.log'
LOG_LEVEL = 'INFO'

# Database config
DB_TIMEOUT = 30
DB_CHECK_SAME_THREAD = False

# IOC Types
IOC_TYPES = {
    'ipv4': r'^(\d{1,3}\.){3}\d{1,3}$',
    'ipv6': r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$',
    'domain': r'^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?(\.[a-zA-Z]{2,})+$',
    'url': r'^https?://',
    'email': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
    'hash_md5': r'^[a-f0-9]{32}$',
    'hash_sha1': r'^[a-f0-9]{40}$',
    'hash_sha256': r'^[a-f0-9]{64}$',
}

# Risk levels
RISK_LEVELS = {
    'CRITICAL': 4,
    'HIGH': 3,
    'MEDIUM': 2,
    'LOW': 1,
}
