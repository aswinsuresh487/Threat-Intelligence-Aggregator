"""
Feed Parser - Parses threat feeds in multiple formats
"""
import json
import csv
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

class FeedParser:
    @staticmethod
    def parse_csv(file_path: str) -> list:
        """Parse CSV feed"""
        try:
            data = []
            with open(file_path, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    data.append(row)
            logger.info(f"Parsed CSV: {file_path} - {len(data)} records")
            return data
        except Exception as e:
            logger.error(f"Error parsing CSV: {e}")
            return []
    
    @staticmethod
    def parse_json(file_path: str) -> list:
        """Parse JSON feed"""
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            if isinstance(data, dict):
                data = [data]
            logger.info(f"Parsed JSON: {file_path} - {len(data)} records")
            return data
        except Exception as e:
            logger.error(f"Error parsing JSON: {e}")
            return []
    
    @staticmethod
    def parse_txt(file_path: str) -> list:
        """Parse TXT feed (one IOC per line)"""
        try:
            data = []
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        data.append({'value': line})
            logger.info(f"Parsed TXT: {file_path} - {len(data)} records")
            return data
        except Exception as e:
            logger.error(f"Error parsing TXT: {e}")
            return []
    
    @staticmethod
    def parse_feed(file_path: str) -> list:
        """Auto-detect format and parse"""
        path = Path(file_path)
        suffix = path.suffix.lower()
        
        if suffix == '.csv':
            return FeedParser.parse_csv(file_path)
        elif suffix == '.json':
            return FeedParser.parse_json(file_path)
        elif suffix == '.txt':
            return FeedParser.parse_txt(file_path)
        else:
            logger.warning(f"Unknown file format: {suffix}")
            return []
