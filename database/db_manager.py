"""
Database Manager - SQLite operations for threat intelligence data
"""
import sqlite3
import logging
from pathlib import Path
from datetime import datetime
from config import DATABASE_PATH, LOG_FILE

logger = logging.getLogger(__name__)

class ThreatIntelligenceDB:
    def __init__(self):
        self.db_path = DATABASE_PATH
        self.connection = None
        self.cursor = None
        self.init_db()
    
    def init_db(self):
        """Initialize database with schema"""
        try:
            self.connection = sqlite3.connect(self.db_path)
            self.cursor = self.connection.cursor()
            
            # Create tables
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS iocs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ioc_value TEXT UNIQUE NOT NULL,
                    ioc_type TEXT NOT NULL,
                    source TEXT,
                    severity TEXT DEFAULT 'MEDIUM',
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    frequency INTEGER DEFAULT 1
                )
            ''')
            
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS ioc_feeds (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ioc_id INTEGER NOT NULL,
                    feed_name TEXT NOT NULL,
                    feed_date TIMESTAMP,
                    FOREIGN KEY (ioc_id) REFERENCES iocs(id)
                )
            ''')
            
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS correlations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ioc_id INTEGER NOT NULL,
                    feed_count INTEGER DEFAULT 1,
                    risk_score REAL DEFAULT 0.0,
                    FOREIGN KEY (ioc_id) REFERENCES iocs(id)
                )
            ''')
            
            self.connection.commit()
            logger.info(f"Database initialized: {self.db_path}")
        except Exception as e:
            logger.error(f"Database init error: {e}")
            raise
    
    def add_ioc(self, ioc_value: str, ioc_type: str, source: str, severity: str = 'MEDIUM'):
        """Add IOC to database"""
        try:
            self.cursor.execute('''
                INSERT OR IGNORE INTO iocs (ioc_value, ioc_type, source, severity)
                VALUES (?, ?, ?, ?)
            ''', (ioc_value, ioc_type, source, severity))
            self.connection.commit()
            return self.cursor.lastrowid
        except Exception as e:
            logger.error(f"Error adding IOC: {e}")
            return None
    
    def get_all_iocs(self):
        """Get all IOCs"""
        try:
            self.cursor.execute('SELECT * FROM iocs')
            return self.cursor.fetchall()
        except Exception as e:
            logger.error(f"Error fetching IOCs: {e}")
            return []
    
    def get_ioc_count(self):
        """Get total IOC count"""
        try:
            self.cursor.execute('SELECT COUNT(*) FROM iocs')
            return self.cursor.fetchone()[0]
        except Exception as e:
            logger.error(f"Error getting count: {e}")
            return 0
    
    def close(self):
        """Close database connection"""
        if self.connection:
            self.connection.close()
