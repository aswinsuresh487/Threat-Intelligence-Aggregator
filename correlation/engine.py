"""
Correlation Engine - Correlates IOCs across feeds
"""
import logging
from collections import defaultdict

logger = logging.getLogger(__name__)

class CorrelationEngine:
    def __init__(self):
        self.ioc_feeds = defaultdict(list)
        self.ioc_scores = {}
    
    def correlate(self, iocs: list) -> dict:
        """Correlate IOCs across feeds"""
        self.ioc_feeds = defaultdict(list)
        
        # Group IOCs by value
        for ioc in iocs:
            value = ioc.get('ioc_value', '')
            source = ioc.get('source', 'unknown')
            self.ioc_feeds[value].append(source)
        
        # Calculate risk scores
        self.calculate_scores()
        return self.ioc_scores
    
    def calculate_scores(self):
        """Calculate risk scores based on frequency"""
        for ioc_value, feeds in self.ioc_feeds.items():
            frequency = len(feeds)
            
            # Risk scoring logic
            if frequency >= 3:
                severity = 'CRITICAL'
                score = 100
            elif frequency == 2:
                severity = 'HIGH'
                score = 75
            elif frequency == 1:
                severity = 'MEDIUM'
                score = 50
            else:
                severity = 'LOW'
                score = 25
            
            self.ioc_scores[ioc_value] = {
                'frequency': frequency,
                'severity': severity,
                'score': score,
                'feeds': feeds
            }
    
    def get_critical_iocs(self) -> list:
        """Get CRITICAL severity IOCs"""
        return [ioc for ioc, data in self.ioc_scores.items() 
                if data['severity'] == 'CRITICAL']
    
    def get_high_iocs(self) -> list:
        """Get HIGH severity IOCs"""
        return [ioc for ioc, data in self.ioc_scores.items() 
                if data['severity'] == 'HIGH']
