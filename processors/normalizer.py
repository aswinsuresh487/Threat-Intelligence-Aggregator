"""
IOC Normalizer - Standardizes IOC data format
"""
import logging

logger = logging.getLogger(__name__)

class IOCNormalizer:
    @staticmethod
    def normalize_ioc(value: str, ioc_type: str) -> str:
        """Normalize IOC to standard format"""
        value = value.strip()
        
        if ioc_type in ['ipv4', 'ipv6', 'hash']:
            return value.lower()
        elif ioc_type in ['domain', 'email']:
            return value.lower()
        elif ioc_type == 'url':
            return value.lower()
        
        return value
    
    @staticmethod
    def extract_domain_from_url(url: str) -> str:
        """Extract domain from URL"""
        try:
            url = url.replace('http://', '').replace('https://', '')
            domain = url.split('/')[0]
            return domain
        except Exception as e:
            logger.error(f"Error extracting domain: {e}")
            return url
    
    @staticmethod
    def normalize_severity(raw_severity: str) -> str:
        """Normalize severity level"""
        severity_map = {
            'critical': 'CRITICAL',
            'high': 'HIGH',
            'medium': 'MEDIUM',
            'low': 'LOW',
            'info': 'LOW',
            'unknown': 'MEDIUM'
        }
        return severity_map.get(raw_severity.lower(), 'MEDIUM')
