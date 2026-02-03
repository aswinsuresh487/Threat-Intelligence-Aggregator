"""
IOC Enricher - Adds metadata and context to IOCs
"""
import logging

logger = logging.getLogger(__name__)

class IOCEnricher:
    @staticmethod
    def enrich_ioc(ioc_value: str, ioc_type: str) -> dict:
        """Enrich IOC with metadata"""
        enriched = {
            'ioc_value': ioc_value,
            'ioc_type': ioc_type,
            'metadata': {
                'length': len(ioc_value),
                'source_type': 'feed',
                'enriched_at': None,
            }
        }
        
        # Type-specific enrichment
        if ioc_type == 'ipv4':
            enriched['metadata']['ip_version'] = 4
            enriched['metadata']['is_private'] = IOCEnricher.is_private_ip(ioc_value)
        elif ioc_type == 'ipv6':
            enriched['metadata']['ip_version'] = 6
        elif ioc_type == 'hash':
            enriched['metadata']['hash_length'] = len(ioc_value)
        
        return enriched
    
    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """Check if IP is private range"""
        private_ranges = [
            ('10.0.0.0', '10.255.255.255'),
            ('172.16.0.0', '172.31.255.255'),
            ('192.168.0.0', '192.168.255.255'),
            ('127.0.0.0', '127.255.255.255'),
        ]
        
        parts = list(map(int, ip.split('.')))
        ip_int = (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
        
        for start_ip, end_ip in private_ranges:
            start_parts = list(map(int, start_ip.split('.')))
            end_parts = list(map(int, end_ip.split('.')))
            
            start_int = (start_parts[0] << 24) + (start_parts[1] << 16) + (start_parts[2] << 8) + start_parts[3]
            end_int = (end_parts[0] << 24) + (end_parts[1] << 16) + (end_parts[2] << 8) + end_parts[3]
            
            if start_int <= ip_int <= end_int:
                return True
        
        return False
