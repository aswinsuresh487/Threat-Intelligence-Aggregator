"""
IOC Validator - Validates and detects IOC types
"""
import re
import logging

logger = logging.getLogger(__name__)

class IOCValidator:
    @staticmethod
    def validate_ipv4(ip: str) -> bool:
        """Validate IPv4 address"""
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(pattern, ip):
            return False
        parts = ip.split('.')
        return all(0 <= int(p) <= 255 for p in parts)
    
    @staticmethod
    def validate_ipv6(ip: str) -> bool:
        """Validate IPv6 address"""
        pattern = r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
        return bool(re.match(pattern, ip))
    
    @staticmethod
    def validate_domain(domain: str) -> bool:
        """Validate domain name"""
        pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?(\.[a-zA-Z]{2,})+$'
        return bool(re.match(pattern, domain))
    
    @staticmethod
    def validate_url(url: str) -> bool:
        """Validate URL"""
        pattern = r'^https?://'
        return bool(re.match(pattern, url))
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email address"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    @staticmethod
    def validate_hash(hash_value: str) -> bool:
        """Validate hash (MD5, SHA1, SHA256)"""
        patterns = {
            'MD5': r'^[a-f0-9]{32}$',
            'SHA1': r'^[a-f0-9]{40}$',
            'SHA256': r'^[a-f0-9]{64}$'
        }
        for hash_type, pattern in patterns.items():
            if re.match(pattern, hash_value.lower()):
                return True
        return False
    
    @staticmethod
    def detect_ioc_type(value: str) -> str:
        """Auto-detect IOC type"""
        value = value.strip().lower()
        
        if IOCValidator.validate_ipv4(value):
            return 'ipv4'
        elif IOCValidator.validate_ipv6(value):
            return 'ipv6'
        elif IOCValidator.validate_domain(value):
            return 'domain'
        elif IOCValidator.validate_url(value):
            return 'url'
        elif IOCValidator.validate_email(value):
            return 'email'
        elif IOCValidator.validate_hash(value):
            return 'hash'
        else:
            return 'unknown'
    
    @staticmethod
    def validate_ioc(value: str, ioc_type: str = None) -> bool:
        """Validate IOC by type"""
        if not ioc_type:
            ioc_type = IOCValidator.detect_ioc_type(value)
        
        validators = {
            'ipv4': IOCValidator.validate_ipv4,
            'ipv6': IOCValidator.validate_ipv6,
            'domain': IOCValidator.validate_domain,
            'url': IOCValidator.validate_url,
            'email': IOCValidator.validate_email,
            'hash': IOCValidator.validate_hash,
        }
        
        validator = validators.get(ioc_type)
        return validator(value) if validator else False
