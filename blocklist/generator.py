"""
Blocklist Generator - Generates blocklists from IOCs
"""
import logging
from pathlib import Path
from config import OUTPUT_DIR

logger = logging.getLogger(__name__)

class BlocklistGenerator:
    def __init__(self):
        self.output_dir = OUTPUT_DIR / 'blocklists'
        self.output_dir.mkdir(exist_ok=True)
    
    def generate_firewall_blocklist(self, iocs: list) -> str:
        """Generate firewall IP blocklist"""
        try:
            ip_iocs = [ioc for ioc in iocs if ioc.get('ioc_type') in ['ipv4', 'ipv6']]
            
            output_file = self.output_dir / 'firewall_ips.txt'
            with open(output_file, 'w') as f:
                f.write('# Firewall IP Blocklist\n')
                f.write(f'# Total IPs: {len(ip_iocs)}\n\n')
                for ioc in ip_iocs:
                    f.write(f"{ioc['ioc_value']}\n")
            
            logger.info(f"Generated firewall blocklist: {output_file}")
            return str(output_file)
        except Exception as e:
            logger.error(f"Error generating firewall blocklist: {e}")
            return ""
    
    def generate_domain_blocklist(self, iocs: list) -> str:
        """Generate domain/URL blocklist"""
        try:
            domain_iocs = [ioc for ioc in iocs if ioc.get('ioc_type') in ['domain', 'url']]
            
            output_file = self.output_dir / 'web_filter_domains.txt'
            with open(output_file, 'w') as f:
                f.write('# Web Filter Domain Blocklist\n')
                f.write(f'# Total Domains: {len(domain_iocs)}\n\n')
                for ioc in domain_iocs:
                    f.write(f"{ioc['ioc_value']}\n")
            
            logger.info(f"Generated domain blocklist: {output_file}")
            return str(output_file)
        except Exception as e:
            logger.error(f"Error generating domain blocklist: {e}")
            return ""
    
    def generate_hash_blocklist(self, iocs: list) -> str:
        """Generate file hash blocklist"""
        try:
            hash_iocs = [ioc for ioc in iocs if ioc.get('ioc_type') == 'hash']
            
            output_file = self.output_dir / 'edr_hashes.txt'
            with open(output_file, 'w') as f:
                f.write('# EDR/AV Hash Blocklist\n')
                f.write(f'# Total Hashes: {len(hash_iocs)}\n\n')
                for ioc in hash_iocs:
                    f.write(f"{ioc['ioc_value']}\n")
            
            logger.info(f"Generated hash blocklist: {output_file}")
            return str(output_file)
        except Exception as e:
            logger.error(f"Error generating hash blocklist: {e}")
            return ""
    
    def generate_all(self, iocs: list) -> dict:
        """Generate all blocklists"""
        return {
            'firewall': self.generate_firewall_blocklist(iocs),
            'domain': self.generate_domain_blocklist(iocs),
            'hash': self.generate_hash_blocklist(iocs),
        }

