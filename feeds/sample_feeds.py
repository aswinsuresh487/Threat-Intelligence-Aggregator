"""
Sample Threat Feeds - Mock data for testing
"""

SAMPLE_FEEDS = {
    'malicious_ips': {
        'source': 'MalwareIPs Feed',
        'type': 'ipv4',
        'data': [
            '192.168.1.100',
            '10.0.0.50',
            '172.16.0.25',
            '8.8.8.8',
            '1.1.1.1',
        ]
    },
    'malicious_domains': {
        'source': 'MaliciousDomains Feed',
        'type': 'domain',
        'data': [
            'malware.example.com',
            'phishing.test.org',
            'botnet.evil.net',
            'c2-server.bad.com',
            'steal-data.malicious.io',
        ]
    },
    'malicious_urls': {
        'source': 'URLBlacklist Feed',
        'type': 'url',
        'data': [
            'http://malware.example.com/payload',
            'https://phishing.test.org/login',
            'http://botnet.evil.net/command',
            'https://c2-server.bad.com/beacon',
            'http://steal-data.malicious.io/exfil',
        ]
    },
    'malicious_hashes': {
        'source': 'FileHashBlacklist',
        'type': 'hash',
        'data': [
            'd41d8cd98f00b204e9800998ecf8427e',
            '5d41402abc4b2a76b9719d911017c592',
            '356a192b7913b04c54574d18c28d46e6395428ab',
        ]
    },
    'phishing_emails': {
        'source': 'EmailThreatFeed',
        'type': 'email',
        'data': [
            'attacker@malware.com',
            'phisher@evil.org',
            'spam@botnet.net',
        ]
    },
}

def get_sample_feed(feed_name: str) -> dict:
    """Get a sample feed by name"""
    return SAMPLE_FEEDS.get(feed_name, {})

def get_all_feeds() -> dict:
    """Get all sample feeds"""
    return SAMPLE_FEEDS

def get_total_iocs() -> int:
    """Get total IOCs in all feeds"""
    total = 0
    for feed in SAMPLE_FEEDS.values():
        total += len(feed.get('data', []))
    return total
