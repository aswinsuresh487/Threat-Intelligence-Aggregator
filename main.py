#!/usr/bin/env python3
"""
Threat Intelligence Aggregator - Main Application
Collects, parses, validates, correlates and reports on threat IOCs
"""
import argparse
import logging
import sys
from pathlib import Path

from config import LOG_FILE, LOGS_DIR
from database.db_manager import ThreatIntelligenceDB
from processors.validator import IOCValidator
from processors.normalizer import IOCNormalizer
from processors.enricher import IOCEnricher
from correlation.engine import CorrelationEngine
from blocklist.generator import BlocklistGenerator
from reporting.reporter import ThreatReporter
from feeds.sample_feeds import get_all_feeds, get_total_iocs
from parsers.feed_parser import FeedParser

# Setup logging
LOGS_DIR.mkdir(exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class ThreatIntelligenceAggregator:
    def __init__(self):
        self.db = ThreatIntelligenceDB()
        self.validator = IOCValidator()
        self.normalizer = IOCNormalizer()
        self.enricher = IOCEnricher()
        self.correlation_engine = CorrelationEngine()
        self.blocklist_gen = BlocklistGenerator()
        self.reporter = ThreatReporter(self.db)
        self.iocs = []
    
    def process_sample_feeds(self):
        """Process sample threat feeds"""
        logger.info("Processing sample threat feeds...")
        feeds = get_all_feeds()
        
        for feed_name, feed_data in feeds.items():
            logger.info(f"Processing feed: {feed_name}")
            source = feed_data.get('source', 'unknown')
            ioc_type = feed_data.get('type', 'unknown')
            
            for ioc_value in feed_data.get('data', []):
                # Validate
                if self.validator.validate_ioc(ioc_value, ioc_type):
                    # Normalize
                    normalized = self.normalizer.normalize_ioc(ioc_value, ioc_type)
                    
                    # Enrich
                    enriched = self.enricher.enrich_ioc(normalized, ioc_type)
                    
                    # Store
                    ioc_entry = {
                        'ioc_value': normalized,
                        'ioc_type': ioc_type,
                        'source': source,
                        'severity': 'MEDIUM'
                    }
                    self.iocs.append(ioc_entry)
                    self.db.add_ioc(normalized, ioc_type, source, 'MEDIUM')
        
        logger.info(f"Processed {len(self.iocs)} IOCs from all feeds")
    
    def run_correlation(self):
        """Run correlation analysis"""
        logger.info("Running correlation analysis...")
        correlations = self.correlation_engine.correlate(self.iocs)
        logger.info(f"Found {len(correlations)} unique IOCs with correlations")
        return correlations
    
    def generate_blocklists(self):
        """Generate blocklists"""
        logger.info("Generating blocklists...")
        blocklists = self.blocklist_gen.generate_all(self.iocs)
        logger.info(f"Generated blocklists: {blocklists}")
        return blocklists
    
    def generate_reports(self):
        """Generate reports"""
        logger.info("Generating reports...")
        correlations = self.run_correlation()
        
        self.reporter.generate_reports()
    
    def print_stats(self):
        """Print statistics"""
        ioc_count = self.db.get_ioc_count()
        
        print("\n" + "="*50)
        print("THREAT INTELLIGENCE AGGREGATOR - STATISTICS")
        print("="*50)
        print(f"Total IOCs in Database: {ioc_count}")
        print(f"Sample IOCs Available: {get_total_iocs()}")
        print(f"Log File: {LOG_FILE}")
        print("="*50 + "\n")

def main():
    parser = argparse.ArgumentParser(
        description='Threat Intelligence Aggregator - Collect, parse, and correlate threat feeds'
    )
    parser.add_argument('--process-samples', action='store_true', 
                       help='Process sample threat feeds')
    parser.add_argument('--stats', action='store_true',
                       help='Show database statistics')
    parser.add_argument('--correlate', action='store_true',
                       help='Run correlation analysis')
    parser.add_argument('--blocklists', action='store_true',
                       help='Generate blocklists')
    parser.add_argument('--reports', action='store_true',
                       help='Generate reports')
    parser.add_argument('--full-workflow', action='store_true',
                       help='Execute full workflow (process, correlate, blocklists, reports)')
    
    args = parser.parse_args()
    
    agg = ThreatIntelligenceAggregator()
    
    try:
        if args.process_samples or args.full_workflow:
            agg.process_sample_feeds()
            print("✅ Sample feeds processed successfully!")
        
        if args.stats or args.full_workflow:
            agg.print_stats()
        
        if args.correlate or args.full_workflow:
            agg.run_correlation()
            print("✅ Correlation analysis complete!")
        
        if args.blocklists or args.full_workflow:
            agg.generate_blocklists()
            print("✅ Blocklists generated!")
        
        if args.reports or args.full_workflow:
            agg.generate_reports()
            print("✅ Reports generated!")
        
        if not any([args.process_samples, args.stats, args.correlate, 
                   args.blocklists, args.reports, args.full_workflow]):
            parser.print_help()
    
    except Exception as e:
        logger.error(f"Application error: {e}", exc_info=True)
        print(f"❌ Error: {e}")
        sys.exit(1)
    
    finally:
        agg.db.close()

if __name__ == '__main__':
    main()
