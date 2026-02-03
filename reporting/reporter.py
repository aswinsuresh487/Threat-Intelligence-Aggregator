import json
from datetime import datetime
from pathlib import Path

class ThreatReporter:
    def __init__(self, db_manager):
        self.db = db_manager
        self.output_dir = Path("output")
        
    def generate_report(self):
        """Generate HTML threat report with actual IOC data"""
        iocs = self.db.get_all_iocs()
        
        table_rows = ""
        for ioc in iocs:
            # ioc is a tuple: (id, ioc_value, ioc_type, source, severity, frequency, risk_score)
            ioc_value = ioc[1]
            ioc_type = ioc[2]
            source = ioc[3]
            severity = ioc[4]
            frequency = ioc[5]
            
            severity_class = severity.lower()
            table_rows += f"""        <tr>
            <td>{ioc_value}</td>
            <td>{ioc_type}</td>
            <td>{source}</td>
            <td><span class="{severity_class}">{severity}</span></td>
            <td>{frequency}</td>
        </tr>
"""
        
        html_content = f"""<html>
<head>
    <title>Threat Intelligence Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th {{ background-color: #4CAF50; color: white; padding: 12px; text-align: left; }}
        td {{ border: 1px solid #ddd; padding: 12px; }}
        tr:nth-child(even) {{ background-color: #f2f2f2; }}
        .critical {{ color: red; font-weight: bold; }}
        .high {{ color: orange; font-weight: bold; }}
        .medium {{ color: #ff9800; }}
        .low {{ color: green; }}
    </style>
</head>
<body>
    <h1>Threat Intelligence Report</h1>
    <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <p>Total IOCs: {len(iocs)}</p>
    
    <h2>IOC Summary</h2>
    <table>
        <tr>
            <th>IOC Value</th>
            <th>Type</th>
            <th>Source</th>
            <th>Severity</th>
            <th>Frequency</th>
        </tr>
{table_rows}
    </table>
</body>
</html>"""
        
        report_path = self.output_dir / 'reports' / 'threat_report.html'
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(html_content)
        print(f"Generated HTML report: {report_path}")
        
    def export_csv(self):
        """Export IOCs to CSV"""
        iocs = self.db.get_all_iocs()
        
        csv_path = self.output_dir / 'datasets' / 'iocs_export.csv'
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(csv_path, 'w') as f:
            f.write("IOC Value,Type,Source,Severity,Frequency,Score\n")
            for ioc in iocs:
                # ioc: (id, ioc_value, ioc_type, source, severity, frequency, risk_score)
                f.write(f"{ioc[1]},{ioc[2]},{ioc[3]},{ioc[4]},{ioc[5]},{ioc[6]}\n")
        
        print(f"Exported CSV: {csv_path}")
        
    def export_json(self):
        """Export IOCs to JSON"""
        iocs = self.db.get_all_iocs()
        
        json_data = {
            "generated": datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3],
            "total_iocs": len(iocs),
            "iocs": [
                {
                    "value": ioc[1],
                    "type": ioc[2],
                    "source": ioc[3],
                    "severity": ioc[4],
                    "frequency": ioc[5],
                    "risk_score": ioc[6]
                }
                for ioc in iocs
            ],
            "correlations": {}
        }
        
        json_path = self.output_dir / 'datasets' / 'iocs_export.json'
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(json_data, indent=2))
        
        print(f"Exported JSON: {json_path}")
        
    def generate_reports(self):
        """Generate all reports"""
        print("\n=== GENERATING REPORTS ===")
        self.generate_report()
        self.export_csv()
        self.export_json()
        print("Reports generated successfully!")
