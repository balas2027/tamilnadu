"""
Forensic Report Generator.

Compiles all findings from TOR circuit analysis into
exportable forensic reports in JSON and CSV formats.

Required fields per Hackathon specification:
- Probable Origin IP
- Full Circuit Path (Entry, Middle, Exit)
- Activity/Purpose
- Local Entry Timestamp
- Composite Confidence Score
- Log Reference Pointer
"""

import csv
import json
import time
import os
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional
from datetime import datetime


@dataclass
class ForensicFinding:
    """
    A single forensic finding for a TOR circuit trace.
    
    Contains all required fields for hackathon specification.
    """
    # Identification
    finding_id: str
    analysis_timestamp: str
    
    # Origin Tracing
    probable_origin_ip: str
    origin_confidence: float
    
    # Circuit Path
    entry_guard_ip: str
    entry_guard_nickname: str
    entry_guard_port: int
    middle_relay_ip: str
    middle_relay_nickname: str
    exit_node_ip: str
    exit_node_nickname: str
    
    # Activity
    activity_purpose: str
    circuit_id: str
    
    # Timing
    local_entry_timestamp: float
    local_entry_formatted: str
    
    # Confidence Scoring
    composite_confidence_score: float
    identity_score: float
    fingerprint_score: float
    pattern_score: float
    
    # Log Reference
    log_reference_pointer: str
    
    # Metadata
    analyst_notes: str = ""
    classification: str = "TOR_TRAFFIC"


class ForensicReportGenerator:
    """
    Generates forensic reports from TOR circuit analysis.
    
    Supports:
    - JSON export (detailed)
    - CSV export (tabular)
    - Summary report
    """
    
    def __init__(self, output_dir: str = "./reports"):
        """
        Initialize report generator.
        
        Args:
            output_dir: Directory for saved reports
        """
        self.output_dir = output_dir
        self._findings: List[ForensicFinding] = []
        self._report_metadata: Dict = {}
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
    
    def create_finding(self, 
                       flow_data: Dict,
                       finding_id: str = None) -> ForensicFinding:
        """
        Create a ForensicFinding from analyzed flow data.
        
        Args:
            flow_data: Dictionary with flow analysis results
            finding_id: Optional custom ID
            
        Returns:
            ForensicFinding object
        """
        if finding_id is None:
            finding_id = f"TOR-{int(time.time())}-{len(self._findings) + 1:03d}"
        
        local_entry = flow_data.get('local_entry_time', 0)
        
        finding = ForensicFinding(
            finding_id=finding_id,
            analysis_timestamp=datetime.now().isoformat(),
            
            # Origin
            probable_origin_ip=flow_data.get('probable_origin_ip', 'Unknown'),
            origin_confidence=flow_data.get('origin_confidence', 0.0),
            
            # Circuit Path
            entry_guard_ip=flow_data.get('entry_guard_ip', ''),
            entry_guard_nickname=flow_data.get('entry_guard_nickname', ''),
            entry_guard_port=flow_data.get('entry_guard_port', 0),
            middle_relay_ip=flow_data.get('middle_relay_ip', ''),
            middle_relay_nickname=flow_data.get('middle_relay_nickname', ''),
            exit_node_ip=flow_data.get('exit_node_ip', ''),
            exit_node_nickname=flow_data.get('exit_node_nickname', ''),
            
            # Activity
            activity_purpose=flow_data.get('purpose', 'GENERAL'),
            circuit_id=flow_data.get('circuit_id', ''),
            
            # Timing
            local_entry_timestamp=local_entry,
            local_entry_formatted=time.strftime('%Y-%m-%d %H:%M:%S', 
                                                 time.localtime(local_entry)) if local_entry else 'N/A',
            
            # Scoring
            composite_confidence_score=flow_data.get('composite_confidence_score', 0.0),
            identity_score=flow_data.get('identity_score', 0.0),
            fingerprint_score=flow_data.get('fingerprint_score', 0.0),
            pattern_score=flow_data.get('pattern_score', 0.0),
            
            # Log Reference
            log_reference_pointer=flow_data.get('log_reference', ''),
            
            # Metadata
            analyst_notes=flow_data.get('notes', ''),
            classification=flow_data.get('classification', 'TOR_TRAFFIC')
        )
        
        self._findings.append(finding)
        return finding
    
    def add_finding(self, finding: ForensicFinding):
        """Add an existing finding to the report."""
        self._findings.append(finding)
    
    def set_metadata(self, 
                     case_id: str = "",
                     analyst: str = "",
                     description: str = "",
                     custom_fields: Dict = None):
        """
        Set report metadata.
        
        Args:
            case_id: Case/investigation identifier
            analyst: Analyst name/ID
            description: Case description
            custom_fields: Additional metadata
        """
        self._report_metadata = {
            'case_id': case_id,
            'analyst': analyst,
            'description': description,
            'generated_at': datetime.now().isoformat(),
            'tool_version': 'TOR-Forensics-v1.0',
            **(custom_fields or {})
        }
    
    def generate_json_report(self, filename: str = None) -> str:
        """
        Generate JSON format forensic report.
        
        Args:
            filename: Optional filename (auto-generated if not provided)
            
        Returns:
            JSON string of the report
        """
        if filename is None:
            filename = f"forensic_report_{int(time.time())}.json"
        
        report = {
            'report_metadata': self._report_metadata,
            'summary': {
                'total_findings': len(self._findings),
                'high_confidence_count': sum(1 for f in self._findings if f.composite_confidence_score >= 0.7),
                'medium_confidence_count': sum(1 for f in self._findings if 0.4 <= f.composite_confidence_score < 0.7),
                'low_confidence_count': sum(1 for f in self._findings if f.composite_confidence_score < 0.4),
                'unique_origin_ips': list(set(f.probable_origin_ip for f in self._findings if f.probable_origin_ip)),
                'unique_entry_guards': list(set(f.entry_guard_ip for f in self._findings if f.entry_guard_ip))
            },
            'findings': [asdict(f) for f in self._findings]
        }
        
        json_str = json.dumps(report, indent=2, default=str)
        
        # Save to file
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, 'w') as f:
            f.write(json_str)
        
        return json_str
    
    def generate_csv_report(self, filename: str = None) -> str:
        """
        Generate CSV format forensic report.
        
        Args:
            filename: Optional filename
            
        Returns:
            Path to generated CSV file
        """
        if filename is None:
            filename = f"forensic_report_{int(time.time())}.csv"
        
        filepath = os.path.join(self.output_dir, filename)
        
        # Define CSV columns (subset of key fields)
        columns = [
            'finding_id',
            'analysis_timestamp',
            'probable_origin_ip',
            'origin_confidence',
            'entry_guard_ip',
            'entry_guard_nickname',
            'middle_relay_ip',
            'middle_relay_nickname',
            'exit_node_ip',
            'exit_node_nickname',
            'activity_purpose',
            'circuit_id',
            'local_entry_formatted',
            'composite_confidence_score',
            'identity_score',
            'fingerprint_score',
            'pattern_score',
            'log_reference_pointer',
            'classification'
        ]
        
        with open(filepath, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=columns, extrasaction='ignore')
            writer.writeheader()
            
            for finding in self._findings:
                writer.writerow(asdict(finding))
        
        return filepath
    
    def generate_summary(self) -> Dict:
        """
        Generate a summary of all findings.
        
        Returns:
            Summary dictionary
        """
        if not self._findings:
            return {'count': 0, 'message': 'No findings'}
        
        ccs_scores = [f.composite_confidence_score for f in self._findings]
        origin_ips = [f.probable_origin_ip for f in self._findings if f.probable_origin_ip]
        entry_guards = [f.entry_guard_nickname for f in self._findings if f.entry_guard_nickname]
        
        from collections import Counter
        
        return {
            'total_findings': len(self._findings),
            'average_confidence': sum(ccs_scores) / len(ccs_scores),
            'max_confidence': max(ccs_scores),
            'min_confidence': min(ccs_scores),
            'unique_origins': len(set(origin_ips)),
            'most_common_origin': Counter(origin_ips).most_common(1)[0] if origin_ips else None,
            'unique_entry_guards': len(set(entry_guards)),
            'most_common_guard': Counter(entry_guards).most_common(1)[0] if entry_guards else None,
            'purposes': list(set(f.activity_purpose for f in self._findings))
        }
    
    def get_findings(self) -> List[ForensicFinding]:
        """Get all findings."""
        return self._findings.copy()
    
    def clear_findings(self):
        """Clear all findings."""
        self._findings.clear()
    
    def export_single_finding_json(self, finding: ForensicFinding) -> str:
        """
        Export a single finding as JSON string.
        
        Args:
            finding: ForensicFinding to export
            
        Returns:
            JSON string
        """
        return json.dumps(asdict(finding), indent=2, default=str)


# Convenience functions for quick export

def generate_quick_report(flow_data: Dict, output_dir: str = "./reports") -> Dict:
    """
    Generate a quick forensic report from a single flow.
    
    Args:
        flow_data: Flow analysis data
        output_dir: Output directory for report files
        
    Returns:
        Dict with JSON content and file paths
    """
    generator = ForensicReportGenerator(output_dir)
    generator.set_metadata(
        case_id=f"QUICK-{int(time.time())}",
        analyst="Automated Analysis",
        description="Single flow forensic trace"
    )
    
    finding = generator.create_finding(flow_data)
    
    json_content = generator.generate_json_report()
    csv_path = generator.generate_csv_report()
    
    return {
        'finding': asdict(finding),
        'json_report': json_content,
        'csv_path': csv_path,
        'summary': generator.generate_summary()
    }


def format_finding_for_display(finding: ForensicFinding) -> str:
    """
    Format a finding for dashboard display.
    
    Args:
        finding: ForensicFinding to format
        
    Returns:
        Formatted string for display
    """
    return f"""
╔══════════════════════════════════════════════════════════════════╗
║                    FORENSIC TRACE REPORT                         ║
╠══════════════════════════════════════════════════════════════════╣
║  Finding ID:     {finding.finding_id:<45} ║
║  Analysis Time:  {finding.analysis_timestamp:<45} ║
╠══════════════════════════════════════════════════════════════════╣
║  PROBABLE ORIGIN IP:  {finding.probable_origin_ip:<40} ║
║  Origin Confidence:   {finding.origin_confidence:.1%:<40} ║
╠══════════════════════════════════════════════════════════════════╣
║  CIRCUIT PATH:                                                    ║
║    🛡️ Entry Guard:  {finding.entry_guard_nickname:<20} ({finding.entry_guard_ip}) ║
║    🔗 Middle Relay: {finding.middle_relay_nickname:<20} ({finding.middle_relay_ip}) ║
║    🚪 Exit Node:    {finding.exit_node_nickname:<20} ({finding.exit_node_ip}) ║
╠══════════════════════════════════════════════════════════════════╣
║  Purpose/Activity: {finding.activity_purpose:<44} ║
║  Local Entry Time: {finding.local_entry_formatted:<44} ║
╠══════════════════════════════════════════════════════════════════╣
║  COMPOSITE CONFIDENCE SCORE:  {finding.composite_confidence_score:.4f}                       ║
║    - Identity Score:      {finding.identity_score:.4f}                           ║
║    - Fingerprint Score:   {finding.fingerprint_score:.4f}                           ║
║    - Pattern Score:       {finding.pattern_score:.4f}                           ║
╠══════════════════════════════════════════════════════════════════╣
║  Log Reference: {finding.log_reference_pointer:<48} ║
╚══════════════════════════════════════════════════════════════════╝
"""
