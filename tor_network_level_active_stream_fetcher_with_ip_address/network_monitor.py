"""
Network-Wide TOR Monitor Module.

Main orchestrator that detects internal IPs using TOR across the network.
Combines all components: packet capture, flow tracking, ML classification, and CCS scoring.
"""

import time
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable, Tuple
from collections import defaultdict

from .relay_database import RelayDatabase, get_relay_database
from .global_listener import GlobalListener, PacketInfo
from .flow_tracker import FlowTracker, NetworkFlow
from .feature_extractor import FeatureExtractor
from .rf_classifier import TORRandomForestClassifier, get_classifier
from .ccs_calculator import CCSCalculator, CCSResult, get_ccs_calculator


@dataclass
class TORUserActivity:
    """
    Tracks TOR activity for an internal IP.
    """
    internal_ip: str
    first_seen: float
    last_seen: float
    
    # Flow statistics
    total_flows: int = 0
    total_packets: int = 0
    total_bytes: int = 0
    
    # TOR detection details
    highest_ccs_score: float = 0.0
    avg_ccs_score: float = 0.0
    entry_guards: List[str] = field(default_factory=list)
    relay_names: List[str] = field(default_factory=list)
    
    # Evidence collection
    all_evidence: List[str] = field(default_factory=list)
    
    # Active flows
    active_flow_count: int = 0
    
    def to_dict(self) -> Dict:
        return {
            'internal_ip': self.internal_ip,
            'first_seen': self.first_seen,
            'last_seen': self.last_seen,
            'duration': round(self.last_seen - self.first_seen, 2),
            'total_flows': self.total_flows,
            'total_packets': self.total_packets,
            'total_bytes': self.total_bytes,
            'highest_ccs_score': round(self.highest_ccs_score, 4),
            'avg_ccs_score': round(self.avg_ccs_score, 4),
            'entry_guards': self.entry_guards[:5],  # Top 5
            'relay_names': list(set(self.relay_names))[:5],
            'evidence_count': len(self.all_evidence),
            'active_flow_count': self.active_flow_count
        }


class NetworkWideMonitor:
    """
    Network-Wide TOR Traffic Monitor.
    
    Passively monitors all network traffic to detect internal IPs
    communicating with the TOR network.
    
    Features:
    - Real-time packet capture and flow tracking
    - Random Forest ML classification
    - CCS (Composite Confidence Score) calculation
    - Forensic report generation
    - Callback system for live updates
    """
    
    def __init__(self,
                 interface: Optional[str] = None,
                 ccs_threshold: float = 0.50):
        """
        Initialize Network-Wide Monitor.
        
        Args:
            interface: Network interface to capture on (None = default)
            ccs_threshold: Minimum CCS score to flag as TOR (0.0-1.0)
        """
        # Core components
        self.interface = interface
        self.ccs_threshold = ccs_threshold
        
        self.relay_db = get_relay_database()
        self.listener = GlobalListener(interface)
        self.flow_tracker = FlowTracker(
            flow_timeout=60.0,
            max_flows=5000,
            min_packets_for_analysis=5
        )
        self.classifier = get_classifier()
        self.ccs_calculator = get_ccs_calculator()
        self.feature_extractor = FeatureExtractor()
        
        # State tracking
        self._detected_users: Dict[str, TORUserActivity] = {}
        self._running = False
        self._start_time: float = 0
        self._flow_analysis_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        
        # Callbacks
        self._on_tor_detected_callbacks: List[Callable[[TORUserActivity], None]] = []
        self._on_flow_analyzed_callbacks: List[Callable[[NetworkFlow, CCSResult], None]] = []
        
        # Statistics
        self._stats = {
            'packets_processed': 0,
            'flows_analyzed': 0,
            'tor_flows_detected': 0,
            'internal_ips_detected': 0
        }
        
        # Register packet callback
        self.listener.on_packet(self._on_packet)
    
    def on_tor_detected(self, callback: Callable[[TORUserActivity], None]):
        """Register callback for when TOR user is detected."""
        self._on_tor_detected_callbacks.append(callback)
    
    def on_flow_analyzed(self, callback: Callable[[NetworkFlow, CCSResult], None]):
        """Register callback for when a flow is analyzed."""
        self._on_flow_analyzed_callbacks.append(callback)
    
    def _on_packet(self, packet: PacketInfo):
        """Process incoming packet."""
        self._stats['packets_processed'] += 1
        self.flow_tracker.process_packet(packet)
    
    def _analyze_flow(self, flow: NetworkFlow) -> Optional[CCSResult]:
        """
        Analyze a flow for TOR traffic with MULTIMODAL VALIDATION.
        
        Uses RF Classifier Gating: RF only influences score if Identity > 0.
        This prevents false positives on normal encrypted traffic.
        
        Returns:
            CCSResult if TOR detected, None otherwise
        """
        if flow.packet_count < 5:
            return None
        
        # Quick check: is destination a known TOR relay?
        is_known_relay = self.relay_db.is_known_relay(flow.dst_ip)
        
        # Calculate CCS
        ccs_result = self.ccs_calculator.calculate(flow)
        
        # Start with CCS score
        combined_score = ccs_result.ccs_score
        
        # RF CLASSIFIER GATING:
        # Only use RF if Identity Score is NON-ZERO (destination is verified TOR relay)
        # This prevents RF from boosting scores on normal HTTPS traffic
        if ccs_result.identity_score > 0:
            # Destination is a verified TOR relay - RF can influence decision
            rf_prediction, rf_confidence, _ = self.classifier.predict_flow(flow)
            
            if rf_prediction == 1:  # RF says TOR
                # RF confirms TOR detection - boost confidence
                combined_score = min(1.0, combined_score + rf_confidence * 0.1)
        # ELSE: Identity = 0 means not a TOR relay IP
        #       RF is IGNORED to prevent false positives
        
        # Update flow with classification
        flow.is_tor = combined_score >= self.ccs_threshold
        flow.tor_confidence = combined_score
        
        self._stats['flows_analyzed'] += 1
        
        # Call flow analyzed callbacks
        for callback in self._on_flow_analyzed_callbacks:
            try:
                callback(flow, ccs_result)
            except:
                pass
        
        if flow.is_tor:
            self._stats['tor_flows_detected'] += 1
            self._register_tor_user(flow, ccs_result)
            return ccs_result
        
        return None
    
    def _register_tor_user(self, flow: NetworkFlow, ccs_result: CCSResult):
        """Register or update a TOR user detection."""
        src_ip = flow.src_ip
        current_time = time.time()
        
        if src_ip not in self._detected_users:
            self._detected_users[src_ip] = TORUserActivity(
                internal_ip=src_ip,
                first_seen=current_time,
                last_seen=current_time
            )
            self._stats['internal_ips_detected'] += 1
            
            # New TOR user detected - trigger callbacks
            for callback in self._on_tor_detected_callbacks:
                try:
                    callback(self._detected_users[src_ip])
                except:
                    pass
        
        user = self._detected_users[src_ip]
        
        # Update statistics
        user.last_seen = current_time
        user.total_flows += 1
        user.total_packets += flow.packet_count
        user.total_bytes += flow.total_bytes
        
        # Update CCS scores
        user.highest_ccs_score = max(user.highest_ccs_score, ccs_result.ccs_score)
        # Running average
        user.avg_ccs_score = (
            (user.avg_ccs_score * (user.total_flows - 1) + ccs_result.ccs_score) 
            / user.total_flows
        )
        
        # Track entry guards
        if flow.dst_ip not in user.entry_guards:
            user.entry_guards.append(flow.dst_ip)
        
        # Track relay names
        if ccs_result.relay_name and ccs_result.relay_name not in user.relay_names:
            user.relay_names.append(ccs_result.relay_name)
        
        # Collect evidence
        user.all_evidence.extend(ccs_result.evidence)
        
        # Limit evidence to last 50
        if len(user.all_evidence) > 50:
            user.all_evidence = user.all_evidence[-50:]
    
    def _flow_analysis_loop(self):
        """Background thread for analyzing completed flows."""
        while not self._stop_event.is_set():
            try:
                # Cleanup idle flows and analyze them
                completed_flows = self.flow_tracker.cleanup_idle_flows()
                
                for flow in completed_flows:
                    self._analyze_flow(flow)
                
                # Also analyze active flows periodically
                for flow in self.flow_tracker.get_active_flows():
                    if flow.packet_count >= 10 and not flow.is_tor:
                        self._analyze_flow(flow)
                
                # Update active flow counts
                for ip, user in self._detected_users.items():
                    user.active_flow_count = len([
                        f for f in self.flow_tracker.get_flows_for_ip(ip)
                        if f.is_tor
                    ])
                
                time.sleep(1.0)  # Check every second
                
            except Exception as e:
                print(f"[NetworkMonitor] Analysis error: {e}")
                time.sleep(1.0)
    
    def start(self, duration: Optional[float] = None):
        """
        Start network-wide monitoring.
        
        Args:
            duration: Monitoring duration in seconds (None = unlimited)
        """
        if self._running:
            print("[NetworkMonitor] Already running")
            return
        
        # Ensure relay database is loaded
        print("[NetworkMonitor] Loading TOR relay database...")
        self.relay_db.fetch_relay_list()
        
        self._running = True
        self._start_time = time.time()
        self._stop_event.clear()
        
        # Start packet capture
        print(f"[NetworkMonitor] Starting capture on {self.interface or 'default'}...")
        self.listener.start(duration=duration)
        
        # Start flow analysis thread
        self._flow_analysis_thread = threading.Thread(
            target=self._flow_analysis_loop,
            daemon=True
        )
        self._flow_analysis_thread.start()
        
        print("[NetworkMonitor] Network-wide monitoring started")
    
    def stop(self):
        """Stop monitoring."""
        if not self._running:
            return
        
        self._stop_event.set()
        self._running = False
        
        # Stop capture
        self.listener.stop()
        
        # Wait for analysis thread
        if self._flow_analysis_thread and self._flow_analysis_thread.is_alive():
            self._flow_analysis_thread.join(timeout=2.0)
        
        print("[NetworkMonitor] Monitoring stopped")
    
    def is_running(self) -> bool:
        """Check if monitoring is running."""
        return self._running
    
    def get_detected_users(self) -> List[TORUserActivity]:
        """Get all detected TOR users."""
        return list(self._detected_users.values())
    
    def get_user(self, ip: str) -> Optional[TORUserActivity]:
        """Get TOR user activity for an IP."""
        return self._detected_users.get(ip)
    
    def get_tor_flows(self) -> List[NetworkFlow]:
        """Get all TOR flows."""
        return self.flow_tracker.get_tor_flows()
    
    def generate_report(self, ip: str) -> Optional[str]:
        """
        Generate forensic report for an IP.
        
        Args:
            ip: Internal IP address
            
        Returns:
            Formatted report string or None
        """
        user = self._detected_users.get(ip)
        if not user:
            return None
        
        # Get the highest-confidence flow for this user
        flows = [f for f in self.flow_tracker.get_flows_for_ip(ip) if f.is_tor]
        if not flows:
            return f"No active TOR flows for {ip}"
        
        best_flow = max(flows, key=lambda f: f.tor_confidence)
        ccs_result = self.ccs_calculator.calculate(best_flow)
        
        return self.ccs_calculator.generate_forensic_report(ip, ccs_result, best_flow)
    
    def generate_summary_report(self) -> str:
        """Generate summary report of all detected TOR activity."""
        elapsed = time.time() - self._start_time if self._start_time else 0
        
        report = f"""
╔══════════════════════════════════════════════════════════════════════╗
║              NETWORK-WIDE TOR DETECTION SUMMARY                      ║
╠══════════════════════════════════════════════════════════════════════╣
║ Monitoring Duration: {elapsed:.1f} seconds                                    ║
║ Packets Processed:   {self._stats['packets_processed']:<50} ║
║ Flows Analyzed:      {self._stats['flows_analyzed']:<50} ║
║ TOR Flows Detected:  {self._stats['tor_flows_detected']:<50} ║
║ Internal IPs Using TOR: {self._stats['internal_ips_detected']:<47} ║
╠══════════════════════════════════════════════════════════════════════╣
║ DETECTED TOR USERS:                                                  ║
╠══════════════════════════════════════════════════════════════════════╣"""
        
        for user in sorted(self._detected_users.values(), 
                          key=lambda u: u.highest_ccs_score, reverse=True):
            confidence_pct = user.highest_ccs_score * 100
            report += f"""
║ {user.internal_ip:<20} → Entry Guard: {user.entry_guards[0] if user.entry_guards else 'Unknown':<20} ║
║                        Confidence: {confidence_pct:.1f}%  Flows: {user.total_flows:<18} ║"""
        
        if not self._detected_users:
            report += "\n║   No TOR users detected                                              ║"
        
        report += """
╚══════════════════════════════════════════════════════════════════════╝"""
        
        return report
    
    def get_stats(self) -> Dict:
        """Get monitoring statistics."""
        elapsed = time.time() - self._start_time if self._start_time else 0
        
        # Calculate unique TOR users from detected_users dict (most accurate count)
        unique_tor_users = len(self._detected_users)
        
        # Get total TOR flows from all detected users
        total_tor_flows_from_users = sum(u.total_flows for u in self._detected_users.values())
        
        return {
            'packets_processed': self._stats['packets_processed'],
            'flows_analyzed': self._stats['flows_analyzed'],
            'tor_flows_detected': self._stats['tor_flows_detected'],  # Raw count from analysis
            'internal_ips_detected': unique_tor_users,  # Unique IPs only
            'unique_tor_users': unique_tor_users,  # Alias for clarity
            'total_tor_flows': total_tor_flows_from_users,  # Flows per user summed
            'is_running': self._running,
            'elapsed_seconds': round(elapsed, 2),
            'relay_database_loaded': self.relay_db._is_loaded,
            'relay_count': len(self.relay_db._relay_ips),
            'ccs_threshold': self.ccs_threshold,
            'active_flows': len(self.flow_tracker.get_active_flows()),
            'detected_users': [u.to_dict() for u in self._detected_users.values()]
        }
    
    def clear(self):
        """Clear all tracking data."""
        self._detected_users.clear()
        self.flow_tracker.clear()
        self._stats = {
            'packets_processed': 0,
            'flows_analyzed': 0,
            'tor_flows_detected': 0,
            'internal_ips_detected': 0
        }


# Singleton instance-
_network_monitor: Optional[NetworkWideMonitor] = None


def get_network_monitor(interface: Optional[str] = None) -> NetworkWideMonitor:
    """Get singleton network monitor instance."""
    global _network_monitor
    if _network_monitor is None:
        _network_monitor = NetworkWideMonitor(interface=interface)
    return _network_monitor
