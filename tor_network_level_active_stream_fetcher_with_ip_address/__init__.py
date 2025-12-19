"""
TOR Network Level Active Stream Fetcher with IP Address.

A network-level TOR monitoring system that passively analyzes traffic 
across an entire network to identify TOR users, logical circuits, 
and active streams using Random Forest ML classification.

Modules:
- relay_database: TOR relay IP database from Onionoo
- global_listener: Scapy-based network packet capture
- flow_tracker: Flow grouping and tracking
- feature_extractor: UNB-CIC feature extraction
- rf_classifier: Random Forest TOR classifier  
- ccs_calculator: Composite Confidence Score
- network_monitor: Network-wide TOR detection
"""

from .relay_database import RelayDatabase, get_relay_database
from .global_listener import GlobalListener, PacketInfo
from .flow_tracker import FlowTracker, NetworkFlow
from .feature_extractor import FeatureExtractor, FlowFeatures
from .rf_classifier import TORRandomForestClassifier, get_classifier
from .ccs_calculator import CCSCalculator, CCSResult
from .network_monitor import NetworkWideMonitor, TORUserActivity

__version__ = "1.0.0"
__all__ = [
    "RelayDatabase",
    "get_relay_database", 
    "GlobalListener",
    "PacketInfo",
    "FlowTracker",
    "NetworkFlow",
    "FeatureExtractor",
    "FlowFeatures",
    "TORRandomForestClassifier",
    "get_classifier",
    "CCSCalculator",
    "CCSResult",
    "NetworkWideMonitor",
    "TORUserActivity",
]
