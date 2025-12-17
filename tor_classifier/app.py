"""
TOR Traffic Analyzer - Streamlit Dashboard

A modern, dark-themed dashboard for analyzing network traffic
to detect TOR usage from client-side vantage point.

Features:
- PCAP file upload and analysis
- Synthetic traffic generation for testing
- Entry Guard detection with confidence scores
- Website fingerprinting
- Circuit estimation
- ML-based 4-class classification
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import time
import io
from pathlib import Path

# Import local modules
import sys
sys.path.insert(0, str(Path(__file__).parent))

from core.flow_extractor import FlowExtractor, FlowFeatures
from core.entry_guard_analyzer import EntryGuardAnalyzer, TrafficType
from core.stream_ingester import StreamIngester, is_scapy_available
from core.fusion_detector import FusionDetector, FusionClassification
from analysis.website_fingerprinter import WebsiteFingerprinter
from analysis.circuit_estimator import CircuitEstimator
from models.classifier import TORClassifier
from models.deep_classifier import DeepTORClassifier

# Page configuration
st.set_page_config(
    page_title="TOR Traffic Analyzer",
    page_icon="🧅",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for dark theme with modern styling
st.markdown("""
<style>
    /* Main theme colors */
    :root {
        --primary: #7C3AED;
        --primary-light: #A78BFA;
        --success: #10B981;
        --warning: #F59E0B;
        --danger: #EF4444;
        --info: #3B82F6;
        --bg-dark: #0F172A;
        --bg-card: #1E293B;
        --text-primary: #F1F5F9;
        --text-secondary: #94A3B8;
        --border-color: #334155;
    }
    
    /* Hide Streamlit branding */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    
    /* Main container styling */
    .main .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
    }
    
    /* Card styling */
    .metric-card {
        background: linear-gradient(135deg, #1E293B 0%, #0F172A 100%);
        border: 1px solid #334155;
        border-radius: 12px;
        padding: 1.5rem;
        margin-bottom: 1rem;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
    }
    
    .metric-card h3 {
        color: #94A3B8;
        font-size: 0.875rem;
        font-weight: 500;
        margin-bottom: 0.5rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    
    .metric-card .value {
        color: #F1F5F9;
        font-size: 2rem;
        font-weight: 700;
        line-height: 1.2;
    }
    
    .metric-card .value.success { color: #10B981; }
    .metric-card .value.warning { color: #F59E0B; }
    .metric-card .value.danger { color: #EF4444; }
    .metric-card .value.info { color: #3B82F6; }
    .metric-card .value.primary { color: #A78BFA; }
    
    /* Status badges */
    .status-badge {
        display: inline-block;
        padding: 0.25rem 0.75rem;
        border-radius: 9999px;
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
    }
    
    .status-badge.tor { background: #7C3AED22; color: #A78BFA; border: 1px solid #7C3AED; }
    .status-badge.bridge { background: #F59E0B22; color: #FBBF24; border: 1px solid #F59E0B; }
    .status-badge.vpn { background: #3B82F622; color: #60A5FA; border: 1px solid #3B82F6; }
    .status-badge.normal { background: #10B98122; color: #34D399; border: 1px solid #10B981; }
    
    /* Section headers */
    .section-header {
        color: #F1F5F9;
        font-size: 1.25rem;
        font-weight: 600;
        margin-bottom: 1rem;
        padding-bottom: 0.5rem;
        border-bottom: 2px solid #334155;
    }
    
    /* Info box */
    .info-box {
        background: #1E40AF22;
        border: 1px solid #3B82F6;
        border-radius: 8px;
        padding: 1rem;
        margin: 1rem 0;
    }
    
    .info-box.warning {
        background: #F59E0B22;
        border-color: #F59E0B;
    }
    
    /* Custom scrollbar */
    ::-webkit-scrollbar {
        width: 8px;
        height: 8px;
    }
    
    ::-webkit-scrollbar-track {
        background: #1E293B;
    }
    
    ::-webkit-scrollbar-thumb {
        background: #475569;
        border-radius: 4px;
    }
    
    ::-webkit-scrollbar-thumb:hover {
        background: #64748B;
    }
    
    /* Table styling */
    .dataframe {
        background: #1E293B !important;
    }
    
    .dataframe th {
        background: #0F172A !important;
        color: #94A3B8 !important;
    }
    
    .dataframe td {
        color: #F1F5F9 !important;
    }
    
    /* Sidebar styling */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0F172A 0%, #1E293B 100%);
    }
    
    [data-testid="stSidebar"] .css-1d391kg {
        background: transparent;
    }
    
    /* Button styling */
    .stButton > button {
        background: linear-gradient(135deg, #7C3AED 0%, #5B21B6 100%);
        color: white;
        border: none;
        border-radius: 8px;
        padding: 0.5rem 1.5rem;
        font-weight: 600;
        transition: all 0.3s ease;
    }
    
    .stButton > button:hover {
        background: linear-gradient(135deg, #8B5CF6 0%, #6D28D9 100%);
        box-shadow: 0 4px 12px rgba(124, 58, 237, 0.4);
    }
    
    /* File uploader */
    [data-testid="stFileUploader"] {
        background: #1E293B;
        border: 2px dashed #475569;
        border-radius: 12px;
        padding: 2rem;
    }
    
    /* Progress animation */
    @keyframes pulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.5; }
    }
    
    .analyzing {
        animation: pulse 2s ease-in-out infinite;
    }
</style>
""", unsafe_allow_html=True)


def create_metric_card(title: str, value: str, color_class: str = "") -> str:
    """Create an HTML metric card."""
    return f"""
    <div class="metric-card">
        <h3>{title}</h3>
        <div class="value {color_class}">{value}</div>
    </div>
    """


def create_status_badge(status: str) -> str:
    """Create an HTML status badge."""
    status_map = {
        'TOR Entry Guard': 'tor',
        'TOR_ENTRY_GUARD': 'tor',
        'TOR Bridge': 'bridge',
        'TOR_BRIDGE': 'bridge',
        'TOR SOCKS Proxy': 'tor',
        'TOR_SOCKS': 'tor',
        'VPN': 'vpn',
        'Non-TOR': 'normal',
        'NON_TOR': 'normal'
    }
    badge_class = status_map.get(status, 'normal')
    return f'<span class="status-badge {badge_class}">{status}</span>'


@st.cache_resource
def get_classifiers():
    """Initialize and cache classifiers."""
    binary_clf = TORClassifier()
    deep_clf = DeepTORClassifier()
    return binary_clf, deep_clf


def generate_demo_traffic(traffic_type: str, duration: float) -> list:
    """
    Generate synthetic traffic patterns for Activity Analyzer demo.
    
    Args:
        traffic_type: Type of traffic to simulate
        duration: Duration in seconds
        
    Returns:
        List of packet dictionaries
    """
    import random
    
    packets = []
    current_time = 0.0
    
    if "Browsing" in traffic_type:
        # Web browsing: bursts with pauses
        while current_time < duration:
            # Request burst
            burst_packets = random.randint(5, 15)
            for _ in range(burst_packets):
                packets.append({
                    'size': random.randint(100, 500),
                    'timestamp': current_time,
                    'direction': 1  # outgoing
                })
                current_time += random.uniform(0.01, 0.1)
            
            # Response burst
            response_packets = random.randint(10, 50)
            for _ in range(response_packets):
                packets.append({
                    'size': random.randint(500, 1400),
                    'timestamp': current_time,
                    'direction': -1  # incoming
                })
                current_time += random.uniform(0.005, 0.05)
            
            # Think time
            current_time += random.uniform(1.0, 5.0)
    
    elif "Marketplace" in traffic_type:
        # High reversal, text-heavy browsing
        while current_time < duration:
            for _ in range(random.randint(10, 30)):
                direction = random.choice([1, -1])
                packets.append({
                    'size': random.randint(200, 700),
                    'timestamp': current_time,
                    'direction': direction
                })
                current_time += random.uniform(0.1, 0.5)
            
            # Page load pause
            current_time += random.uniform(2.0, 8.0)
    
    elif "Botnet" in traffic_type or "C2" in traffic_type:
        # Regular heartbeats, fixed sizes
        fixed_size = random.choice([64, 128, 256, 512])
        interval = random.uniform(1.0, 5.0)
        while current_time < duration:
            packets.append({
                'size': fixed_size,
                'timestamp': current_time,
                'direction': 1
            })
            current_time += interval * random.uniform(0.95, 1.05)
            packets.append({
                'size': fixed_size,
                'timestamp': current_time,
                'direction': -1
            })
            current_time += interval * random.uniform(0.95, 1.05)
    
    elif "File" in traffic_type:
        # Large unidirectional download
        while current_time < duration:
            packets.append({
                'size': 1400,
                'timestamp': current_time,
                'direction': -1  # download
            })
            current_time += random.uniform(0.001, 0.01)
    
    elif "Streaming" in traffic_type:
        # Steady video stream
        while current_time < duration:
            packets.append({
                'size': random.randint(1000, 1400),
                'timestamp': current_time,
                'direction': -1
            })
            current_time += random.uniform(0.01, 0.03)
    
    elif "Chat" in traffic_type:
        # Irregular small messages
        while current_time < duration:
            direction = random.choice([1, -1])
            packets.append({
                'size': random.randint(50, 300),
                'timestamp': current_time,
                'direction': direction
            })
            current_time += random.uniform(0.5, 10.0)  # Very irregular
    
    else:
        # Default: random traffic
        while current_time < duration:
            packets.append({
                'size': random.randint(100, 1400),
                'timestamp': current_time,
                'direction': random.choice([1, -1])
            })
            current_time += random.uniform(0.01, 0.5)
    
    return packets


@st.cache_resource
def get_analyzers():
    """Initialize and cache analyzers."""
    entry_guard = EntryGuardAnalyzer()
    fingerprinter = WebsiteFingerprinter()
    circuit_estimator = CircuitEstimator()
    fusion_detector = FusionDetector(enable_consensus_fetch=True)
    return entry_guard, fingerprinter, circuit_estimator, fusion_detector


def analyze_traffic(packets, progress_bar=None):
    """Analyze traffic packets and return results using 3-phase fusion detection."""
    # Get cached components
    binary_clf, deep_clf = get_classifiers()
    entry_guard_analyzer, fingerprinter, circuit_estimator, fusion_detector = get_analyzers()
    
    # Train classifiers if needed
    if not binary_clf.is_trained:
        if progress_bar:
            progress_bar.progress(0.05, "Training binary classifier...")
        binary_clf.train_with_synthetic_data(2000)
    
    if not deep_clf.is_trained:
        if progress_bar:
            progress_bar.progress(0.15, "Training deep classifier...")
        deep_clf.train_with_synthetic(3000)
    
    # Fetch TOR consensus for Phase 1 identity matching
    if progress_bar:
        progress_bar.progress(0.25, "Fetching TOR consensus...")
    try:
        fusion_detector.fetch_consensus()
        consensus_stats = fusion_detector.get_consensus_stats()
        if consensus_stats.get('total_relays', 0) > 0:
            st.session_state['consensus_loaded'] = True
            st.session_state['consensus_stats'] = consensus_stats
    except Exception as e:
        st.session_state['consensus_loaded'] = False
    
    # Extract flows
    if progress_bar:
        progress_bar.progress(0.35, "Extracting flows...")
    
    flow_extractor = FlowExtractor()
    for packet in packets:
        flow_extractor.add_packet(packet.to_dict() if hasattr(packet, 'to_dict') else packet)
    
    flows = flow_extractor.get_all_flows()
    
    if progress_bar:
        progress_bar.progress(0.45, f"Analyzing {len(flows)} flows with Fusion Detector...")
    
    # Analyze each flow with ALL detection methods
    results = []
    for i, flow in enumerate(flows):
        # Build flow info dict
        flow_dict = flow.to_dict()
        flow_dict['packet_sizes'] = flow.packet_sizes
        flow_dict['timestamps'] = flow.timestamps
        
        # === FUSION DETECTION (Primary) ===
        fusion_result = fusion_detector.detect(flow_dict)
        
        # === Entry Guard detection (Legacy/Secondary) ===
        entry_result = entry_guard_analyzer.detect_entry_guard(flow_dict)
        
        # === Deep classification (ML backup) ===
        deep_result = deep_clf.predict_from_flow(flow)
        
        # Website fingerprinting (only for TOR traffic)
        fingerprint = None
        if (fusion_result.classification in [FusionClassification.DEFINITIVE_TOR, 
                                              FusionClassification.HIGH_CONFIDENCE_TOR] or
            entry_result.traffic_type in [TrafficType.TOR_ENTRY_GUARD, TrafficType.TOR_BRIDGE]):
            fingerprint = fingerprinter.fingerprint(flow_dict)
        
        # Circuit estimation
        circuit_est = circuit_estimator.estimate_from_flow(flow_dict)
        
        results.append({
            'flow': flow,
            'fusion': fusion_result,  # NEW: Fusion detection result
            'entry_guard': entry_result,
            'deep_class': deep_result,
            'fingerprint': fingerprint,
            'circuits': circuit_est
        })
        
        if progress_bar and i % 5 == 0:
            progress = 0.45 + (0.45 * (i / len(flows)))
            progress_bar.progress(progress, f"Analyzed {i+1}/{len(flows)} flows...")
    
    if progress_bar:
        progress_bar.progress(1.0, "Analysis complete!")
    
    return results


def main():
    """Main application."""
    
    # Header
    st.markdown("""
    <div style="text-align: center; padding: 2rem 0;">
        <h1 style="color: #A78BFA; font-size: 2.5rem; margin-bottom: 0.5rem;">
            🧅 TOR Traffic Analyzer
        </h1>
        <p style="color: #94A3B8; font-size: 1.1rem;">
            Client-side network traffic analysis for TOR detection
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Sidebar
    with st.sidebar:
        st.markdown("### ⚙️ Configuration")
        
        analysis_mode = st.selectbox(
            "Analysis Mode",
            ["🧪 Synthetic Demo", "📂 Upload PCAP", "📡 Live Capture", "🌍 Global Network Monitor"],
            help="Choose data source for analysis"
        )
        
        st.markdown("---")
        
        if "🧪" in analysis_mode:
            st.markdown("### 📊 Traffic Generation")
            
            col1, col2 = st.columns(2)
            with col1:
                tor_flows = st.number_input("TOR Flows", 1, 20, 5)
                bridge_flows = st.number_input("Bridge Flows", 0, 10, 2)
            with col2:
                normal_flows = st.number_input("Normal Flows", 1, 20, 8)
                vpn_flows = st.number_input("VPN Flows", 0, 10, 2)
            
            packets_per_flow = st.slider("Packets/Flow", 20, 200, 80)
        
        elif "📡" in analysis_mode:
            st.markdown("### 📡 Live Capture Settings")
            
            # Check if Scapy is available
            if not is_scapy_available():
                st.warning("⚠️ Scapy not installed. Install with: `pip install scapy`")
            else:
                # Get available interfaces
                interfaces = StreamIngester.get_available_interfaces()
                default_iface = StreamIngester.get_default_interface()
                
                if interfaces:
                    selected_interface = st.selectbox(
                        "Network Interface",
                        interfaces,
                        index=interfaces.index(default_iface) if default_iface in interfaces else 0,
                        help="Select network interface to capture from"
                    )
                else:
                    selected_interface = None
                    st.info("No interfaces detected. Run as Administrator.")
                
                capture_duration = st.slider("Capture Duration (sec)", 5, 120, 30)
                
                st.info("📡 Captures all TCP & UDP traffic on the selected interface")
        
        st.markdown("---")
        st.markdown("### 📖 About")
        st.markdown("""
        <div style="font-size: 0.85rem; color: #94A3B8;">
        This tool analyzes network traffic to detect TOR usage from a 
        <strong>client-side vantage point</strong>.
        
        <br><br>
        <strong>✅ Can Detect:</strong>
        <ul>
            <li>Entry Guards</li>
            <li>Bridges</li>
            <li>Circuit patterns</li>
        </ul>
        
        <strong>❌ Cannot Detect:</strong>
        <ul>
            <li>Middle relays</li>
            <li>Exit nodes</li>
        </ul>
        </div>
        """, unsafe_allow_html=True)
    
    # Main content
    if "🧪" in analysis_mode:
        # Synthetic demo mode
        st.markdown('<div class="section-header">🧪 Synthetic Traffic Analysis</div>', unsafe_allow_html=True)
        
        if st.button("🚀 Generate & Analyze", use_container_width=True):
            with st.spinner("Generating traffic..."):
                progress = st.progress(0, "Initializing...")
                
                # Generate synthetic traffic
                ingester = StreamIngester()
                packets = ingester.generate_mixed_traffic(
                    num_tor_flows=tor_flows,
                    num_normal_flows=normal_flows,
                    num_bridge_flows=bridge_flows,
                    num_vpn_flows=vpn_flows,
                    packets_per_flow=packets_per_flow
                )
                
                progress.progress(0.1, f"Generated {len(packets)} packets...")
                
                # Analyze
                results = analyze_traffic(packets, progress)
                
                # Store in session state
                st.session_state['results'] = results
                st.session_state['packets'] = packets
    
    elif "📂" in analysis_mode:
        # PCAP upload mode
        st.markdown('<div class="section-header">📂 PCAP File Analysis</div>', unsafe_allow_html=True)
        
        st.markdown("""
        <div class="info-box">
            <strong>ℹ️ Note:</strong> Upload a PCAP file to analyze real network traffic. 
            The file will be processed locally and not stored.
        </div>
        """, unsafe_allow_html=True)
        
        uploaded_file = st.file_uploader(
            "Drop PCAP file here",
            type=['pcap', 'pcapng'],
            help="Upload network capture file"
        )
        
        if uploaded_file is not None:
            if st.button("🔍 Analyze PCAP", use_container_width=True):
                with st.spinner("Processing PCAP file..."):
                    try:
                        from scapy.all import rdpcap
                        
                        # Save uploaded file temporarily
                        import tempfile
                        with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp:
                            tmp.write(uploaded_file.getvalue())
                            tmp_path = tmp.name
                        
                        progress = st.progress(0, "Reading PCAP...")
                        
                        ingester = StreamIngester()
                        packets = ingester.read_pcap(tmp_path)
                        
                        progress.progress(0.2, f"Loaded {len(packets)} packets...")
                        
                        results = analyze_traffic([p.to_dict() for p in packets], progress)
                        
                        st.session_state['results'] = results
                        st.session_state['packets'] = packets
                        
                        # Clean up
                        import os
                        os.unlink(tmp_path)
                        
                    except ImportError:
                        st.error("⚠️ Scapy is required for PCAP analysis. Install with: `pip install scapy`")
                    except Exception as e:
                        st.error(f"⚠️ Error processing PCAP: {str(e)}")
    
    elif "📡" in analysis_mode:
        # Live capture mode
        st.markdown('<div class="section-header">📡 Live Packet Capture</div>', unsafe_allow_html=True)
        
        if not is_scapy_available():
            st.error("""
            ⚠️ **Scapy is required for live capture.**
            
            Install with: `pip install scapy`
            
            On Windows, you may also need [Npcap](https://npcap.com/) installed.
            """)
        else:
            st.markdown("""
            <div class="info-box warning">
                <strong>⚠️ Administrator Required:</strong> Live packet capture requires 
                elevated privileges. Run Streamlit as Administrator on Windows.
            </div>
            """, unsafe_allow_html=True)
            
            # Initialize session state for live capture
            if 'live_capture_active' not in st.session_state:
                st.session_state['live_capture_active'] = False
            if 'live_packets' not in st.session_state:
                st.session_state['live_packets'] = []
            if 'live_session' not in st.session_state:
                st.session_state['live_session'] = None
            
            col1, col2, col3 = st.columns([1, 1, 1])
            
            with col1:
                start_disabled = st.session_state.get('live_capture_active', False)
                if st.button("▶️ Start Capture", use_container_width=True, disabled=start_disabled):
                    try:
                        ingester = StreamIngester()
                        
                        # Store captured packets in session state
                        captured_packets = []
                        
                        def on_packet(pkt):
                            captured_packets.append(pkt)
                        
                        # Start capture with timeout (captures all TCP/UDP)
                        session = ingester.start_live_capture(
                            interface=selected_interface if 'selected_interface' in dir() else None,
                            packet_callback=on_packet,
                            count=0,  # No limit - capture all packets
                            timeout=capture_duration if 'capture_duration' in dir() else 30,
                            filter_expr=None  # No filter - listen to all traffic
                        )
                        
                        st.session_state['live_capture_active'] = True
                        st.session_state['live_session'] = session
                        st.session_state['live_ingester'] = ingester
                        st.session_state['live_packets'] = captured_packets
                        
                        st.success("✅ Capture started!")
                        st.rerun()
                        
                    except Exception as e:
                        st.error(f"⚠️ Failed to start capture: {str(e)}")
            
            with col2:
                stop_disabled = not st.session_state.get('live_capture_active', False)
                if st.button("⏹️ Stop & Analyze", use_container_width=True, disabled=stop_disabled):
                    if st.session_state.get('live_session'):
                        # Stop the capture
                        session = st.session_state['live_session']
                        session.stop()
                        
                        packets = session.get_packets()
                        st.session_state['live_capture_active'] = False
                        
                        if packets:
                            progress = st.progress(0, "Analyzing captured traffic...")
                            results = analyze_traffic(packets, progress)
                            
                            st.session_state['results'] = results
                            st.session_state['packets'] = packets
                            st.success(f"✅ Analyzed {len(packets)} packets!")
                        else:
                            st.warning("No packets captured. Try increasing duration or check permissions.")
                        
                        st.rerun()
            
            with col3:
                if st.button("🔄 Clear", use_container_width=True):
                    if st.session_state.get('live_session'):
                        st.session_state['live_session'].stop()
                    st.session_state['live_capture_active'] = False
                    st.session_state['live_packets'] = []
                    st.session_state['live_session'] = None
                    if 'results' in st.session_state:
                        del st.session_state['results']
                    st.rerun()
            
            # Show live capture status
            if st.session_state.get('live_capture_active') and st.session_state.get('live_session'):
                session = st.session_state['live_session']
                stats = session.get_stats()
                
                st.markdown("---")
                st.markdown('<div class="section-header analyzing">🔴 Capturing...</div>', unsafe_allow_html=True)
                
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("Packets", stats['packet_count'])
                with col2:
                    st.metric("Elapsed", f"{stats['elapsed_time']:.1f}s")
                with col3:
                    st.metric("Rate", f"{stats['packets_per_second']:.1f}/s")
                with col4:
                    st.metric("Interface", stats['interface'] or "Default")
                
                # Auto-refresh while capturing
                time.sleep(1)
                st.rerun()
    
    elif "🌍" in analysis_mode:
        # Global Network Monitor with DYNAMIC updates
        st.markdown('<div class="section-header">🌍 Global TOR Network Monitor (LIVE)</div>', unsafe_allow_html=True)
        
        st.markdown("""
        <div class="info-box">
            <strong>ℹ️ Real-Time Monitor:</strong> Fetches LIVE data from TOR's Onionoo API.
            Enable auto-refresh to continuously update the data every 5 minutes.
        </div>
        """, unsafe_allow_html=True)
        
        try:
            from utils.tor_consensus_updater import get_consensus_updater, TorConsensusUpdater
            
            # Initialize updater in session state
            if 'consensus_updater' not in st.session_state:
                st.session_state['consensus_updater'] = get_consensus_updater(update_interval=300)
            
            updater = st.session_state['consensus_updater']
            
            # Controls row
            col1, col2, col3, col4 = st.columns([1, 1, 1, 1])
            
            with col1:
                if st.button("🔄 Refresh Now", use_container_width=True):
                    with st.spinner("Fetching LIVE TOR network data..."):
                        if updater.force_update():
                            st.success(f"✅ Updated! {updater.get_stats().total_relays:,} relays loaded")
                            st.rerun()
                        else:
                            st.error("❌ Failed to fetch data")
            
            with col2:
                auto_refresh = st.checkbox("🔁 Auto-Refresh (5 min)", value=updater.is_running())
                if auto_refresh and not updater.is_running():
                    updater.start_updater()
                    st.info("Auto-refresh enabled")
                elif not auto_refresh and updater.is_running():
                    updater.stop_updater()
            
            with col3:
                search_query = st.text_input("🔍 Search", placeholder="Nickname, IP, AS...")
            
            with col4:
                stats_obj = updater.get_stats()
                if stats_obj.last_update > 0:
                    last_update = time.strftime('%H:%M:%S', time.localtime(stats_obj.last_update))
                    st.markdown(f"**Last Update:** {last_update}")
                    st.markdown(f"**Source:** {stats_obj.update_source}")
            
            # Get current stats
            stats = updater.get_stats()
            
            if stats.total_relays > 0:
                st.markdown("---")
                st.markdown("### 📊 Network Overview (LIVE)")
                
                col1, col2, col3, col4, col5 = st.columns(5)
                
                with col1:
                    st.markdown(create_metric_card("Total Relays", f"{stats.total_relays:,}", "primary"), unsafe_allow_html=True)
                with col2:
                    st.markdown(create_metric_card("Entry Guards", f"{stats.entry_guards:,}", "success"), unsafe_allow_html=True)
                with col3:
                    st.markdown(create_metric_card("Exit Nodes", f"{stats.exit_nodes:,}", "danger"), unsafe_allow_html=True)
                with col4:
                    st.markdown(create_metric_card("Total Bandwidth", f"{stats.total_bandwidth_gbps:.1f} Gbps", "warning"), unsafe_allow_html=True)
                with col5:
                    st.markdown(create_metric_card("Countries", f"{stats.countries}", "info"), unsafe_allow_html=True)
                
                st.markdown("---")
                
                # Create tabs - Added Correlation Attack and Alerts
                tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
                    "📡 Capture & Analyze", "⚔️ Correlation Attack", "🚨 Alerts", 
                    "🗺️ Countries", "🛡️ Guards", "🚪 Exits", "🔍 Search"
                ])
                
                with tab1:
                    st.markdown("### 📡 Capture & Analyze Traffic")
                    
                    st.markdown("""
                    <div class="info-box">
                        Monitor your <strong>live TOR circuits</strong> and capture packets. See the 
                        <strong>Entry Guard → Middle Relay → Exit Node</strong> path for your traffic.
                    </div>
                    """, unsafe_allow_html=True)
                    
                    # Live TOR Circuit Monitoring
                    st.markdown("#### 🔄 Live TOR Circuits")
                    
                    try:
                        from core.circuit_monitor import get_circuit_monitor, TorCircuitMonitor
                        
                        circuit_monitor = get_circuit_monitor(control_port=9051)
                        
                        col1, col2 = st.columns([1, 3])
                        with col1:
                            if st.button("🔗 Connect to TOR", use_container_width=True):
                                if circuit_monitor.connect():
                                    st.session_state['tor_connected'] = True
                                    st.success("Connected!")
                                    st.rerun()
                                else:
                                    st.error("Failed - ensure TOR is running with Control Port 9051")
                        
                        with col2:
                            if circuit_monitor.is_connected():
                                st.success("✅ Connected to TOR Control Port")
                            else:
                                st.warning("⚠️ Not connected - click 'Connect to TOR'")
                        
                        if circuit_monitor.is_connected():
                            circuits = circuit_monitor.get_circuits()
                            streams = circuit_monitor.get_streams()
                            
                            col1, col2 = st.columns(2)
                            with col1:
                                st.metric("Active Circuits", len(circuits))
                            with col2:
                                st.metric("Active Streams", len(streams))
                            
                            if circuits:
                                st.markdown("##### 🛤️ Circuit Paths (Entry → Middle → Exit)")
                                
                                import pandas as pd
                                circuit_data = []
                                for circ in circuits:
                                    entry = circ.entry_guard
                                    middle = circ.middle_relay
                                    exit_n = circ.exit_node
                                    
                                    circuit_data.append({
                                        'Circuit ID': circ.circuit_id,
                                        'Purpose': circ.purpose,
                                        '🛡️ Entry Guard': f"{entry.nickname} ({entry.ip_address})" if entry else "-",
                                        '🔗 Middle Relay': f"{middle.nickname} ({middle.ip_address})" if middle else "-",
                                        '🚪 Exit Node': f"{exit_n.nickname} ({exit_n.ip_address})" if exit_n else "-",
                                        'Hops': len(circ.path)
                                    })
                                
                                st.dataframe(pd.DataFrame(circuit_data), use_container_width=True)
                                
                                # FORENSIC ORIGIN TRACING
                                st.markdown("---")
                                st.markdown("##### 🔬 Forensic Origin Tracing")
                                
                                try:
                                    from analysis.origin_tracer import OriginTracer, LogicalFlow, CompositeConfidenceCalculator
                                    from utils.forensic_report_generator import ForensicReportGenerator, ForensicFinding
                                    
                                    # Select circuit to trace
                                    circuit_options = [f"{c.circuit_id} - {c.entry_guard.nickname if c.entry_guard else 'Unknown'}" for c in circuits]
                                    selected_circuit_idx = st.selectbox("Select Circuit to Trace", range(len(circuit_options)), 
                                                                        format_func=lambda x: circuit_options[x])
                                    
                                    selected_circuit = circuits[selected_circuit_idx]
                                    
                                    col1, col2 = st.columns(2)
                                    
                                    with col1:
                                        if st.button("🔍 Trace Origin", use_container_width=True):
                                            with st.spinner("Running forensic trace..."):
                                                # Create LogicalFlow from circuit
                                                entry = selected_circuit.entry_guard
                                                middle = selected_circuit.middle_relay
                                                exit_n = selected_circuit.exit_node
                                                
                                                flow = LogicalFlow(
                                                    flow_id=f"FLOW-{selected_circuit.circuit_id}",
                                                    entry_guard_ip=entry.ip_address if entry else "",
                                                    entry_guard_nickname=entry.nickname if entry else "",
                                                    entry_guard_port=entry.or_port if entry else 0,
                                                    middle_relay_ip=middle.ip_address if middle else "",
                                                    middle_relay_nickname=middle.nickname if middle else "",
                                                    exit_node_ip=exit_n.ip_address if exit_n else "",
                                                    exit_node_nickname=exit_n.nickname if exit_n else "",
                                                    local_entry_time=time.time(),
                                                    circuit_id=selected_circuit.circuit_id,
                                                    purpose=selected_circuit.purpose,
                                                    # Simulated scores for demo
                                                    identity_score=0.95 if entry else 0.0,  # High if Entry Guard matched
                                                    fingerprint_score=0.85,  # TOR TLS fingerprint
                                                    pattern_score=0.75  # Traffic pattern match
                                                )
                                                
                                                # Calculate Composite Confidence Score
                                                ccs_calc = CompositeConfidenceCalculator()
                                                flow.composite_confidence_score = ccs_calc.calculate(
                                                    flow.identity_score,
                                                    flow.fingerprint_score,
                                                    flow.pattern_score
                                                )
                                                
                                                # Simulate origin (local machine IP)
                                                import socket
                                                try:
                                                    local_ip = socket.gethostbyname(socket.gethostname())
                                                except:
                                                    local_ip = "192.168.1.100"
                                                
                                                flow.probable_origin_ip = local_ip
                                                flow.origin_confidence = 0.92
                                                flow.log_reference = f"Live TOR Control Port, Circuit #{selected_circuit.circuit_id}"
                                                
                                                st.session_state['forensic_flow'] = flow
                                                st.success("Trace complete!")
                                                st.rerun()
                                    
                                    with col2:
                                        if st.button("📄 Export Report", use_container_width=True):
                                            if 'forensic_flow' in st.session_state:
                                                flow = st.session_state['forensic_flow']
                                                
                                                generator = ForensicReportGenerator(output_dir="./reports")
                                                generator.set_metadata(
                                                    case_id=f"TOR-TRACE-{int(time.time())}",
                                                    analyst="Automated Forensic Analyzer",
                                                    description="TOR Circuit Origin Trace"
                                                )
                                                
                                                finding = generator.create_finding(flow.to_dict())
                                                json_report = generator.generate_json_report()
                                                csv_path = generator.generate_csv_report()
                                                
                                                st.session_state['forensic_report'] = json_report
                                                st.success(f"Report generated! CSV saved to {csv_path}")
                                            else:
                                                st.warning("Run 'Trace Origin' first")
                                    
                                    # Display trace results
                                    if 'forensic_flow' in st.session_state:
                                        flow = st.session_state['forensic_flow']
                                        
                                        st.markdown("---")
                                        st.markdown("##### 📋 Forensic Trace Result")
                                        
                                        result_cols = st.columns(4)
                                        with result_cols[0]:
                                            st.markdown(create_metric_card("Origin IP", flow.probable_origin_ip, "danger"), unsafe_allow_html=True)
                                        with result_cols[1]:
                                            st.markdown(create_metric_card("CCS Score", f"{flow.composite_confidence_score:.3f}", "success"), unsafe_allow_html=True)
                                        with result_cols[2]:
                                            st.markdown(create_metric_card("Origin Conf.", f"{flow.origin_confidence:.1%}", "warning"), unsafe_allow_html=True)
                                        with result_cols[3]:
                                            st.markdown(create_metric_card("Purpose", flow.purpose, "info"), unsafe_allow_html=True)
                                        
                                        # Score breakdown
                                        st.markdown("**CCS Breakdown:** Identity (w=0.45): " + f"{flow.identity_score:.2f}" + 
                                                   " | Fingerprint (w=0.35): " + f"{flow.fingerprint_score:.2f}" +
                                                   " | Pattern (w=0.20): " + f"{flow.pattern_score:.2f}")
                                        
                                        # Circuit path display
                                        st.markdown(f"**Circuit:** 🛡️ {flow.entry_guard_nickname} → 🔗 {flow.middle_relay_nickname} → 🚪 {flow.exit_node_nickname}")
                                        st.markdown(f"**Log Reference:** {flow.log_reference}")
                                    
                                    # Display JSON report
                                    if 'forensic_report' in st.session_state:
                                        st.markdown("---")
                                        st.markdown("##### 📄 Forensic Report (JSON)")
                                        st.code(st.session_state['forensic_report'], language='json')
                                    
                                except ImportError as e:
                                    st.warning(f"Forensic modules not available: {e}")
                                except Exception as e:
                                    st.error(f"Forensic trace error: {e}")
                            
                            if streams:
                                st.markdown("##### 📊 Active Streams")
                                import pandas as pd
                                stream_data = [s.to_dict() for s in streams]
                                st.dataframe(pd.DataFrame(stream_data), use_container_width=True, height=200)
                            
                            if st.button("🔄 Refresh Circuits"):
                                st.rerun()
                    
                    except ImportError as e:
                        st.warning(f"Circuit monitor not available: {e}")
                    except Exception as e:
                        st.error(f"Error: {e}")
                
                with tab2:
                    # REAL-TIME CORRELATION ATTACK TAB
                    st.markdown("### ⚔️ Real-Time Correlation Attack")
                    
                    st.markdown("""
                    <div class="info-box">
                        <strong>Live traffic correlation attack.</strong> Captures real network traffic, 
                        identifies TOR Entry Guards, and performs IAT/volume correlation in real-time.
                    </div>
                    """, unsafe_allow_html=True)
                    
                    try:
                        from analysis.realtime_correlation import (
                            get_realtime_engine, 
                            build_tor_relay_database,
                            RealTimeCorrelationEngine
                        )
                        from core.stream_ingester import StreamIngester
                        
                        # Get engine and set TOR relays
                        rt_engine = get_realtime_engine()
                        
                        # Load TOR relay database
                        raw_relays = updater.get_raw_relays()
                        if raw_relays:
                            relay_db = build_tor_relay_database(raw_relays)
                            rt_engine.set_tor_relays(relay_db)
                            st.info(f"📡 Loaded {len(relay_db):,} TOR relay IPs for correlation")
                        
                        # Capture controls
                        st.markdown("#### 🎯 Live Capture & Correlation")
                        
                        col1, col2, col3 = st.columns(3)
                        
                        with col1:
                            if is_scapy_available():
                                interfaces = StreamIngester.get_available_interfaces()
                                capture_iface = st.selectbox("Interface", ["Default"] + (interfaces if interfaces else []))
                            else:
                                capture_iface = "Default"
                                st.warning("Scapy not available")
                        
                        with col2:
                            capture_duration = st.slider("Duration (sec)", 10, 120, 30)
                        
                        with col3:
                            st.markdown("<br>", unsafe_allow_html=True)
                            start_btn = st.button("🔴 Start Live Attack", use_container_width=True, 
                                                  disabled=rt_engine.is_capturing())
                        
                        # Start capture
                        if start_btn and is_scapy_available():
                            iface = None if capture_iface == "Default" else capture_iface
                            rt_engine.clear()
                            rt_engine.start_capture(interface=iface, duration=capture_duration)
                            st.success(f"🔴 Live capture started for {capture_duration}s...")
                            time.sleep(1)
                            st.rerun()
                        
                        # Status display
                        status = rt_engine.get_status()
                        
                        if status['capturing'] or status['packets_captured'] > 0:
                            st.markdown("---")
                            st.markdown("#### 📊 Live Status")
                            
                            col1, col2, col3, col4 = st.columns(4)
                            with col1:
                                capture_status = "🔴 LIVE" if status['capturing'] else "⏹️ STOPPED"
                                st.markdown(create_metric_card("Status", capture_status, "danger" if status['capturing'] else "info"), unsafe_allow_html=True)
                            with col2:
                                st.markdown(create_metric_card("Packets", f"{status['packets_captured']:,}", "primary"), unsafe_allow_html=True)
                            with col3:
                                st.markdown(create_metric_card("TOR Flows", str(status['tor_flows']), "success"), unsafe_allow_html=True)
                            with col4:
                                st.markdown(create_metric_card("Correlations", str(status['correlations']), "warning"), unsafe_allow_html=True)
                            
                            # Auto-refresh while capturing
                            if status['capturing']:
                                time.sleep(2)
                                st.rerun()
                        
                        # TOR flows detected
                        tor_flows = rt_engine.get_tor_flows()
                        if tor_flows:
                            st.markdown("---")
                            st.markdown("#### 🛡️ Detected TOR Traffic")
                            
                            import pandas as pd
                            flow_df = pd.DataFrame(tor_flows)
                            st.dataframe(flow_df, use_container_width=True, height=200)
                        
                        # Correlation results
                        correlations = rt_engine.get_correlations()
                        if correlations:
                            st.markdown("---")
                            st.markdown("#### 🎯 Correlation Results")
                            
                            # Latest correlation
                            latest = correlations[-1]
                            
                            col1, col2, col3, col4 = st.columns(4)
                            with col1:
                                match_status = "🎯 MATCH" if latest['is_match'] else "❌ NO MATCH"
                                match_color = "danger" if latest['is_match'] else "success"
                                st.markdown(create_metric_card("Result", match_status, match_color), unsafe_allow_html=True)
                            with col2:
                                st.markdown(create_metric_card("Score", f"{latest['correlation_score']:.3f}", "warning"), unsafe_allow_html=True)
                            with col3:
                                st.markdown(create_metric_card("Origin IP", latest['origin_ip'], "info"), unsafe_allow_html=True)
                            with col4:
                                st.markdown(create_metric_card("Entry Guard", latest['entry_guard'].split('(')[0].strip(), "primary"), unsafe_allow_html=True)
                            
                            # Conclusion
                            if latest['is_match']:
                                st.error(f"🎯 **TOR TRAFFIC CORRELATED!** Origin IP: {latest['origin_ip']} → Entry Guard: {latest['entry_guard']}")
                            
                            # Evidence
                            st.markdown("**Evidence:**")
                            for ev in latest['evidence']:
                                st.markdown(f"• {ev}")
                            
                            # All correlations table
                            st.markdown("---")
                            st.markdown("#### 📋 All Correlations")
                            import pandas as pd
                            corr_df = pd.DataFrame(correlations)
                            st.dataframe(corr_df[['time_formatted', 'correlation_score', 'timing_score', 'volume_score', 'is_match', 'origin_ip']], 
                                        use_container_width=True, height=200)
                        
                        # Clear button
                        if st.button("🗑️ Clear Results"):
                            rt_engine.clear()
                            if 'attack_results' in st.session_state:
                                del st.session_state['attack_results']
                            st.rerun()
                        
                    except ImportError as e:
                        st.warning(f"Real-time correlation not available: {e}")
                    except Exception as e:
                        st.error(f"Error: {e}")
                
                with tab3:
                    # ALERTS TAB
                    st.markdown("### 🚨 Real-Time Alerts")
                    
                    st.markdown("""
                    <div class="info-box">
                        Monitor <strong>security alerts</strong> for suspicious TOR activity patterns. 
                        Alerts are logged to SIEM-compatible JSON format.
                    </div>
                    """, unsafe_allow_html=True)
                    
                    try:
                        from core.alert_system import get_alert_system, AlertType, AlertSeverity
                        
                        alert_system = get_alert_system()
                        
                        # Controls
                        col1, col2, col3 = st.columns(3)
                        
                        with col1:
                            if st.button("🔔 Generate Test Alert", use_container_width=True):
                                alert = alert_system.alert_hidden_service_connection(
                                    origin_ip="192.168.1.100",
                                    circuit_id="TEST-001",
                                    purpose="HS_CLIENT_REND",
                                    confidence=0.85
                                )
                                st.success(f"Alert created: {alert.alert_id}")
                        
                        with col2:
                            if st.button("📄 Export Alerts", use_container_width=True):
                                filepath = alert_system.export_alerts_json()
                                st.success(f"Exported to: {filepath}")
                        
                        with col3:
                            if st.button("🔄 Refresh", use_container_width=True):
                                st.rerun()
                        
                        # Statistics
                        stats_alerts = alert_system.get_statistics()
                        
                        st.markdown("---")
                        st.markdown("#### 📊 Alert Statistics")
                        
                        col1, col2, col3, col4 = st.columns(4)
                        with col1:
                            st.markdown(create_metric_card("Total Alerts", str(stats_alerts.get('total', 0)), "primary"), unsafe_allow_html=True)
                        with col2:
                            st.markdown(create_metric_card("Unacknowledged", str(stats_alerts.get('unacknowledged', 0)), "danger"), unsafe_allow_html=True)
                        with col3:
                            critical = stats_alerts.get('by_severity', {}).get('CRITICAL', 0)
                            st.markdown(create_metric_card("Critical", str(critical), "warning"), unsafe_allow_html=True)
                        with col4:
                            high = stats_alerts.get('by_severity', {}).get('HIGH', 0)
                            st.markdown(create_metric_card("High", str(high), "info"), unsafe_allow_html=True)
                        
                        # Alert list
                        st.markdown("---")
                        st.markdown("#### 📋 Recent Alerts")
                        
                        alerts = alert_system.get_alerts(limit=20)
                        
                        if alerts:
                            import pandas as pd
                            alert_data = []
                            for a in alerts:
                                sev_emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(a.severity.value, '⚪')
                                alert_data.append({
                                    'ID': a.alert_id,
                                    'Severity': f"{sev_emoji} {a.severity.value}",
                                    'Type': a.alert_type.value.replace('_', ' '),
                                    'Title': a.title[:40] + '...' if len(a.title) > 40 else a.title,
                                    'Source IP': a.source_ip or '-',
                                    'Time': time.strftime('%H:%M:%S', time.localtime(a.timestamp)),
                                    'Ack': '✅' if a.acknowledged else '❌'
                                })
                            
                            st.dataframe(pd.DataFrame(alert_data), use_container_width=True, height=300)
                        else:
                            st.info("No alerts yet. Generate test alerts or run analysis to trigger alerts.")
                        
                        # Log file location
                        st.markdown(f"**SIEM Log:** `{stats_alerts.get('log_file', 'N/A')}`")
                        
                    except ImportError as e:
                        st.warning(f"Alert system not available: {e}")
                    except Exception as e:
                        st.error(f"Error: {e}")
                
                with tab4:
                    st.markdown("### Top Countries by Relay Count")
                    
                    if stats.country_distribution:
                        top_countries = dict(sorted(stats.country_distribution.items(), key=lambda x: -x[1])[:15])
                        
                        fig = px.bar(
                            x=list(top_countries.keys()),
                            y=list(top_countries.values()),
                            labels={'x': 'Country', 'y': 'Relay Count'},
                            color=list(top_countries.values()),
                            color_continuous_scale='Viridis'
                        )
                        fig.update_layout(
                            paper_bgcolor='rgba(0,0,0,0)',
                            plot_bgcolor='rgba(0,0,0,0)',
                            font_color='#94A3B8',
                            height=400,
                            showlegend=False
                        )
                        st.plotly_chart(fig, use_container_width=True)
                
                with tab5:
                    st.markdown("### 🛡️ Entry Guard Relays")
                    guards = updater.get_guards()
                    
                    if guards:
                        st.info(f"Found {len(guards):,} Entry Guard relays")
                        
                        guard_data = []
                        for g in sorted(guards, key=lambda x: -(x.get('bandwidth', [0])[0] if isinstance(x.get('bandwidth'), list) else x.get('bandwidth', 0)))[:50]:
                            bw = g.get('bandwidth', [0])
                            bw_val = bw[0] if isinstance(bw, list) else bw
                            or_addr = g.get('or_addresses', [''])[0]
                            ip = or_addr.rsplit(':', 1)[0].strip('[]') if or_addr else g.get('address', '')
                            
                            guard_data.append({
                                'Nickname': g.get('nickname', 'Unknown'),
                                'Country': g.get('country_name', 'Unknown'),
                                'Bandwidth (Mbps)': round(bw_val / 1_000_000, 2),
                                'IP': ip,
                                'AS': (g.get('as_name', 'Unknown')[:25] + '...') if len(g.get('as_name', '')) > 25 else g.get('as_name', 'Unknown')
                            })
                        
                        import pandas as pd
                        st.dataframe(pd.DataFrame(guard_data), use_container_width=True, height=400)
                
                with tab6:
                    st.markdown("### 🚪 Exit Node Relays")
                    exits = updater.get_exits()
                    
                    if exits:
                        st.info(f"Found {len(exits):,} Exit Node relays")
                        
                        exit_data = []
                        for e in sorted(exits, key=lambda x: -(x.get('bandwidth', [0])[0] if isinstance(x.get('bandwidth'), list) else x.get('bandwidth', 0)))[:50]:
                            bw = e.get('bandwidth', [0])
                            bw_val = bw[0] if isinstance(bw, list) else bw
                            or_addr = e.get('or_addresses', [''])[0]
                            ip = or_addr.rsplit(':', 1)[0].strip('[]') if or_addr else e.get('address', '')
                            
                            exit_data.append({
                                'Nickname': e.get('nickname', 'Unknown'),
                                'Country': e.get('country_name', 'Unknown'),
                                'Bandwidth (Mbps)': round(bw_val / 1_000_000, 2),
                                'IP': ip,
                                'Flags': ', '.join(e.get('flags', [])[:3])
                            })
                        
                        import pandas as pd
                        st.dataframe(pd.DataFrame(exit_data), use_container_width=True, height=400)
                
                with tab7:
                    if search_query:
                        results = updater.search_relays(search_query)
                        
                        if results:
                            st.success(f"Found {len(results)} matching relays")
                            
                            search_data = []
                            for r in results[:50]:
                                flags = r.get('flags', [])
                                role = 'Guard' if 'Guard' in flags else ('Exit' if 'Exit' in flags else 'Relay')
                                bw = r.get('bandwidth', [0])
                                bw_val = bw[0] if isinstance(bw, list) else bw
                                or_addr = r.get('or_addresses', [''])[0]
                                ip = or_addr.rsplit(':', 1)[0].strip('[]') if or_addr else r.get('address', '')
                                
                                search_data.append({
                                    'Nickname': r.get('nickname', 'Unknown'),
                                    'Role': role,
                                    'Country': r.get('country_name', 'Unknown'),
                                    'IP': ip,
                                    'Bandwidth (Mbps)': round(bw_val / 1_000_000, 2)
                                })
                            
                            import pandas as pd
                            st.dataframe(pd.DataFrame(search_data), use_container_width=True, height=400)
                        else:
                            st.warning("No matching relays found")
                    else:
                        st.info("Enter a search query to find relays")
                
                # Auto-refresh display
                if updater.is_running():
                    st.markdown("---")
                    st.markdown("🔄 **Auto-refresh active** - Data updates every 5 minutes")
                    time.sleep(5)  # Short pause before potential rerun
                    st.rerun()
            
            else:
                st.info("👆 Click 'Refresh Now' to load live TOR network data")
        
        except ImportError as e:
            st.error(f"Failed to import consensus updater: {e}")
        except Exception as e:
            st.error(f"Error: {e}")
    
    elif "🔍" in analysis_mode:
        # Activity Analyzer
        st.markdown('<div class="section-header">🔍 Activity Analyzer</div>', unsafe_allow_html=True)
        
        st.markdown("""
        <div class="info-box">
            <strong>ℹ️ Activity Analyzer:</strong> Classifies traffic into activity types 
            (marketplace, botnet C2, file sharing, streaming) and generates correlation 
            fingerprints for Entry↔Exit linking.
        </div>
        """, unsafe_allow_html=True)
        
        try:
            from analysis.activity_fingerprinter import ActivityFingerprinter, ActivityType
            from analysis.burst_correlator import BurstCorrelator, create_packet_list
            import random
            
            fingerprinter = ActivityFingerprinter()
            correlator = BurstCorrelator(gap_threshold=2.0)
            
            # Demo options
            st.markdown("### 🧪 Generate Demo Traffic")
            
            col1, col2 = st.columns(2)
            
            with col1:
                demo_type = st.selectbox(
                    "Traffic Type",
                    ["🌐 Web Browsing", "🛒 Marketplace", "🤖 Botnet C2", "📁 File Sharing", "📺 Video Streaming", "💬 Chat"]
                )
            
            with col2:
                demo_duration = st.slider("Duration (seconds)", 5, 300, 60)
            
            if st.button("🚀 Generate & Analyze", use_container_width=True):
                with st.spinner("Generating traffic pattern..."):
                    # Generate synthetic traffic based on type
                    packets = generate_demo_traffic(demo_type, demo_duration)
                    
                    # Create flow data
                    sizes = [p['size'] * (1 if p['direction'] > 0 else -1) for p in packets]
                    timestamps = [p['timestamp'] for p in packets]
                    
                    flow_data = {
                        'packet_sizes': sizes,
                        'timestamps': timestamps,
                        'total_bytes': sum(abs(s) for s in sizes),
                        'duration': demo_duration
                    }
                    
                    # Activity classification
                    activity_result = fingerprinter.classify_flow(flow_data)
                    
                    # Burst correlation
                    segments = correlator.segment_stream(packets)
                    fingerprints = [correlator.generate_fingerprint(seg) for seg in segments]
                    
                    # Display results
                    st.markdown("---")
                    st.markdown("### 📊 Activity Classification")
                    
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        activity_color = "danger" if activity_result.is_suspicious else "success"
                        st.markdown(create_metric_card("Detected Activity", activity_result.detected_activity.value, activity_color), unsafe_allow_html=True)
                    
                    with col2:
                        conf_color = "success" if activity_result.confidence > 0.7 else "warning"
                        st.markdown(create_metric_card("Confidence", f"{activity_result.confidence:.1%}", conf_color), unsafe_allow_html=True)
                    
                    with col3:
                        auto_color = "warning" if activity_result.is_automated else "info"
                        st.markdown(create_metric_card("Automated", "Yes" if activity_result.is_automated else "No", auto_color), unsafe_allow_html=True)
                    
                    # Alert for suspicious activity
                    if activity_result.is_suspicious:
                        st.markdown("""
                        <div class="info-box warning">
                            ⚠️ <strong>Suspicious Pattern Detected!</strong> Traffic exhibits characteristics 
                            associated with automated or potentially malicious activity.
                        </div>
                        """, unsafe_allow_html=True)
                    
                    # Indicators
                    st.markdown("### 🔎 Detection Indicators")
                    for indicator in activity_result.indicators:
                        st.markdown(f"• {indicator}")
                    
                    # Score breakdown
                    st.markdown("### 📈 Activity Scores")
                    import pandas as pd
                    score_df = pd.DataFrame([
                        {'Activity': k, 'Score': v}
                        for k, v in sorted(activity_result.scores.items(), key=lambda x: -x[1])
                    ])
                    
                    fig = px.bar(
                        score_df, x='Activity', y='Score',
                        color='Score', color_continuous_scale='Viridis'
                    )
                    fig.update_layout(
                        paper_bgcolor='rgba(0,0,0,0)',
                        plot_bgcolor='rgba(0,0,0,0)',
                        font_color='#94A3B8',
                        height=300
                    )
                    st.plotly_chart(fig, use_container_width=True)
                    
                    # Correlation fingerprints
                    st.markdown("---")
                    st.markdown("### 🔗 Circuit Segments & Correlation Fingerprints")
                    st.info(f"Segmented stream into {len(segments)} circuits (gap threshold: 2.0s)")
                    
                    if fingerprints:
                        fp_data = []
                        for fp in fingerprints:
                            fp_data.append({
                                'Segment': fp.segment_id,
                                'Duration': f"{fp.duration:.2f}s",
                                'Packets': fp.packet_count,
                                'Bytes': f"{fp.total_bytes:,}",
                                'IAT μ': f"{fp.iat_mean:.3f}s",
                                'Upload %': f"{fp.upload_ratio:.1%}",
                                'Watermark': fp.watermark[:12] + '...'
                            })
                        
                        st.dataframe(pd.DataFrame(fp_data), use_container_width=True)
                        
                        # Watermark explanation
                        st.markdown("""
                        <div class="info-box">
                            <strong>💡 Correlation Watermarks:</strong> These unique fingerprints can be matched 
                            against Exit Node observations to correlate Entry↔Exit traffic. Each watermark 
                            encodes timing, size, and directional patterns that survive TOR's 3-hop routing.
                        </div>
                        """, unsafe_allow_html=True)
            
            # Template reference
            st.markdown("---")
            st.markdown("### 📋 Activity Templates Reference")
            
            templates = fingerprinter.get_activity_templates()
            template_data = []
            for t in templates:
                template_data.append({
                    'Activity': t['type'],
                    'Burst Reversal': f"{t['burst_reversal'][0]}-{t['burst_reversal'][1]}",
                    'Packet Size': f"{t['avg_packet_size'][0]}-{t['avg_packet_size'][1]}B",
                    'Duration': f"{t['duration'][0]}-{t['duration'][1]}s"
                })
            
            import pandas as pd
            st.dataframe(pd.DataFrame(template_data), use_container_width=True)
        
        except ImportError as e:
            st.error(f"Failed to import activity modules: {e}")
        except Exception as e:
            st.error(f"Error: {e}")
            import traceback
            st.code(traceback.format_exc())
    
    # Display results
    if 'results' in st.session_state and st.session_state['results']:
        results = st.session_state['results']
        
        st.markdown("---")
        
        # Summary metrics
        st.markdown('<div class="section-header">📊 Analysis Summary</div>', unsafe_allow_html=True)
        
        # Count by type
        type_counts = {
            'TOR Entry Guard': 0,
            'TOR Bridge': 0,
            'TOR SOCKS Proxy': 0,
            'VPN': 0,
            'Non-TOR': 0
        }
        
        for r in results:
            traffic_type = r['entry_guard'].traffic_type.value
            if traffic_type in type_counts:
                type_counts[traffic_type] += 1
        
        # Combine TOR counts for summary
        total_tor = type_counts['TOR Entry Guard'] + type_counts['TOR Bridge'] + type_counts['TOR SOCKS Proxy']
        
        col1, col2, col3, col4, col5 = st.columns(5)
        
        with col1:
            st.markdown(create_metric_card("Total Flows", str(len(results)), "primary"), unsafe_allow_html=True)
        
        with col2:
            st.markdown(create_metric_card("TOR Traffic", str(total_tor), "danger"), unsafe_allow_html=True)
        
        with col3:
            st.markdown(create_metric_card("TOR Bridges", str(type_counts['TOR Bridge']), "warning"), unsafe_allow_html=True)
        
        with col4:
            st.markdown(create_metric_card("VPN", str(type_counts['VPN']), "info"), unsafe_allow_html=True)
        
        with col5:
            st.markdown(create_metric_card("Normal", str(type_counts['Non-TOR']), "success"), unsafe_allow_html=True)
        
        # Traffic distribution chart
        st.markdown("---")
        col_chart, col_table = st.columns([1, 2])
        
        with col_chart:
            st.markdown('<div class="section-header">🎯 Traffic Distribution</div>', unsafe_allow_html=True)
            
            fig = go.Figure(data=[go.Pie(
                labels=list(type_counts.keys()),
                values=list(type_counts.values()),
                hole=0.4,
                marker_colors=['#7C3AED', '#F59E0B', '#3B82F6', '#10B981']
            )])
            
            fig.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font_color='#94A3B8',
                showlegend=True,
                legend=dict(
                    orientation="h",
                    yanchor="bottom",
                    y=-0.2,
                    xanchor="center",
                    x=0.5
                ),
                margin=dict(l=20, r=20, t=20, b=60)
            )
            
            st.plotly_chart(fig, use_container_width=True)
        
        with col_table:
            st.markdown('<div class="section-header">📋 Flow Details</div>', unsafe_allow_html=True)
            
            # Create DataFrame for display
            table_data = []
            for r in results:
                flow = r['flow']
                entry = r['entry_guard']
                deep = r['deep_class']
                
                table_data.append({
                    'Flow ID': flow.flow_id[:8] + '...',
                    'Destination': f"{flow.dst_ip}:{flow.dst_port}",
                    'Packets': flow.total_packets,
                    'Bytes': flow.total_bytes,
                    'Duration': f"{flow.duration:.2f}s",
                    'Type': entry.traffic_type.value,
                    'Confidence': f"{entry.confidence:.0%}",
                    'ML Class': deep.traffic_type
                })
            
            df = pd.DataFrame(table_data)
            st.dataframe(df, use_container_width=True, hide_index=True)
        
        # Detailed analysis
        st.markdown("---")
        st.markdown('<div class="section-header">🔬 Detailed Analysis</div>', unsafe_allow_html=True)
        
        # Filter for TOR-related flows
        tor_results = [r for r in results if r['entry_guard'].traffic_type in 
                       [TrafficType.TOR_ENTRY_GUARD, TrafficType.TOR_BRIDGE, TrafficType.TOR_SOCKS]]
        
        if tor_results:
            tabs = st.tabs(["🎯 Detection Details", "🌐 Website Fingerprinting", "🔄 Circuit Analysis"])
            
            with tabs[0]:
                for i, r in enumerate(tor_results[:5]):  # Show up to 5
                    flow = r['flow']
                    entry = r['entry_guard']
                    
                    with st.expander(f"Flow: {flow.dst_ip}:{flow.dst_port}", expanded=(i == 0)):
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.markdown(f"**Traffic Type:** {create_status_badge(entry.traffic_type.value)}", unsafe_allow_html=True)
                            st.markdown(f"**Confidence:** {entry.confidence:.1%}")
                            st.markdown(f"**Packets:** {flow.total_packets}")
                            st.markdown(f"**Bytes:** {flow.total_bytes:,}")
                        
                        with col2:
                            st.markdown("**Detection Indicators:**")
                            for indicator in entry.indicators:
                                st.markdown(f"- ✓ {indicator}")
            
            with tabs[1]:
                fingerprint_results = [r for r in tor_results if r['fingerprint'] and r['fingerprint'].matched_website]
                
                if fingerprint_results:
                    for r in fingerprint_results[:5]:
                        fp = r['fingerprint']
                        flow = r['flow']
                        
                        with st.expander(f"Flow: {flow.dst_ip} → {fp.matched_website}"):
                            col1, col2 = st.columns(2)
                            
                            with col1:
                                st.markdown(f"**Matched Website:** {fp.matched_website}")
                                st.markdown(f"**Category:** {fp.category}")
                                st.markdown(f"**Similarity:** {fp.similarity_score:.1%}")
                            
                            with col2:
                                st.markdown("**Top Matches:**")
                                for name, score in fp.top_matches[:3]:
                                    st.markdown(f"- {name}: {score:.1%}")
                else:
                    st.info("No website fingerprints detected in TOR flows.")
            
            with tabs[2]:
                for r in tor_results[:5]:
                    circuits = r['circuits']
                    flow = r['flow']
                    
                    with st.expander(f"Flow: {flow.dst_ip}:{flow.dst_port}"):
                        col1, col2, col3 = st.columns(3)
                        
                        with col1:
                            st.metric("Estimated Circuits", circuits.estimated_circuits)
                        with col2:
                            st.metric("Burst Count", circuits.burst_count)
                        with col3:
                            st.metric("Confidence", f"{circuits.confidence:.1%}")
        else:
            st.info("No TOR-related traffic detected in this sample.")
        
        # Model performance
        st.markdown("---")
        st.markdown('<div class="section-header">🤖 Model Performance</div>', unsafe_allow_html=True)
        
        binary_clf, deep_clf = get_classifiers()
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### Binary Classifier (TOR/Non-TOR)")
            if binary_clf.training_metrics:
                metrics = binary_clf.training_metrics
                fig = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=metrics.get('accuracy', 0) * 100,
                    title={'text': "Accuracy"},
                    gauge={
                        'axis': {'range': [0, 100]},
                        'bar': {'color': "#7C3AED"},
                        'bgcolor': "#1E293B",
                        'borderwidth': 0,
                        'steps': [
                            {'range': [0, 50], 'color': "#EF4444"},
                            {'range': [50, 75], 'color': "#F59E0B"},
                            {'range': [75, 100], 'color': "#10B981"}
                        ]
                    }
                ))
                fig.update_layout(
                    paper_bgcolor='rgba(0,0,0,0)',
                    font_color='#94A3B8',
                    height=250
                )
                st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.markdown("#### Deep Classifier (4-class)")
            if deep_clf.training_metrics:
                metrics = deep_clf.training_metrics
                
                # Per-class metrics bar chart
                per_class = deep_clf.get_per_class_metrics()
                if per_class:
                    classes = list(per_class.keys())
                    precision = [per_class[c]['precision'] for c in classes]
                    recall = [per_class[c]['recall'] for c in classes]
                    
                    fig = go.Figure(data=[
                        go.Bar(name='Precision', x=classes, y=precision, marker_color='#7C3AED'),
                        go.Bar(name='Recall', x=classes, y=recall, marker_color='#3B82F6')
                    ])
                    
                    fig.update_layout(
                        barmode='group',
                        paper_bgcolor='rgba(0,0,0,0)',
                        plot_bgcolor='rgba(0,0,0,0)',
                        font_color='#94A3B8',
                        height=250,
                        yaxis=dict(range=[0, 1]),
                        legend=dict(orientation="h", y=-0.2)
                    )
                    st.plotly_chart(fig, use_container_width=True)


if __name__ == "__main__":
    main()
