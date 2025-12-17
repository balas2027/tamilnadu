"""
TOR Network Constants and Enumerations.

Contains known TOR relay prefixes, ports, cell sizes, and TLS ciphers
used for detecting TOR traffic from client-side vantage point.
"""

from enum import Enum
from typing import Set, List


class TrafficType(Enum):
    """Classification of detected traffic types."""
    NON_TOR = "Non-TOR"
    TOR_ENTRY_GUARD = "TOR Entry Guard"
    TOR_BRIDGE = "TOR Bridge"
    TOR_SOCKS = "TOR SOCKS Proxy"
    VPN = "VPN"


# Known TOR Relay IP Prefixes from TOR Consensus
# These are major TOR relay operators - EXPANDED LIST
TOR_RELAY_PREFIXES: List[str] = [
    # Torservers.net (large operator)
    '185.220.100.', '185.220.101.', '185.220.102.', '185.220.103.',
    '185.220.104.', '185.220.105.',
    # Quintex Alliance Consulting
    '199.249.230.', '199.249.231.',
    # CalyxInstitute
    '162.247.72.', '162.247.73.', '162.247.74.',
    # Nos Oignons (French non-profit)
    '89.234.157.',
    # Artikel10 (German association)
    '87.118.122.', '87.118.116.',
    # CCC (Chaos Computer Club)
    '213.164.204.',
    # Digitalcourage
    '46.165.230.',
    # Emerald Onion
    '23.129.64.',
    # F3 Netze
    '193.218.118.',
    # Zwiebelfreunde
    '178.17.170.', '178.17.171.',
    # Hetzner (commonly hosts TOR relays)
    '49.12.', '49.13.',  # Hetzner ranges
    '144.91.', '144.76.',  # Contabo/Hetzner
    '95.216.', '95.217.',  # Hetzner Cloud
    '135.181.', '65.108.', '65.109.',  # More Hetzner
    # More common relay operators
    '104.244.72.', '104.244.73.', '104.244.74.', '104.244.75.', '104.244.76.', '104.244.77.',
    '45.66.33.',
    '171.25.193.',
    '209.141.58.',
    '51.15.', '51.38.', '51.68.', '51.75.', '51.77.', '51.79.', '51.83.', '51.89.', '51.91.', '51.158.',  # OVH ranges
    '5.199.', '5.2.', '5.9.', # Various EU providers
    '176.10.', '176.126.',
    '37.187.', '37.120.',
    '62.210.', '62.102.',
    '78.46.', '78.47.',
    '81.7.', '81.169.',
    '85.25.',
    '88.198.', '88.99.',
    '91.121.', '91.219.', '91.232.',
    '92.60.', '92.222.',
    '94.23.', '94.130.',
    '95.128.', '95.142.', '95.211.',
    '109.70.',
    '128.31.',
    '136.243.',
    '138.201.',
    '148.251.',
    '158.69.',
    '163.172.',
    '167.86.', '167.114.',
    '176.58.',
    '178.62.', '178.63.',
    '185.56.', '185.100.', '185.107.', '185.129.', '185.165.', '185.195.', '185.220.',
    '188.138.', '188.166.',
    '192.42.', '192.87.',
    '193.11.', '193.234.',
    '194.26.', '194.32.',
    '195.154.',
    '198.50.', '198.96.', '198.98.',
    '204.8.', '204.13.',
    '212.83.', '212.129.',
    '213.61.', '213.95.',
    '217.79.', '217.182.',
]

# Localhost addresses (for SOCKS proxy detection)
LOCALHOST_IPS: Set[str] = {
    '127.0.0.1',
    '::1',
    'localhost',
}

# TOR SOCKS proxy ports
TOR_SOCKS_PORTS: Set[int] = {
    9050,   # Tor daemon SOCKS
    9150,   # Tor Browser Bundle SOCKS
    9051,   # Control port
}

# TOR-specific ports
TOR_PORTS: Set[int] = {
    9001,   # Default ORPort (Onion Router Port)
    9030,   # Directory port
    9050,   # SOCKS port (Tor daemon)
    9150,   # SOCKS port (Tor Browser Bundle)
    9051,   # Control port
    443,    # HTTPS (often used by relays)
    80,     # HTTP (some relays)
}

# TOR ORPort common ports (relay ports)
TOR_ORPORTS: Set[int] = {
    9001,   # Default
    9030,   # Directory
    443,    # Disguised as HTTPS
    80,     # Disguised as HTTP
    9002, 9003, 9004,  # Alternative ports
}

# TOR Cell sizes (512 bytes + various protocol headers)
# Expanded range for better detection
TOR_CELL_SIZES: Set[int] = {
    512,    # Base cell size
    514,    # Cell + 2 byte circuit ID
    536,    # Cell + TLS overhead
    548,    # Cell + TLS + TCP overhead
    558,    # Variable header
    586,    # Maximum observed cell with overhead
    509,    # Payload in RELAY cell
    498,    # Minimum observed
    # Extended range for TLS wrapped cells
    566, 574, 582, 594, 602,
}

# TOR typical packet size range (wider for better detection)
TOR_PACKET_SIZE_RANGE = (450, 650)

# TLS Cipher Suites commonly used by TOR
TOR_TLS_CIPHERS: Set[str] = {
    'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
    'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
    'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
    'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
    'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256',
}

# TOR circuit timing constants
TOR_CIRCUIT_LIFETIME_SECONDS = 600  # 10 minutes default
TOR_CIRCUIT_BUILD_TIMEOUT = 60      # 1 minute

# Detection thresholds (lowered for better sensitivity)
CONFIDENCE_THRESHOLDS = {
    'definitive': 0.90,
    'strong': 0.75,
    'medium': 0.55,
    'low': 0.35,
}

# Flow timeout for aggregation
FLOW_TIMEOUT_SECONDS = 120

# Minimum packets for reliable classification (lowered)
MIN_PACKETS_FOR_CLASSIFICATION = 5

