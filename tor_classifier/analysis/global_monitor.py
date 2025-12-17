"""
Global TOR Network Monitor.

Fetches and analyzes the entire TOR network in real-time,
providing visibility into all relays, guards, exits, and
network health statistics.
"""

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from collections import Counter
import json

# Try to import stem for direct TOR access
try:
    from stem.descriptor.remote import DescriptorDownloader
    from stem.control import Controller
    STEM_AVAILABLE = True
except ImportError:
    STEM_AVAILABLE = False

import requests


@dataclass
class RelayStats:
    """Statistics for a single TOR relay."""
    fingerprint: str
    nickname: str
    address: str
    or_port: int
    country: str
    country_name: str
    as_number: str
    as_name: str
    bandwidth: int  # bytes/s
    flags: List[str]
    is_guard: bool
    is_exit: bool
    is_stable: bool
    is_fast: bool
    is_running: bool
    first_seen: str
    last_seen: str
    
    def to_dict(self) -> Dict:
        return {
            'fingerprint': self.fingerprint[:8] + '...',
            'nickname': self.nickname,
            'address': self.address,
            'or_port': self.or_port,
            'country': self.country,
            'country_name': self.country_name,
            'as_number': self.as_number,
            'as_name': self.as_name,
            'bandwidth_mbps': round(self.bandwidth / 1_000_000, 2),
            'flags': self.flags,
            'is_guard': self.is_guard,
            'is_exit': self.is_exit,
            'is_stable': self.is_stable,
            'is_fast': self.is_fast
        }


@dataclass
class NetworkStats:
    """Global TOR network statistics."""
    total_relays: int
    total_guards: int
    total_exits: int
    total_bandwidth_gbps: float
    countries: Dict[str, int]  # country -> relay count
    top_as: List[Tuple[str, int]]  # (AS name, relay count)
    avg_bandwidth_mbps: float
    relays_by_flag: Dict[str, int]
    timestamp: float
    
    def to_dict(self) -> Dict:
        return {
            'total_relays': self.total_relays,
            'total_guards': self.total_guards,
            'total_exits': self.total_exits,
            'total_bandwidth_gbps': round(self.total_bandwidth_gbps, 2),
            'countries_count': len(self.countries),
            'top_countries': dict(sorted(self.countries.items(), key=lambda x: -x[1])[:10]),
            'top_as': self.top_as[:10],
            'avg_bandwidth_mbps': round(self.avg_bandwidth_mbps, 2),
            'relays_by_flag': self.relays_by_flag,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.timestamp))
        }


class GlobalNetworkMonitor:
    """
    Monitors the entire TOR network globally.
    
    Fetches data from TOR's Onionoo API and local TOR daemon
    to provide comprehensive network visibility.
    """
    
    ONIONOO_DETAILS = "https://onionoo.torproject.org/details"
    ONIONOO_BANDWIDTH = "https://onionoo.torproject.org/bandwidth"
    ONIONOO_SUMMARY = "https://onionoo.torproject.org/summary"
    
    def __init__(self):
        """Initialize global network monitor."""
        self._relays: List[RelayStats] = []
        self._guards: List[RelayStats] = []
        self._exits: List[RelayStats] = []
        self._network_stats: Optional[NetworkStats] = None
        self._last_fetch: float = 0
        self._cache_duration = 300  # 5 minutes
        
    def fetch_network_data(self, force: bool = False) -> bool:
        """
        Fetch all TOR network data from Onionoo API.
        
        Args:
            force: Force refresh, ignore cache
            
        Returns:
            True if successful
        """
        if not force and self._last_fetch > 0:
            if time.time() - self._last_fetch < self._cache_duration:
                return True
        
        try:
            print("📡 Fetching global TOR network data...")
            
            # Fetch relay details
            response = requests.get(
                self.ONIONOO_DETAILS,
                params={
                    'type': 'relay',
                    'running': 'true',
                    'fields': 'fingerprint,nickname,or_addresses,country,country_name,'
                              'as,as_name,bandwidth,flags,first_seen,last_seen'
                },
                timeout=60,
                headers={'User-Agent': 'TOR-Network-Monitor/1.0'}
            )
            response.raise_for_status()
            data = response.json()
            
            self._relays.clear()
            self._guards.clear()
            self._exits.clear()
            
            countries = Counter()
            as_counter = Counter()
            flag_counter = Counter()
            total_bandwidth = 0
            
            for relay in data.get('relays', []):
                # Parse address
                or_addresses = relay.get('or_addresses', [])
                if not or_addresses:
                    continue
                
                addr = or_addresses[0]
                if ':' in addr:
                    parts = addr.rsplit(':', 1)
                    ip = parts[0].strip('[]')
                    port = int(parts[1]) if len(parts) > 1 else 9001
                else:
                    ip = addr
                    port = 9001
                
                flags = relay.get('flags', [])
                bandwidth = relay.get('bandwidth', [0, 0, 0])
                bw = bandwidth[0] if isinstance(bandwidth, list) else bandwidth
                
                stats = RelayStats(
                    fingerprint=relay.get('fingerprint', ''),
                    nickname=relay.get('nickname', 'Unknown'),
                    address=ip,
                    or_port=port,
                    country=relay.get('country', 'unknown'),
                    country_name=relay.get('country_name', 'Unknown'),
                    as_number=relay.get('as', ''),
                    as_name=relay.get('as_name', 'Unknown'),
                    bandwidth=bw,
                    flags=flags,
                    is_guard='Guard' in flags,
                    is_exit='Exit' in flags,
                    is_stable='Stable' in flags,
                    is_fast='Fast' in flags,
                    is_running='Running' in flags,
                    first_seen=relay.get('first_seen', ''),
                    last_seen=relay.get('last_seen', '')
                )
                
                self._relays.append(stats)
                
                if stats.is_guard:
                    self._guards.append(stats)
                if stats.is_exit:
                    self._exits.append(stats)
                
                # Aggregate stats
                countries[stats.country_name] += 1
                as_counter[stats.as_name] += 1
                total_bandwidth += bw
                
                for flag in flags:
                    flag_counter[flag] += 1
            
            # Calculate network stats
            self._network_stats = NetworkStats(
                total_relays=len(self._relays),
                total_guards=len(self._guards),
                total_exits=len(self._exits),
                total_bandwidth_gbps=total_bandwidth / 1_000_000_000,
                countries=dict(countries),
                top_as=as_counter.most_common(20),
                avg_bandwidth_mbps=(total_bandwidth / len(self._relays) / 1_000_000) if self._relays else 0,
                relays_by_flag=dict(flag_counter),
                timestamp=time.time()
            )
            
            self._last_fetch = time.time()
            print(f"✅ Loaded {len(self._relays)} relays from {len(countries)} countries")
            return True
            
        except Exception as e:
            print(f"❌ Failed to fetch network data: {e}")
            return False
    
    def get_all_relays(self) -> List[RelayStats]:
        """Get all relays."""
        if not self._relays:
            self.fetch_network_data()
        return self._relays
    
    def get_guards(self) -> List[RelayStats]:
        """Get all Entry Guard relays."""
        if not self._guards:
            self.fetch_network_data()
        return self._guards
    
    def get_exits(self) -> List[RelayStats]:
        """Get all Exit relays."""
        if not self._exits:
            self.fetch_network_data()
        return self._exits
    
    def get_network_stats(self) -> Optional[NetworkStats]:
        """Get network-wide statistics."""
        if not self._network_stats:
            self.fetch_network_data()
        return self._network_stats
    
    def get_relays_by_country(self, country: str) -> List[RelayStats]:
        """Get relays in a specific country."""
        return [r for r in self._relays if r.country_name.lower() == country.lower()]
    
    def get_top_bandwidth_relays(self, n: int = 50) -> List[RelayStats]:
        """Get top N relays by bandwidth."""
        return sorted(self._relays, key=lambda r: -r.bandwidth)[:n]
    
    def get_relay_by_ip(self, ip: str) -> Optional[RelayStats]:
        """Find a relay by IP address."""
        for relay in self._relays:
            if relay.address == ip:
                return relay
        return None
    
    def search_relays(self, query: str) -> List[RelayStats]:
        """Search relays by nickname, IP, or AS."""
        query = query.lower()
        results = []
        for relay in self._relays:
            if (query in relay.nickname.lower() or
                query in relay.address or
                query in relay.as_name.lower()):
                results.append(relay)
        return results[:100]  # Limit results
    
    def get_country_distribution(self) -> Dict[str, int]:
        """Get relay count by country."""
        if self._network_stats:
            return self._network_stats.countries
        return {}
    
    def get_bandwidth_distribution(self) -> Dict[str, float]:
        """Get bandwidth distribution by country (in Gbps)."""
        distribution = Counter()
        for relay in self._relays:
            distribution[relay.country_name] += relay.bandwidth
        return {k: round(v / 1_000_000_000, 2) for k, v in distribution.items()}
    
    def analyze_relay(self, ip: str) -> Optional[Dict]:
        """
        Analyze a specific relay by IP.
        
        Returns detailed information about the relay.
        """
        relay = self.get_relay_by_ip(ip)
        if not relay:
            return None
        
        return {
            'relay': relay.to_dict(),
            'is_known': True,
            'confidence': 1.0,
            'classification': 'DEFINITIVE TOR RELAY',
            'role': 'Entry Guard' if relay.is_guard else ('Exit' if relay.is_exit else 'Middle Relay')
        }
    
    def is_tor_relay(self, ip: str) -> Tuple[bool, float, str]:
        """
        Check if an IP is a TOR relay.
        
        Returns:
            (is_relay, confidence, description)
        """
        relay = self.get_relay_by_ip(ip)
        if relay:
            role = 'Guard' if relay.is_guard else ('Exit' if relay.is_exit else 'Relay')
            return True, 1.0, f"TOR {role}: {relay.nickname} ({relay.country_name})"
        return False, 0.0, "Not a known TOR relay"


# Singleton instance for caching
_global_monitor = None

def get_global_monitor() -> GlobalNetworkMonitor:
    """Get the global network monitor singleton."""
    global _global_monitor
    if _global_monitor is None:
        _global_monitor = GlobalNetworkMonitor()
    return _global_monitor
