"""
TOR Relay Database Module.

Fetches and caches live TOR relay IPs from Onionoo API for identity matching.
Provides Phase 1 identity scoring for the CCS (Composite Confidence Score).
"""

import time
import json
import requests
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple
from pathlib import Path


@dataclass
class RelayInfo:
    """Information about a TOR relay."""
    fingerprint: str
    nickname: str
    address: str
    or_port: int
    dir_port: int
    flags: List[str]
    bandwidth: int
    is_guard: bool
    is_exit: bool
    country: str = ""
    
    def to_dict(self) -> Dict:
        return {
            'fingerprint': self.fingerprint,
            'nickname': self.nickname,
            'address': self.address,
            'or_port': self.or_port,
            'dir_port': self.dir_port,
            'flags': self.flags,
            'bandwidth': self.bandwidth,
            'is_guard': self.is_guard,
            'is_exit': self.is_exit,
            'country': self.country
        }


# Known TOR relay IP prefixes (from major operators)
TOR_RELAY_PREFIXES = [
    '185.220.100.', '185.220.101.', '185.220.102.', '185.220.103.',  # Torservers.net
    '199.249.230.', '199.249.231.',                                   # Quintex Alliance
    '162.247.72.', '162.247.73.', '162.247.74.',                     # CalyxInstitute
    '89.234.157.',                                                    # Nos Oignons
    '87.118.122.', '87.118.116.',                                    # Artikel10
    '51.15.', '51.158.',                                              # Scaleway (many relays)
    '193.218.118.', '193.234.15.',                                   # Various EU operators
    '104.244.', '198.98.',                                            # US operators
    '45.141.215.', '45.151.167.',                                    # More operators
    '91.132.', '91.219.', '91.213.',                                 # EU ranges
    '185.100.', '185.129.',                                           # Privacy hosts
    '178.17.', '178.20.',                                             # EU ranges
    '109.70.100.',                                                    # appliedprivacy.net
    '192.42.116.',                                                    # NL range
    '77.81.247.',                                                     # AT range
    '95.211.',                                                        # LeaseWeb
    '213.164.',                                                       # UK range
]


class RelayDatabase:
    """
    TOR Relay Database.
    
    Fetches live relay data from Onionoo API and provides
    identity matching for network-wide TOR detection.
    """
    
    ONIONOO_URL = "https://onionoo.torproject.org/details"
    CACHE_DURATION = 3600  # 1 hour
    
    def __init__(self, cache_dir: Optional[str] = None):
        """
        Initialize relay database.
        
        Args:
            cache_dir: Directory to store cached relay data
        """
        self.cache_dir = Path(cache_dir) if cache_dir else Path.home() / '.tor_network_fetcher_cache'
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        self._relays: Dict[str, RelayInfo] = {}  # IP -> RelayInfo
        self._relay_ips: Set[str] = set()
        self._guard_ips: Set[str] = set()
        self._exit_ips: Set[str] = set()
        self._last_fetch: float = 0
        self._is_loaded = False
    
    def _get_cache_path(self) -> Path:
        """Get path to cache file."""
        return self.cache_dir / 'relay_database.json'
    
    def _load_from_cache(self) -> bool:
        """Load relay data from cache if valid."""
        cache_path = self._get_cache_path()
        
        if not cache_path.exists():
            return False
        
        try:
            with open(cache_path, 'r') as f:
                data = json.load(f)
            
            cache_time = data.get('timestamp', 0)
            if time.time() - cache_time > self.CACHE_DURATION:
                return False
            
            for relay_data in data.get('relays', []):
                relay = RelayInfo(**relay_data)
                self._relays[relay.address] = relay
                self._relay_ips.add(relay.address)
                if relay.is_guard:
                    self._guard_ips.add(relay.address)
                if relay.is_exit:
                    self._exit_ips.add(relay.address)
            
            self._last_fetch = cache_time
            self._is_loaded = True
            return True
            
        except Exception as e:
            print(f"[RelayDatabase] Cache load error: {e}")
            return False
    
    def _save_to_cache(self):
        """Save relay data to cache."""
        cache_path = self._get_cache_path()
        
        try:
            data = {
                'timestamp': time.time(),
                'relays': [r.to_dict() for r in self._relays.values()]
            }
            with open(cache_path, 'w') as f:
                json.dump(data, f)
        except Exception as e:
            print(f"[RelayDatabase] Cache save error: {e}")
    
    def fetch_relay_list(self, force: bool = False) -> bool:
        """
        Fetch relay list from Onionoo API.
        
        Args:
            force: Force refresh, ignore cache
            
        Returns:
            True if successful
        """
        # Check cache first
        if not force and self._is_loaded:
            if time.time() - self._last_fetch < self.CACHE_DURATION:
                return True
        
        if not force and self._load_from_cache():
            print(f"[RelayDatabase] Loaded {len(self._relay_ips)} relays from cache")
            return True
        
        try:
            print("[RelayDatabase] Fetching from Onionoo API...")
            
            params = {
                'type': 'relay',
                'running': 'true',
                'fields': 'fingerprint,nickname,or_addresses,dir_address,flags,bandwidth,country'
            }
            
            response = requests.get(
                self.ONIONOO_URL,
                params=params,
                timeout=30,
                headers={'User-Agent': 'TOR-Network-Fetcher/1.0'}
            )
            response.raise_for_status()
            data = response.json()
            
            self._relays.clear()
            self._relay_ips.clear()
            self._guard_ips.clear()
            self._exit_ips.clear()
            
            for relay in data.get('relays', []):
                or_addresses = relay.get('or_addresses', [])
                if not or_addresses:
                    continue
                
                # Get primary address (first one, usually IPv4)
                primary_addr = or_addresses[0]
                if ':' in primary_addr:
                    parts = primary_addr.rsplit(':', 1)
                    ip = parts[0].strip('[]')
                    port = int(parts[1]) if len(parts) > 1 else 9001
                else:
                    ip = primary_addr
                    port = 9001
                
                flags = relay.get('flags', [])
                
                relay_info = RelayInfo(
                    fingerprint=relay.get('fingerprint', ''),
                    nickname=relay.get('nickname', 'Unknown'),
                    address=ip,
                    or_port=port,
                    dir_port=relay.get('dir_address', 0),
                    flags=flags,
                    bandwidth=relay.get('bandwidth', [0, 0, 0])[0] if relay.get('bandwidth') else 0,
                    is_guard='Guard' in flags,
                    is_exit='Exit' in flags,
                    country=relay.get('country', '')
                )
                
                self._relays[ip] = relay_info
                self._relay_ips.add(ip)
                
                if relay_info.is_guard:
                    self._guard_ips.add(ip)
                if relay_info.is_exit:
                    self._exit_ips.add(ip)
            
            self._last_fetch = time.time()
            self._is_loaded = True
            self._save_to_cache()
            
            print(f"[RelayDatabase] Loaded {len(self._relay_ips)} relays ({len(self._guard_ips)} guards, {len(self._exit_ips)} exits)")
            return True
            
        except Exception as e:
            print(f"[RelayDatabase] Fetch error: {e}")
            return False
    
    def is_known_relay(self, ip: str) -> bool:
        """
        Check if IP is a known TOR relay.
        
        Args:
            ip: IP address to check
            
        Returns:
            True if IP is in relay database or matches known prefix
        """
        if not self._is_loaded:
            self.fetch_relay_list()
        
        # Check exact match in database
        if ip in self._relay_ips:
            return True
        
        # Check known prefixes
        return any(ip.startswith(prefix) for prefix in TOR_RELAY_PREFIXES)
    
    def is_guard(self, ip: str) -> bool:
        """Check if IP is a Guard relay."""
        if not self._is_loaded:
            self.fetch_relay_list()
        return ip in self._guard_ips
    
    def is_exit(self, ip: str) -> bool:
        """Check if IP is an Exit relay."""
        if not self._is_loaded:
            self.fetch_relay_list()
        return ip in self._exit_ips
    
    def get_relay_info(self, ip: str) -> Optional[RelayInfo]:
        """
        Get detailed information about a relay.
        
        Args:
            ip: IP address of relay
            
        Returns:
            RelayInfo or None if not found
        """
        if not self._is_loaded:
            self.fetch_relay_list()
        return self._relays.get(ip)
    
    def get_identity_score(self, ip: str, port: int) -> Tuple[float, str]:
        """
        Calculate Phase 1 identity confidence score.
        
        This is the first component of the CCS (w=0.45).
        
        Args:
            ip: Destination IP
            port: Destination port
            
        Returns:
            (score, reason) tuple
        """
        if not self._is_loaded:
            self.fetch_relay_list()
        
        relay = self._relays.get(ip)
        
        if relay:
            # Known relay in database
            if port == relay.or_port:
                # Exact port match
                if relay.is_guard:
                    return 1.0, f"Consensus Guard relay: {relay.nickname}"
                return 0.95, f"Consensus relay: {relay.nickname}"
            elif port in [9001, 9030, 443]:
                # TOR port but different from listed
                return 0.90, f"Consensus relay on TOR port: {relay.nickname}"
            elif port == 80:
                # HTTP - possible false positive
                return 0.50, f"Consensus relay on HTTP (suspicious): {relay.nickname}"
            else:
                return 0.80, f"Consensus relay, non-standard port: {relay.nickname}"
        
        # Check known prefixes (not in current consensus but likely TOR)
        if any(ip.startswith(prefix) for prefix in TOR_RELAY_PREFIXES):
            if port in [9001, 9030, 443]:
                return 0.75, "Known TOR operator IP prefix on TOR port"
            return 0.60, "Known TOR operator IP prefix"
        
        # Not in consensus - check port-based heuristics
        if port == 9001:
            return 0.50, "TOR ORPort 9001 (not in current consensus)"
        elif port == 9030:
            return 0.45, "TOR DirPort 9030 (not in current consensus)"
        
        return 0.0, "Not a known TOR relay"
    
    def get_all_relay_ips(self) -> Set[str]:
        """Get all known relay IPs."""
        if not self._is_loaded:
            self.fetch_relay_list()
        return self._relay_ips.copy()
    
    def get_all_guard_ips(self) -> Set[str]:
        """Get all known Guard relay IPs."""
        if not self._is_loaded:
            self.fetch_relay_list()
        return self._guard_ips.copy()
    
    def get_stats(self) -> Dict:
        """Get database statistics."""
        return {
            'total_relays': len(self._relay_ips),
            'guards': len(self._guard_ips),
            'exits': len(self._exit_ips),
            'last_fetch': self._last_fetch,
            'is_loaded': self._is_loaded,
            'cache_valid': time.time() - self._last_fetch < self.CACHE_DURATION if self._last_fetch else False
        }


# Singleton instance
_relay_database: Optional[RelayDatabase] = None


def get_relay_database() -> RelayDatabase:
    """Get singleton relay database instance."""
    global _relay_database
    if _relay_database is None:
        _relay_database = RelayDatabase()
    return _relay_database
