"""
TOR Consensus Updater.

Fetches and parses the current TOR network consensus data in real-time
using a background thread for continuous updates.
"""

import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# Try to import stem for direct TOR consensus access
try:
    from stem.descriptor.remote import DescriptorDownloader
    STEM_AVAILABLE = True
except ImportError:
    STEM_AVAILABLE = False

import requests


@dataclass
class ConsensusStats:
    """Current TOR network statistics from consensus."""
    total_relays: int = 0
    entry_guards: int = 0
    exit_nodes: int = 0
    total_bandwidth_gbps: float = 0.0
    countries: int = 0
    country_distribution: Dict[str, int] = field(default_factory=dict)
    top_bandwidth_relays: List[Dict] = field(default_factory=list)
    last_update: float = 0
    update_source: str = "none"
    
    def to_dict(self) -> Dict:
        return {
            'total_relays': self.total_relays,
            'entry_guards': self.entry_guards,
            'exit_nodes': self.exit_nodes,
            'total_bandwidth_gbps': round(self.total_bandwidth_gbps, 2),
            'countries': self.countries,
            'country_distribution': self.country_distribution,
            'last_update': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.last_update)) if self.last_update else 'Never',
            'update_source': self.update_source
        }


class TorConsensusUpdater:
    """
    Fetches and parses the current TOR network consensus data.
    
    Runs a background thread to periodically update the data,
    ensuring the dashboard always shows fresh information.
    """
    
    ONIONOO_URL = "https://onionoo.torproject.org/details"
    
    def __init__(self, update_interval: int = 300):  # Update every 5 minutes
        """
        Initialize the consensus updater.
        
        Args:
            update_interval: Seconds between updates (default 5 minutes)
        """
        self.update_interval = update_interval
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self.stats = ConsensusStats()
        self._raw_relays: List[Dict] = []
        self._is_running = False
        
    def _fetch_from_onionoo(self) -> bool:
        """Fetch consensus from Onionoo API."""
        try:
            print(f"📡 [{time.strftime('%H:%M:%S')}] Fetching TOR consensus from Onionoo...")
            
            response = requests.get(
                self.ONIONOO_URL,
                params={
                    'type': 'relay',
                    'running': 'true',
                    'fields': 'fingerprint,nickname,or_addresses,country,country_name,'
                              'as,as_name,bandwidth,flags,first_seen,last_seen'
                },
                timeout=60,
                headers={'User-Agent': 'TOR-Consensus-Updater/2.0'}
            )
            response.raise_for_status()
            data = response.json()
            
            relays = data.get('relays', [])
            
            with self._lock:
                self._raw_relays = relays
                self._aggregate_stats()
            
            print(f"✅ [{time.strftime('%H:%M:%S')}] Fetched {len(relays)} relays from Onionoo")
            return True
            
        except Exception as e:
            print(f"❌ [{time.strftime('%H:%M:%S')}] Onionoo fetch error: {e}")
            return False
    
    def _fetch_from_stem(self) -> bool:
        """Fetch consensus from TOR directory authorities via stem."""
        if not STEM_AVAILABLE:
            return False
        
        try:
            print(f"📡 [{time.strftime('%H:%M:%S')}] Fetching TOR consensus via stem...")
            
            downloader = DescriptorDownloader()
            consensus = list(downloader.get_consensus().run())
            
            relays = []
            for router in consensus:
                flags = list(router.flags) if router.flags else []
                relays.append({
                    'fingerprint': router.fingerprint,
                    'nickname': router.nickname,
                    'address': router.address,
                    'or_port': router.or_port,
                    'flags': flags,
                    'bandwidth': [router.bandwidth or 0],
                    'country_name': 'Unknown',  # stem doesn't provide this directly
                    'as_name': 'Unknown'
                })
            
            with self._lock:
                self._raw_relays = relays
                self._aggregate_stats_from_stem(relays)
            
            print(f"✅ [{time.strftime('%H:%M:%S')}] Fetched {len(relays)} relays via stem")
            return True
            
        except Exception as e:
            print(f"❌ [{time.strftime('%H:%M:%S')}] Stem fetch error: {e}")
            return False
    
    def _aggregate_stats(self):
        """Aggregate statistics from raw relay data (Onionoo format)."""
        country_dist = Counter()
        total_bw = 0
        guards = 0
        exits = 0
        
        for relay in self._raw_relays:
            flags = relay.get('flags', [])
            
            if 'Guard' in flags:
                guards += 1
            if 'Exit' in flags:
                exits += 1
            
            bw = relay.get('bandwidth', [0])
            if isinstance(bw, list) and bw:
                total_bw += bw[0]
            elif isinstance(bw, (int, float)):
                total_bw += bw
            
            country = relay.get('country_name', 'Unknown')
            country_dist[country] += 1
        
        self.stats = ConsensusStats(
            total_relays=len(self._raw_relays),
            entry_guards=guards,
            exit_nodes=exits,
            total_bandwidth_gbps=total_bw / 1_000_000_000,
            countries=len(country_dist),
            country_distribution=dict(country_dist),
            last_update=time.time(),
            update_source="onionoo"
        )
    
    def _aggregate_stats_from_stem(self, relays: List[Dict]):
        """Aggregate statistics from stem relay data."""
        total_bw = 0
        guards = 0
        exits = 0
        
        for relay in relays:
            flags = relay.get('flags', [])
            
            if 'Guard' in flags:
                guards += 1
            if 'Exit' in flags:
                exits += 1
            
            bw = relay.get('bandwidth', [0])
            if isinstance(bw, list) and bw:
                total_bw += bw[0]
            elif isinstance(bw, (int, float)):
                total_bw += bw
        
        self.stats = ConsensusStats(
            total_relays=len(relays),
            entry_guards=guards,
            exit_nodes=exits,
            total_bandwidth_gbps=total_bw / 1_000_000_000,
            countries=0,
            country_distribution={},
            last_update=time.time(),
            update_source="stem"
        )
    
    def _fetch_and_parse(self):
        """Fetch consensus data from best available source."""
        # Try Onionoo first (has country info)
        if self._fetch_from_onionoo():
            return
        
        # Fall back to stem
        if STEM_AVAILABLE and self._fetch_from_stem():
            return
        
        print(f"⚠️ [{time.strftime('%H:%M:%S')}] Could not fetch consensus from any source")
    
    def _run_update_loop(self):
        """Background thread loop for periodic updates."""
        while not self._stop_event.is_set():
            self._fetch_and_parse()
            self._stop_event.wait(self.update_interval)
    
    def start_updater(self):
        """Start the background update thread."""
        if self._is_running:
            return
        
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_update_loop, daemon=True)
        self._thread.start()
        self._is_running = True
        print(f"🚀 Consensus updater started (interval: {self.update_interval}s)")
    
    def stop_updater(self):
        """Stop the background update thread."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        self._is_running = False
        print("🛑 Consensus updater stopped")
    
    def force_update(self) -> bool:
        """Force an immediate update (synchronous)."""
        self._fetch_and_parse()
        return self.stats.total_relays > 0
    
    def get_stats(self) -> ConsensusStats:
        """Get the current consensus statistics."""
        with self._lock:
            return self.stats
    
    def get_raw_relays(self) -> List[Dict]:
        """Get raw relay data."""
        with self._lock:
            return self._raw_relays.copy()
    
    def get_guards(self) -> List[Dict]:
        """Get Entry Guard relays."""
        with self._lock:
            return [r for r in self._raw_relays if 'Guard' in r.get('flags', [])]
    
    def get_exits(self) -> List[Dict]:
        """Get Exit Node relays."""
        with self._lock:
            return [r for r in self._raw_relays if 'Exit' in r.get('flags', [])]
    
    def search_relays(self, query: str) -> List[Dict]:
        """Search relays by nickname, IP, or AS."""
        query = query.lower()
        results = []
        
        with self._lock:
            for relay in self._raw_relays:
                nickname = relay.get('nickname', '').lower()
                as_name = relay.get('as_name', '').lower()
                
                # Get IP from or_addresses
                or_addr = relay.get('or_addresses', [''])[0]
                ip = or_addr.rsplit(':', 1)[0].strip('[]') if or_addr else ''
                
                if query in nickname or query in ip or query in as_name:
                    results.append(relay)
        
        return results[:100]
    
    def is_running(self) -> bool:
        """Check if updater is running."""
        return self._is_running


# Singleton instance
_updater_instance: Optional[TorConsensusUpdater] = None


def get_consensus_updater(update_interval: int = 300) -> TorConsensusUpdater:
    """
    Get the singleton consensus updater instance.
    
    Args:
        update_interval: Seconds between updates
        
    Returns:
        TorConsensusUpdater instance
    """
    global _updater_instance
    if _updater_instance is None:
        _updater_instance = TorConsensusUpdater(update_interval)
    return _updater_instance


def start_background_updates(interval: int = 300):
    """Start background consensus updates."""
    updater = get_consensus_updater(interval)
    updater.start_updater()
    return updater


def get_current_stats() -> ConsensusStats:
    """Get current consensus stats (convenience function)."""
    return get_consensus_updater().get_stats()
