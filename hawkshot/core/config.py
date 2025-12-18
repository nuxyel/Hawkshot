"""
HAWKSHOT Configuration
Global configuration, constants, and state management.
"""

import os
import json
from dataclasses import dataclass, field, asdict
from typing import List, Optional
from datetime import datetime

# Version info
VERSION = "4.0.0"
BANNER = f"""
   ▄█    █▄       ▄████████  ▄█     █▄     ▄█   ▄█▄    ▄████████    ▄█    █▄     ▄██████▄      ███     
  ███    ███     ███    ███ ███     ███   ███ ▄███▀   ███    ███   ███    ███   ███    ███ ▀█████████▄ 
  ███    ███     ███    ███ ███     ███   ███▐██▀     ███    █▀    ███    ███   ███    ███    ▀███▀▀██ 
 ▄███▄▄▄▄███▄▄   ███    ███ ███     ███  ▄█████▀      ███         ▄███▄▄▄▄███▄▄ ███    ███     ███   ▀ 
▀▀███▀▀▀▀███▀  ▀███████████ ███     ███ ▀▀█████▄    ▀███████████ ▀▀███▀▀▀▀███▀  ███    ███     ███     
  ███    ███     ███    ███ ███     ███   ███▐██▄            ███   ███    ███   ███    ███     ███     
  ███    ███     ███    ███ ███ ▄█▄ ███   ███ ▀███▄    ▄█    ███   ███    ███   ███    ███     ███     
  ███    █▀      ███    █▀   ▀███▀███▀    ███   ▀█▀  ▄████████▀    ███    █▀     ▀██████▀     ▄████▀   
                                          ▀                                                            
                            v{VERSION} - by nuxyel
"""

# Default configuration values
DEFAULT_THREADS = 20
MAX_THREADS = 500
MIN_THREADS = 1
DEFAULT_TIMEOUT = 5
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# Common User-Agent rotation list for stealth
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
]


@dataclass
class ScanState:
    """Serializable scan state for resume capability."""
    module: str
    target: str
    wordlist: str
    completed_items: List[str] = field(default_factory=list)
    found_results: List[dict] = field(default_factory=list)
    started_at: str = field(default_factory=lambda: datetime.now().isoformat())
    last_updated: str = field(default_factory=lambda: datetime.now().isoformat())
    total_items: int = 0
    
    def save(self, filepath: str):
        """Save state to JSON file."""
        self.last_updated = datetime.now().isoformat()
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(asdict(self), f, indent=2)
    
    @classmethod
    def load(cls, filepath: str) -> Optional['ScanState']:
        """Load state from JSON file."""
        if not os.path.exists(filepath):
            return None
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return cls(**data)
        except (json.JSONDecodeError, TypeError, KeyError):
            return None
    
    def get_remaining_items(self, all_items: List[str]) -> List[str]:
        """Get items not yet completed."""
        completed_set = set(self.completed_items)
        return [item for item in all_items if item not in completed_set]
    
    def mark_completed(self, item: str):
        """Mark an item as completed."""
        if item not in self.completed_items:
            self.completed_items.append(item)
    
    def add_result(self, result: dict):
        """Add a found result."""
        self.found_results.append(result)


@dataclass
class ScanConfig:
    """Configuration for a scan operation."""
    target: str
    wordlist: str
    threads: int = DEFAULT_THREADS
    timeout: int = DEFAULT_TIMEOUT
    delay: float = 0.0
    verbose: bool = False
    output: Optional[str] = None
    json_output: bool = False
    resume: bool = False
    state_file: Optional[str] = None
    
    # DNS specific
    record_types: List[str] = field(default_factory=lambda: ['A'])
    
    # Web specific
    user_agent: str = DEFAULT_USER_AGENT
    verify_ssl: bool = True
    follow_redirects: bool = True
    status_codes: Optional[List[int]] = None  # Filter specific codes
    extensions: Optional[List[str]] = None  # Add extensions to paths
    
    # VHost specific
    base_host: Optional[str] = None
    
    def get_state_filepath(self) -> str:
        """Generate state file path."""
        if self.state_file:
            return self.state_file
        safe_target = self.target.replace('://', '_').replace('/', '_').replace('.', '_')
        return f".hawkshot_state_{safe_target}.json"
