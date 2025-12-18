"""
HAWKSHOT Output Utilities
Colored output, progress bar, and file export functions.
"""

import sys
import json
import threading
from datetime import datetime
from typing import List, Dict, Any, Optional

# Cross-platform color support
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLORS = {
        'cyan': Fore.CYAN,
        'green': Fore.GREEN,
        'red': Fore.RED,
        'blue': Fore.BLUE,
        'magenta': Fore.MAGENTA,
        'yellow': Fore.YELLOW,
        'white': Fore.WHITE,
        'reset': Style.RESET_ALL
    }
    HAS_COLORS = True
except ImportError:
    try:
        from termcolor import colored as _termcolor_colored
        def colored(text: str, color: str) -> str:
            return _termcolor_colored(text, color)
        HAS_COLORS = True
    except ImportError:
        HAS_COLORS = False
        COLORS = None
else:
    def colored(text: str, color: str) -> str:
        return f"{COLORS.get(color, '')}{text}{COLORS['reset']}"

if not HAS_COLORS:
    def colored(text: str, color: str) -> str:
        return text


class Logger:
    """Thread-safe logger with verbosity control."""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self._lock = threading.Lock()
    
    def _print(self, message: str):
        """Thread-safe print."""
        with self._lock:
            print(message)
            sys.stdout.flush()
    
    def info(self, message: str):
        """Print info message (blue)."""
        self._print(colored(f"[*] {message}", 'blue'))
    
    def success(self, message: str):
        """Print success message (green)."""
        self._print(colored(f"[+] {message}", 'green'))
    
    def warning(self, message: str):
        """Print warning message (yellow)."""
        self._print(colored(f"[!] {message}", 'yellow'))
    
    def error(self, message: str):
        """Print error message (red)."""
        self._print(colored(f"[-] {message}", 'red'))
    
    def debug(self, message: str):
        """Print debug message if verbose (yellow)."""
        if self.verbose:
            self._print(colored(f"[DEBUG] {message}", 'yellow'))
    
    def result(self, message: str, color: str = 'green'):
        """Print a scan result."""
        self._print(colored(message, color))
    
    def banner(self, text: str):
        """Print banner (cyan)."""
        self._print(colored(text, 'cyan'))
    
    def header(self, text: str):
        """Print section header (magenta)."""
        self._print(colored(text, 'magenta'))


class ProgressBar:
    """Thread-safe progress bar for scan operations."""
    
    def __init__(self, total: int, prefix: str = "Progress", width: int = 40):
        self.total = total
        self.current = 0
        self.prefix = prefix
        self.width = width
        self._lock = threading.Lock()
        self._last_percent = -1
    
    def update(self, amount: int = 1):
        """Update progress by amount."""
        with self._lock:
            self.current += amount
            self._render()
    
    def set(self, value: int):
        """Set progress to specific value."""
        with self._lock:
            self.current = value
            self._render()
    
    def _render(self):
        """Render progress bar to terminal."""
        if self.total == 0:
            return
        
        percent = int((self.current / self.total) * 100)
        
        # Only update if percent changed (reduce flicker)
        if percent == self._last_percent:
            return
        self._last_percent = percent
        
        filled = int(self.width * self.current / self.total)
        bar = '█' * filled + '░' * (self.width - filled)
        
        # Use carriage return to overwrite line
        line = f"\r{self.prefix}: [{bar}] {percent}% ({self.current}/{self.total})"
        sys.stdout.write(line)
        sys.stdout.flush()
    
    def finish(self):
        """Complete progress bar and move to new line."""
        with self._lock:
            self.current = self.total
            self._render()
            print()  # New line


def save_results(
    output_file: str,
    results: List[Dict[str, Any]],
    metadata: Dict[str, Any],
    json_format: bool = False
) -> bool:
    """
    Save results to file with metadata.
    
    Args:
        output_file: Path to output file
        results: List of result dictionaries
        metadata: Scan metadata dictionary
        json_format: If True, save as JSON instead of text
    
    Returns:
        True if successful, False otherwise
    """
    try:
        if json_format:
            # JSON output
            output_data = {
                'metadata': {
                    'tool': 'hawkshot',
                    'version': '4.0.0',
                    'timestamp': datetime.now().isoformat(),
                    **metadata
                },
                'results': results,
                'total_count': len(results)
            }
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)
        else:
            # Text output with metadata header
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("# HAWKSHOT Scan Results\n")
                f.write(f"# Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                for key, value in metadata.items():
                    f.write(f"# {key}: {value}\n")
                f.write(f"# Total results: {len(results)}\n")
                f.write("#" + "=" * 60 + "\n\n")
                
                for item in sorted(results, key=lambda x: x.get('raw', str(x))):
                    f.write(item.get('raw', str(item)) + '\n')
        
        return True
    except PermissionError:
        return False
    except Exception:
        return False


def format_dns_result(subdomain: str, record_type: str, value: str) -> Dict[str, Any]:
    """Format a DNS enumeration result."""
    raw = f"[{record_type.ljust(5)}] {subdomain.ljust(40)} -> {value}"
    return {
        'subdomain': subdomain,
        'type': record_type,
        'value': value,
        'raw': raw
    }


def format_web_result(
    url: str,
    status_code: int,
    content_length: int,
    redirect_url: Optional[str] = None
) -> Dict[str, Any]:
    """Format a web scanning result."""
    raw = f"[{status_code}] {url} (Length: {content_length})"
    if redirect_url and redirect_url != url:
        raw += f" -> {redirect_url}"
    return {
        'url': url,
        'status': status_code,
        'length': content_length,
        'redirect': redirect_url,
        'raw': raw
    }


def format_vhost_result(vhost: str, status_code: int, content_length: int) -> Dict[str, Any]:
    """Format a VHost enumeration result."""
    raw = f"[{status_code}] {vhost} (Length: {content_length})"
    return {
        'vhost': vhost,
        'status': status_code,
        'length': content_length,
        'raw': raw
    }


def format_tech_result(url: str, technology: str, version: Optional[str] = None) -> Dict[str, Any]:
    """Format a technology detection result."""
    version_str = f" v{version}" if version else ""
    raw = f"[TECH] {technology}{version_str} @ {url}"
    return {
        'url': url,
        'technology': technology,
        'version': version,
        'raw': raw
    }


def get_status_color(status_code: int) -> str:
    """Get color for HTTP status code."""
    if 200 <= status_code < 300:
        return 'green'
    elif 300 <= status_code < 400:
        return 'cyan'
    elif 400 <= status_code < 500:
        return 'yellow'
    elif 500 <= status_code < 600:
        return 'red'
    else:
        return 'white'
