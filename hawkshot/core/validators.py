"""
HAWKSHOT Input Validators
Validation functions for CLI arguments.
"""

import re
import os
import argparse
from typing import List


def validate_domain(domain: str) -> str:
    """
    Validate and normalize domain input.
    
    Args:
        domain: Domain string to validate
        
    Returns:
        Normalized domain string
        
    Raises:
        argparse.ArgumentTypeError: If domain is invalid
    """
    # Remove protocol if present
    domain = re.sub(r'^https?://', '', domain)
    # Remove trailing slashes and paths
    domain = domain.split('/')[0]
    # Remove port if present
    domain = domain.split(':')[0]
    # Remove www. prefix for consistency
    domain = re.sub(r'^www\.', '', domain)
    
    # Basic domain validation pattern
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
    
    if not re.match(pattern, domain):
        raise argparse.ArgumentTypeError(f"Invalid domain format: '{domain}'")
    
    return domain.lower()


def validate_url(url: str) -> str:
    """
    Validate and normalize URL input.
    
    Args:
        url: URL string to validate
        
    Returns:
        Normalized URL string (without trailing slash)
        
    Raises:
        argparse.ArgumentTypeError: If URL is invalid
    """
    # Add http:// if no scheme present
    if not re.match(r'^https?://', url):
        url = f"http://{url}"
    
    # Basic URL structure validation
    pattern = r'^https?://[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*'
    
    if not re.match(pattern, url):
        raise argparse.ArgumentTypeError(f"Invalid URL format: '{url}'")
    
    return url.rstrip('/')


def validate_threads(value: str) -> int:
    """
    Validate thread count within safe bounds.
    
    Args:
        value: Thread count string
        
    Returns:
        Validated thread count integer
        
    Raises:
        argparse.ArgumentTypeError: If thread count is invalid
    """
    try:
        ivalue = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"Threads must be an integer, got: '{value}'")
    
    from hawkshot.core.config import MIN_THREADS, MAX_THREADS
    
    if not MIN_THREADS <= ivalue <= MAX_THREADS:
        raise argparse.ArgumentTypeError(
            f"Threads must be between {MIN_THREADS}-{MAX_THREADS}, got: {ivalue}"
        )
    
    return ivalue


def validate_delay(value: str) -> float:
    """
    Validate delay value.
    
    Args:
        value: Delay string (seconds)
        
    Returns:
        Validated delay float
        
    Raises:
        argparse.ArgumentTypeError: If delay is invalid
    """
    try:
        fvalue = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"Delay must be a number, got: '{value}'")
    
    if fvalue < 0:
        raise argparse.ArgumentTypeError(f"Delay cannot be negative, got: {fvalue}")
    
    if fvalue > 60:
        raise argparse.ArgumentTypeError(f"Delay too large (max 60s), got: {fvalue}")
    
    return fvalue


def validate_wordlist(path: str) -> str:
    """
    Validate wordlist file exists and is readable.
    
    Args:
        path: Path to wordlist file
        
    Returns:
        Validated path string
        
    Raises:
        argparse.ArgumentTypeError: If file doesn't exist or isn't readable
    """
    if not os.path.exists(path):
        raise argparse.ArgumentTypeError(f"Wordlist not found: '{path}'")
    
    if not os.path.isfile(path):
        raise argparse.ArgumentTypeError(f"Wordlist is not a file: '{path}'")
    
    if not os.access(path, os.R_OK):
        raise argparse.ArgumentTypeError(f"Wordlist not readable: '{path}'")
    
    return path


def validate_output(path: str) -> str:
    """
    Validate output file path is writable.
    
    Args:
        path: Path to output file
        
    Returns:
        Validated path string
        
    Raises:
        argparse.ArgumentTypeError: If path is not writable
    """
    directory = os.path.dirname(path) or '.'
    
    if not os.path.exists(directory):
        raise argparse.ArgumentTypeError(f"Output directory doesn't exist: '{directory}'")
    
    if not os.access(directory, os.W_OK):
        raise argparse.ArgumentTypeError(f"Output directory not writable: '{directory}'")
    
    return path


def validate_record_types(types: List[str]) -> List[str]:
    """
    Validate DNS record types.
    
    Args:
        types: List of record type strings
        
    Returns:
        Validated and uppercased list
        
    Raises:
        argparse.ArgumentTypeError: If any type is invalid
    """
    valid_types = {'A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'PTR', 'SRV', 'CAA'}
    
    result = []
    for t in types:
        upper_t = t.upper()
        if upper_t not in valid_types:
            raise argparse.ArgumentTypeError(
                f"Invalid record type: '{t}'. Valid types: {', '.join(sorted(valid_types))}"
            )
        result.append(upper_t)
    
    return result


def validate_status_codes(codes: str) -> List[int]:
    """
    Validate and parse status code filter.
    
    Args:
        codes: Comma-separated status codes (e.g., "200,301,403")
        
    Returns:
        List of status code integers
        
    Raises:
        argparse.ArgumentTypeError: If any code is invalid
    """
    result = []
    for code in codes.split(','):
        code = code.strip()
        try:
            icode = int(code)
            if not 100 <= icode <= 599:
                raise argparse.ArgumentTypeError(
                    f"Status code out of range: {icode} (must be 100-599)"
                )
            result.append(icode)
        except ValueError:
            raise argparse.ArgumentTypeError(f"Invalid status code: '{code}'")
    
    return result


def validate_extensions(extensions: str) -> List[str]:
    """
    Validate and parse file extensions.
    
    Args:
        extensions: Comma-separated extensions (e.g., "php,html,txt")
        
    Returns:
        List of extensions with leading dots
    """
    result = []
    for ext in extensions.split(','):
        ext = ext.strip().lower()
        if ext:
            # Ensure dot prefix
            if not ext.startswith('.'):
                ext = '.' + ext
            result.append(ext)
    return result
