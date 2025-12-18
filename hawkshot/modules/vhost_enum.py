"""
HAWKSHOT VHost Enumeration Module
Virtual host enumeration via Host header manipulation.
"""

import queue
import threading
import time
from typing import List, Dict, Any, Optional

import requests
import urllib3

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from hawkshot.core.config import ScanConfig, ScanState
from hawkshot.core.output import (
    Logger, ProgressBar, format_vhost_result, save_results, get_status_color
)


def load_wordlist(filepath: str) -> List[str]:
    """Load wordlist from file, stripping empty lines."""
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        return [line.strip() for line in f if line.strip()]


def get_baseline_response(url: str, config: ScanConfig) -> Optional[tuple]:
    """
    Get baseline response for comparison.
    
    Returns:
        Tuple of (status_code, content_length) or None if failed
    """
    try:
        response = requests.get(
            url,
            timeout=config.timeout,
            verify=config.verify_ssl,
            headers={'User-Agent': config.user_agent}
        )
        return (response.status_code, len(response.content))
    except requests.exceptions.RequestException:
        return None


def vhost_worker(
    base_url: str,
    base_host: str,
    work_queue: queue.Queue,
    results: List[Dict[str, Any]],
    lock: threading.Lock,
    config: ScanConfig,
    baseline: tuple,
    logger: Logger,
    progress: ProgressBar,
    state: Optional[ScanState] = None
):
    """Worker thread for VHost enumeration."""
    session = requests.Session()
    session.verify = config.verify_ssl
    
    baseline_status, baseline_length = baseline
    
    while True:
        try:
            vhost_prefix = work_queue.get(block=True, timeout=0.5)
        except queue.Empty:
            break
        
        # Build the virtual host
        vhost = f"{vhost_prefix}.{base_host}"
        
        try:
            response = session.get(
                base_url,
                timeout=config.timeout,
                headers={
                    'Host': vhost,
                    'User-Agent': config.user_agent
                }
            )
            
            # Compare with baseline to detect different vhosts
            content_length = len(response.content)
            
            # Consider it a hit if:
            # 1. Status code is different from baseline
            # 2. Content length differs significantly (>10% difference)
            is_different = (
                response.status_code != baseline_status or
                abs(content_length - baseline_length) > baseline_length * 0.1
            )
            
            if is_different and response.status_code != 404:
                result = format_vhost_result(vhost, response.status_code, content_length)
                color = get_status_color(response.status_code)
                logger.result(result['raw'], color)
                
                with lock:
                    results.append(result)
                    if state:
                        state.add_result(result)
                        
        except requests.exceptions.Timeout:
            logger.debug(f"Timeout: {vhost}")
        except requests.exceptions.ConnectionError:
            logger.debug(f"Connection error: {vhost}")
        except requests.exceptions.RequestException as e:
            logger.debug(f"Request error for {vhost}: {type(e).__name__}")
        
        with lock:
            if state:
                state.mark_completed(vhost_prefix)
        
        progress.update()
        
        if config.delay > 0:
            time.sleep(config.delay)
        
        work_queue.task_done()
    
    session.close()


def run_vhost_enum(config: ScanConfig, logger: Logger) -> List[Dict[str, Any]]:
    """
    Execute virtual host enumeration.
    
    Args:
        config: Scan configuration (target should be IP/URL, base_host is the domain)
        logger: Logger instance
        
    Returns:
        List of found vhost results
    """
    if not config.base_host:
        logger.error("VHost enumeration requires --host parameter (base domain)")
        return []
    
    # Load wordlist
    try:
        vhosts = load_wordlist(config.wordlist)
    except FileNotFoundError:
        logger.error(f"Wordlist not found: '{config.wordlist}'")
        return []
    except PermissionError:
        logger.error(f"Permission denied reading: '{config.wordlist}'")
        return []
    
    # Get baseline response
    logger.info("Getting baseline response...")
    baseline = get_baseline_response(config.target, config)
    if not baseline:
        logger.error(f"Could not connect to target: {config.target}")
        return []
    
    logger.info(f"Baseline: Status {baseline[0]}, Length {baseline[1]}")
    
    # Check for resume state
    state = None
    scan_vhosts = vhosts
    
    if config.resume:
        state = ScanState.load(config.get_state_filepath())
        if state and state.module == 'vhost' and state.target == config.target:
            scan_vhosts = state.get_remaining_items(vhosts)
            logger.info(f"Resuming: {len(state.completed_items)} done, {len(scan_vhosts)} remaining")
        else:
            state = ScanState(
                module='vhost',
                target=config.target,
                wordlist=config.wordlist,
                total_items=len(vhosts)
            )
    
    # Print scan info
    logger.info(f"Target: {config.target}")
    logger.info(f"Base Host: {config.base_host}")
    logger.info(f"Wordlist: {config.wordlist} ({len(vhosts)} entries)")
    logger.info(f"Threads: {config.threads}")
    
    if not config.verify_ssl:
        logger.warning("SSL verification: DISABLED")
    if config.delay > 0:
        logger.info(f"Delay: {config.delay}s between requests")
    
    logger.header("\n--- Starting VHost Enumeration ---\n")
    
    # Create work queue
    work_queue = queue.Queue()
    for vhost in scan_vhosts:
        work_queue.put(vhost)
    
    # Shared state
    results: List[Dict[str, Any]] = []
    if state:
        results = state.found_results.copy()
    lock = threading.Lock()
    
    # Progress bar
    progress = ProgressBar(len(scan_vhosts), prefix="Scanning")
    
    # Create and start worker threads
    threads = []
    for _ in range(config.threads):
        t = threading.Thread(
            target=vhost_worker,
            args=(
                config.target,
                config.base_host,
                work_queue,
                results,
                lock,
                config,
                baseline,
                logger,
                progress,
                state
            )
        )
        t.daemon = True
        t.start()
        threads.append(t)
    
    # Wait for completion
    try:
        work_queue.join()
    except KeyboardInterrupt:
        if state:
            state.save(config.get_state_filepath())
            logger.warning(f"Scan interrupted. State saved.")
        raise
    
    progress.finish()
    
    # Print summary
    logger.header("\n--- Scan Finished ---")
    logger.success(f"Virtual hosts found: {len(results)}")
    
    # Save results
    if config.output:
        metadata = {
            'module': 'vhost_enum',
            'target': config.target,
            'base_host': config.base_host,
            'wordlist': config.wordlist,
            'threads': config.threads
        }
        if save_results(config.output, results, metadata, config.json_output):
            logger.success(f"Results saved to '{config.output}'")
        else:
            logger.error(f"Failed to save results")
    
    return results
