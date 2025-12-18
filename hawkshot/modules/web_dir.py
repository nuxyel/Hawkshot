"""
HAWKSHOT Web Directory Scanning Module
Directory and file brute-force enumeration.
"""

import queue
import threading
import time
import random
from typing import List, Dict, Any, Optional

import requests
import urllib3

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from hawkshot.core.config import ScanConfig, ScanState, USER_AGENTS
from hawkshot.core.output import (
    Logger, ProgressBar, format_web_result, save_results, get_status_color
)


def load_wordlist(filepath: str) -> List[str]:
    """Load wordlist from file, stripping empty lines."""
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        return [line.strip() for line in f if line.strip()]


def expand_paths_with_extensions(paths: List[str], extensions: List[str]) -> List[str]:
    """Expand paths by adding file extensions."""
    if not extensions:
        return paths
    
    expanded = []
    for path in paths:
        expanded.append(path)  # Original path
        for ext in extensions:
            expanded.append(path + ext)
    return expanded


def dir_worker(
    base_url: str,
    work_queue: queue.Queue,
    results: List[Dict[str, Any]],
    lock: threading.Lock,
    config: ScanConfig,
    logger: Logger,
    progress: ProgressBar,
    state: Optional[ScanState] = None
):
    """Worker thread for directory scanning."""
    # Create session for connection pooling
    session = requests.Session()
    session.verify = config.verify_ssl
    session.headers['User-Agent'] = config.user_agent
    
    while True:
        try:
            path = work_queue.get(block=True, timeout=0.5)
        except queue.Empty:
            break
        
        full_url = f"{base_url}/{path}"
        
        try:
            response = session.get(
                full_url,
                timeout=config.timeout,
                allow_redirects=config.follow_redirects
            )
            
            # Filter by status codes if specified
            if config.status_codes and response.status_code not in config.status_codes:
                pass
            elif response.status_code != 404:
                # Get final URL after redirects
                final_url = response.url if response.url != full_url else None
                
                result = format_web_result(
                    full_url,
                    response.status_code,
                    len(response.content),
                    final_url
                )
                
                color = get_status_color(response.status_code)
                logger.result(result['raw'], color)
                
                with lock:
                    results.append(result)
                    if state:
                        state.add_result(result)
                        
        except requests.exceptions.Timeout:
            logger.debug(f"Timeout: {full_url}")
        except requests.exceptions.ConnectionError as e:
            logger.debug(f"Connection error: {full_url}")
        except requests.exceptions.SSLError as e:
            logger.debug(f"SSL error: {full_url}")
        except requests.exceptions.TooManyRedirects:
            logger.debug(f"Too many redirects: {full_url}")
        except requests.exceptions.RequestException as e:
            logger.debug(f"Request error: {full_url} - {type(e).__name__}")
        
        # Mark completed for resume
        with lock:
            if state:
                state.mark_completed(path)
        
        progress.update()
        
        if config.delay > 0:
            time.sleep(config.delay)
        
        work_queue.task_done()
    
    session.close()


def run_dir_scan(config: ScanConfig, logger: Logger) -> List[Dict[str, Any]]:
    """
    Execute web directory scanning.
    
    Args:
        config: Scan configuration
        logger: Logger instance
        
    Returns:
        List of found path results
    """
    # Load wordlist
    try:
        paths = load_wordlist(config.wordlist)
    except FileNotFoundError:
        logger.error(f"Wordlist not found: '{config.wordlist}'")
        return []
    except PermissionError:
        logger.error(f"Permission denied reading: '{config.wordlist}'")
        return []
    
    # Expand with extensions if specified
    if config.extensions:
        paths = expand_paths_with_extensions(paths, config.extensions)
        logger.info(f"Expanded paths with extensions: {len(paths)} total")
    
    # Check for resume state
    state = None
    scan_paths = paths
    
    if config.resume:
        state = ScanState.load(config.get_state_filepath())
        if state and state.module == 'dir' and state.target == config.target:
            scan_paths = state.get_remaining_items(paths)
            logger.info(f"Resuming scan: {len(state.completed_items)} completed, {len(scan_paths)} remaining")
        else:
            state = ScanState(
                module='dir',
                target=config.target,
                wordlist=config.wordlist,
                total_items=len(paths)
            )
    
    # Print scan info
    logger.info(f"Target URL: {config.target}")
    logger.info(f"Wordlist: {config.wordlist} ({len(paths)} entries)")
    logger.info(f"Threads: {config.threads}")
    logger.info(f"User-Agent: {config.user_agent[:50]}...")
    
    if not config.verify_ssl:
        logger.warning("SSL verification: DISABLED")
    if config.delay > 0:
        logger.info(f"Delay: {config.delay}s between requests")
    if config.status_codes:
        logger.info(f"Status filter: {config.status_codes}")
    
    logger.header("\n--- Starting Directory Scan ---\n")
    
    # Create work queue
    work_queue = queue.Queue()
    for path in scan_paths:
        work_queue.put(path)
    
    # Shared state
    results: List[Dict[str, Any]] = []
    if state:
        results = state.found_results.copy()
    lock = threading.Lock()
    
    # Progress bar
    progress = ProgressBar(len(scan_paths), prefix="Scanning")
    
    # Create and start worker threads
    threads = []
    for _ in range(config.threads):
        t = threading.Thread(
            target=dir_worker,
            args=(
                config.target,
                work_queue,
                results,
                lock,
                config,
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
            logger.warning(f"Scan interrupted. State saved to {config.get_state_filepath()}")
        raise
    
    progress.finish()
    
    # Print summary
    logger.header("\n--- Scan Finished ---")
    logger.success(f"Interesting paths found: {len(results)}")
    
    # Save results
    if config.output:
        metadata = {
            'module': 'dir_scan',
            'target': config.target,
            'wordlist': config.wordlist,
            'threads': config.threads,
            'user_agent': config.user_agent
        }
        if save_results(config.output, results, metadata, config.json_output):
            logger.success(f"Results saved to '{config.output}'")
        else:
            logger.error(f"Failed to save results to '{config.output}'")
    
    # Clean up state file
    if state and not config.resume:
        import os
        state_file = config.get_state_filepath()
        if os.path.exists(state_file):
            os.remove(state_file)
    
    return results
