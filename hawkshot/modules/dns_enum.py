"""
HAWKSHOT DNS Enumeration Module
Subdomain enumeration via DNS brute-force.
"""

import queue
import threading
import time
from typing import List, Dict, Any, Optional

import dns.resolver
import dns.exception

from hawkshot.core.config import ScanConfig, ScanState
from hawkshot.core.output import (
    Logger, ProgressBar, format_dns_result, save_results
)


def load_wordlist(filepath: str) -> List[str]:
    """Load wordlist from file, stripping empty lines."""
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        return [line.strip() for line in f if line.strip()]


def create_resolver(timeout: int = 3) -> dns.resolver.Resolver:
    """Create a DNS resolver with appropriate settings."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    return resolver


def dns_worker(
    target_domain: str,
    record_types: List[str],
    work_queue: queue.Queue,
    results: List[Dict[str, Any]],
    lock: threading.Lock,
    resolver: dns.resolver.Resolver,
    delay: float,
    logger: Logger,
    progress: ProgressBar,
    state: Optional[ScanState] = None
):
    """Worker thread for DNS enumeration."""
    while True:
        try:
            subdomain = work_queue.get(block=True, timeout=0.5)
        except queue.Empty:
            break
        
        full_domain = f"{subdomain}.{target_domain}"
        
        for record_type in record_types:
            try:
                answers = resolver.resolve(full_domain, record_type)
                for answer in answers:
                    result = format_dns_result(full_domain, record_type, str(answer))
                    logger.result(result['raw'], 'green')
                    with lock:
                        results.append(result)
                        if state:
                            state.add_result(result)
            except dns.resolver.NXDOMAIN:
                logger.debug(f"NXDOMAIN: {full_domain}")
            except dns.resolver.NoAnswer:
                logger.debug(f"NoAnswer for {record_type}: {full_domain}")
            except dns.resolver.Timeout:
                logger.debug(f"Timeout: {full_domain}")
            except dns.resolver.NoNameservers:
                logger.debug(f"NoNameservers: {full_domain}")
            except dns.exception.DNSException as e:
                logger.debug(f"DNS error for {full_domain}: {type(e).__name__}")
            except Exception as e:
                logger.debug(f"Error resolving {full_domain}: {type(e).__name__}: {e}")
        
        # Mark completed for resume capability
        with lock:
            if state:
                state.mark_completed(subdomain)
        
        progress.update()
        
        if delay > 0:
            time.sleep(delay)
        
        work_queue.task_done()


def run_dns_enum(config: ScanConfig, logger: Logger) -> List[Dict[str, Any]]:
    """
    Execute DNS subdomain enumeration.
    
    Args:
        config: Scan configuration
        logger: Logger instance
        
    Returns:
        List of found subdomain results
    """
    # Load wordlist
    try:
        all_subdomains = load_wordlist(config.wordlist)
    except FileNotFoundError:
        logger.error(f"Wordlist not found: '{config.wordlist}'")
        return []
    except PermissionError:
        logger.error(f"Permission denied reading: '{config.wordlist}'")
        return []
    
    # Check for resume state
    state = None
    subdomains = all_subdomains
    
    if config.resume:
        state = ScanState.load(config.get_state_filepath())
        if state and state.module == 'dns' and state.target == config.target:
            subdomains = state.get_remaining_items(all_subdomains)
            logger.info(f"Resuming scan: {len(state.completed_items)} completed, {len(subdomains)} remaining")
        else:
            state = ScanState(
                module='dns',
                target=config.target,
                wordlist=config.wordlist,
                total_items=len(all_subdomains)
            )
    
    # Print scan info
    logger.info(f"Target: {config.target}")
    logger.info(f"Wordlist: {config.wordlist} ({len(all_subdomains)} entries)")
    logger.info(f"Threads: {config.threads}")
    logger.info(f"Record Types: {', '.join(config.record_types)}")
    if config.delay > 0:
        logger.info(f"Delay: {config.delay}s between requests")
    
    logger.header("\n--- Starting DNS Enumeration ---\n")
    
    # Create work queue
    work_queue = queue.Queue()
    for sub in subdomains:
        work_queue.put(sub)
    
    # Shared state
    results: List[Dict[str, Any]] = []
    if state:
        results = state.found_results.copy()
    lock = threading.Lock()
    
    # Create reusable resolver
    resolver = create_resolver(config.timeout)
    
    # Progress bar
    progress = ProgressBar(len(subdomains), prefix="Scanning")
    
    # Create and start worker threads
    threads = []
    for _ in range(config.threads):
        t = threading.Thread(
            target=dns_worker,
            args=(
                config.target,
                config.record_types,
                work_queue,
                results,
                lock,
                resolver,
                config.delay,
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
        # Save state on interrupt
        if state:
            state.save(config.get_state_filepath())
            logger.warning(f"Scan interrupted. State saved to {config.get_state_filepath()}")
        raise
    
    progress.finish()
    
    # Print summary
    unique_subdomains = len(set(r['subdomain'] for r in results))
    logger.header("\n--- Scan Finished ---")
    logger.success(f"Unique subdomains found: {unique_subdomains}")
    logger.success(f"Total records found: {len(results)}")
    
    # Save results
    if config.output:
        metadata = {
            'module': 'dns_enum',
            'target': config.target,
            'wordlist': config.wordlist,
            'threads': config.threads,
            'record_types': config.record_types
        }
        if save_results(config.output, results, metadata, config.json_output):
            logger.success(f"Results saved to '{config.output}'")
        else:
            logger.error(f"Failed to save results to '{config.output}'")
    
    # Clean up state file on successful completion
    if state and not config.resume:
        import os
        state_file = config.get_state_filepath()
        if os.path.exists(state_file):
            os.remove(state_file)
    
    return results
