#!/usr/bin/env python3
import dns.resolver
import threading
import queue
import argparse
import sys
from termcolor import colored

def print_banner():
    banner = """
   ▄█    █▄       ▄████████  ▄█     █▄     ▄█   ▄█▄    ▄████████    ▄█    █▄     ▄██████▄      ███     
  ███    ███     ███    ███ ███     ███   ███ ▄███▀   ███    ███   ███    ███   ███    ███ ▀█████████▄ 
  ███    ███     ███    ███ ███     ███   ███▐██▀     ███    █▀    ███    ███   ███    ███    ▀███▀▀██ 
 ▄███▄▄▄▄███▄▄   ███    ███ ███     ███  ▄█████▀      ███         ▄███▄▄▄▄███▄▄ ███    ███     ███   ▀ 
▀▀███▀▀▀▀███▀  ▀███████████ ███     ███ ▀▀█████▄    ▀███████████ ▀▀███▀▀▀▀███▀  ███    ███     ███     
  ███    ███     ███    ███ ███     ███   ███▐██▄            ███   ███    ███   ███    ███     ███     
  ███    ███     ███    ███ ███ ▄█▄ ███   ███ ▀███▄    ▄█    ███   ███    ███   ███    ███     ███     
  ███    █▀      ███    █▀   ▀███▀███▀    ███   ▀█▀  ▄████████▀    ███    █▀     ▀██████▀     ▄████▀   
                                          ▀                                                            
                            v2.7 - by r3n4n
    """
    print(colored(banner, 'magenta'))

def worker(target_domain, record_types, q, found_subdomains, lock):
    while not q.empty():
        subdomain = q.get()
        full_domain = f"{subdomain}.{target_domain}"
        
        for record_type in record_types:
            try:
                resolver = dns.resolver.Resolver()
                answers = resolver.resolve(full_domain, record_type)
                for answer in answers:
                    output = f"[{record_type.ljust(4)}] {full_domain.ljust(30)} -> {answer}"
                    print(colored(output, 'green'))
                    with lock:
                        found_subdomains.append(output)
            except dns.resolver.NXDOMAIN:
                pass
            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.Timeout:
                print(colored(f"[TIMEOUT] {full_domain}", 'yellow'))
            except Exception:
                pass
        q.task_done()

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(description="HAWKSHOT - A fast DNS subdomain brute-force tool")
    parser.add_argument("domain", help="The target domain (e.g., google.com)")
    parser.add_argument("wordlist", help="Path to the subdomain wordlist")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Number of threads (default: 20)")
    parser.add_argument("-T", "--types", nargs='+', default=['A'], help="Record types to query (default: A)")
    parser.add_argument("-o", "--output", help="Save the found results to an output file")
    
    args = parser.parse_args()

    try:
        with open(args.wordlist, "r") as file:
            subdomains = [line.strip() for line in file]
    except FileNotFoundError:
        print(colored(f"[-] Error: Wordlist not found at '{args.wordlist}'", 'red'))
        sys.exit(1)
    
    print(colored(f"[*] Target: {args.domain}", 'blue'))
    print(colored(f"[*] Wordlist: {args.wordlist} ({len(subdomains)} subdomains)", 'blue'))
    print(colored(f"[*] Threads: {args.threads}", 'blue'))
    print(colored(f"[*] Record Types: {', '.join(args.types)}\n", 'blue'))
    print(colored("--- Starting Scan ---", 'magenta'))

    q = queue.Queue()
    for sub in subdomains:
        q.put(sub)
        
    found_subdomains = []
    lock = threading.Lock()
    
    for _ in range(args.threads):
        t = threading.Thread(target=worker, args=(args.domain, args.types, q, found_subdomains, lock))
        t.daemon = True
        t.start()

    q.join()
    
    print(colored("\n--- Scan Finished ---", 'magenta'))
    print(colored(f"[+] Subdomains found: {len(found_subdomains)}", 'cyan'))

    if args.output:
        print(colored(f"[*] Saving results to '{args.output}'...", 'blue'))
        with open(args.output, 'w') as f:
            for item in sorted(found_subdomains):
                f.write(item + '\n')
        print(colored("[+] Results saved successfully!", 'green'))

if __name__ == "__main__":
    main()
