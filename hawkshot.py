#!/usr/bin/env python3
import dns.resolver
import threading
import queue
import argparse
import sys
import requests
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
                            v3.0 - by r3n4n
    """
    print(colored(banner, 'cyan'))

def dns_worker(target_domain, record_types, q, found_subdomains, lock):
    while not q.empty():
        subdomain = q.get()
        full_domain = f"{subdomain}.{target_domain}"
        
        for record_type in record_types:
            try:
                resolver = dns.resolver.Resolver()
                answers = resolver.resolve(full_domain, record_type)
                for answer in answers:
                    output = f"[{record_type.ljust(4)}] {full_domain.ljust(35)} -> {answer}"
                    print(colored(output, 'green'))
                    with lock:
                        found_subdomains.append(output)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, Exception):
                pass
        q.task_done()

def run_dns_enum(args):
    try:
        with open(args.wordlist, "r", encoding='utf-8', errors='ignore') as file:
            subdomains = [line.strip() for line in file]
    except FileNotFoundError:
        print(colored(f"[-] Error: Wordlist not found at '{args.wordlist}'", 'red'))
        sys.exit(1)
    
    print(colored(f"[*] Target: {args.domain}", 'blue'))
    print(colored(f"[*] Wordlist: {args.wordlist} ({len(subdomains)} subdomains)", 'blue'))
    print(colored(f"[*] Threads: {args.threads}", 'blue'))
    print(colored(f"[*] Record Types: {', '.join(args.types)}\n", 'blue'))
    print(colored("--- Starting DNS Enumeration ---", 'magenta'))

    q = queue.Queue()
    for sub in subdomains:
        q.put(sub)
        
    found_subdomains = []
    lock = threading.Lock()
    
    for _ in range(args.threads):
        t = threading.Thread(target=dns_worker, args=(args.domain, args.types, q, found_subdomains, lock))
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

def dir_worker(base_url, q, found_paths, lock):
    while not q.empty():
        path = q.get()
        full_url = f"{base_url}/{path}"
        try:
            response = requests.get(full_url, timeout=5, verify=False, allow_redirects=True)
            if response.status_code != 404:
                output = f"[{response.status_code}] {full_url} (Length: {len(response.content)})"
                color = 'green' if response.status_code == 200 else 'yellow'
                print(colored(output, color))
                with lock:
                    found_paths.append(output)
        except requests.exceptions.RequestException:
            pass
        q.task_done()

def run_dir_scan(args):
    try:
        with open(args.wordlist, "r", encoding='utf-8', errors='ignore') as file:
            paths = [line.strip() for line in file]
    except FileNotFoundError:
        print(colored(f"[-] Error: Wordlist not found at '{args.wordlist}'", 'red'))
        sys.exit(1)

    base_url = args.url.rstrip('/')
    print(colored(f"[*] Target URL: {base_url}", 'blue'))
    print(colored(f"[*] Wordlist: {args.wordlist} ({len(paths)} paths)", 'blue'))
    print(colored(f"[*] Threads: {args.threads}\n", 'blue'))
    print(colored("--- Starting Directory Scan ---", 'magenta'))

    q = queue.Queue()
    for path in paths:
        q.put(path)

    found_paths = []
    lock = threading.Lock()

    for _ in range(args.threads):
        t = threading.Thread(target=dir_worker, args=(base_url, q, found_paths, lock))
        t.daemon = True
        t.start()
    
    q.join()

    print(colored("\n--- Scan Finished ---", 'magenta'))
    print(colored(f"[+] Interesting paths found: {len(found_paths)}", 'cyan'))

    if args.output:
        print(colored(f"[*] Saving results to '{args.output}'...", 'blue'))
        with open(args.output, 'w') as f:
            for item in sorted(found_paths):
                f.write(item + '\n')
        print(colored("[+] Results saved successfully!", 'green'))

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(
        description="HAWKSHOT v3.0 - A Multi-purpose Recon Tool",
        formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(dest='command', help='Available commands', required=True)

    parser_enum = subparsers.add_parser('enum', help='DNS Subdomain Enumeration')
    parser_enum.add_argument("domain", help="The target domain (e.g., google.com)")
    parser_enum.add_argument("wordlist", help="Path to the subdomain wordlist")
    parser_enum.add_argument("-t", "--threads", type=int, default=20, help="Number of threads (default: 20)")
    parser_enum.add_argument("-T", "--types", nargs='+', default=['A'], help="Record types to query (default: A)")
    parser_enum.add_argument("-o", "--output", help="Save the found results to an output file")

    parser_dir = subparsers.add_parser('dir', help='Web Directory & File Scanning')
    parser_dir.add_argument("url", help="The target base URL (e.g., http://example.com)")
    parser_dir.add_argument("wordlist", help="Path to the directory/file wordlist")
    parser_dir.add_argument("-t", "--threads", type=int, default=20, help="Number of threads (default: 20)")
    parser_dir.add_argument("-o", "--output", help="Save the found results to an output file")

    args = parser.parse_args()
    
    if args.command == 'enum':
        run_dns_enum(args)
    elif args.command == 'dir':
        run_dir_scan(args)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(colored("\n[!] Program interrupted by user.", 'red'))
        sys.exit(0)
