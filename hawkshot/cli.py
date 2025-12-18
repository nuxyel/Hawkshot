#!/usr/bin/env python3
"""
HAWKSHOT CLI Module
Command-line interface with argparse subcommands.
"""

import sys
import argparse

from hawkshot.core.config import VERSION, BANNER, ScanConfig, DEFAULT_USER_AGENT
from hawkshot.core.output import Logger, colored
from hawkshot.core.validators import (
    validate_domain,
    validate_url,
    validate_threads,
    validate_delay,
    validate_wordlist,
    validate_record_types,
    validate_status_codes,
    validate_extensions
)


def add_common_arguments(parser: argparse.ArgumentParser):
    """Add arguments common to all scan modules."""
    parser.add_argument(
        "wordlist",
        type=validate_wordlist,
        help="Path to wordlist file"
    )
    parser.add_argument(
        "-t", "--threads",
        type=validate_threads,
        default=20,
        help="Number of threads (1-500, default: 20)"
    )
    parser.add_argument(
        "-o", "--output",
        help="Save results to output file"
    )
    parser.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        help="Output results in JSON format"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose/debug output"
    )
    parser.add_argument(
        "--delay",
        type=validate_delay,
        default=0,
        help="Delay between requests in seconds (default: 0)"
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume interrupted scan from state file"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=5,
        help="Request timeout in seconds (default: 5)"
    )


def add_web_arguments(parser: argparse.ArgumentParser):
    """Add arguments common to web-based modules."""
    parser.add_argument(
        "-ua", "--user-agent",
        default=DEFAULT_USER_AGENT,
        help="Custom User-Agent header"
    )
    parser.add_argument(
        "--no-verify",
        dest="verify_ssl",
        action="store_false",
        default=True,
        help="Disable SSL certificate verification"
    )


def create_parser() -> argparse.ArgumentParser:
    """Create the main argument parser with subcommands."""
    parser = argparse.ArgumentParser(
        prog="hawkshot",
        description=f"HAWKSHOT v{VERSION} - A Multi-purpose Recon Tool",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  hawkshot enum example.com wordlist.txt -t 50 -T A AAAA CNAME
  hawkshot dir http://example.com wordlist.txt -t 30 --delay 0.1
  hawkshot vhost http://10.10.10.10 wordlist.txt --host example.com
  hawkshot tech http://example.com

Use 'hawkshot <command> --help' for detailed options.
        """
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"HAWKSHOT v{VERSION}"
    )
    
    subparsers = parser.add_subparsers(
        dest='command',
        title='Available Commands',
        required=True
    )
    
    # ===== DNS Enumeration =====
    parser_enum = subparsers.add_parser(
        'enum',
        help='DNS Subdomain Enumeration',
        description='Enumerate subdomains via DNS brute-force'
    )
    parser_enum.add_argument(
        "domain",
        type=validate_domain,
        help="Target domain (e.g., example.com)"
    )
    add_common_arguments(parser_enum)
    parser_enum.add_argument(
        "-T", "--types",
        nargs='+',
        default=['A'],
        help="DNS record types to query (default: A). Valid: A, AAAA, CNAME, MX, NS, TXT, SOA, PTR, SRV, CAA"
    )
    
    # ===== Directory Scanning =====
    parser_dir = subparsers.add_parser(
        'dir',
        help='Web Directory & File Scanning',
        description='Scan for hidden directories and files'
    )
    parser_dir.add_argument(
        "url",
        type=validate_url,
        help="Target base URL (e.g., http://example.com)"
    )
    add_common_arguments(parser_dir)
    add_web_arguments(parser_dir)
    parser_dir.add_argument(
        "--no-redirect",
        dest="follow_redirects",
        action="store_false",
        default=True,
        help="Don't follow HTTP redirects"
    )
    parser_dir.add_argument(
        "-x", "--extensions",
        type=validate_extensions,
        help="Extensions to append (e.g., php,html,txt)"
    )
    parser_dir.add_argument(
        "-s", "--status-codes",
        type=validate_status_codes,
        help="Only show these status codes (e.g., 200,301,403)"
    )
    
    # ===== VHost Enumeration =====
    parser_vhost = subparsers.add_parser(
        'vhost',
        help='Virtual Host Enumeration',
        description='Enumerate virtual hosts via Host header manipulation'
    )
    parser_vhost.add_argument(
        "url",
        type=validate_url,
        help="Target URL/IP (e.g., http://10.10.10.10)"
    )
    add_common_arguments(parser_vhost)
    add_web_arguments(parser_vhost)
    parser_vhost.add_argument(
        "--host",
        dest="base_host",
        required=True,
        help="Base domain for vhost generation (e.g., example.com)"
    )
    
    # ===== Technology Detection =====
    parser_tech = subparsers.add_parser(
        'tech',
        help='Technology Detection',
        description='Detect technologies, frameworks, and CMS'
    )
    parser_tech.add_argument(
        "url",
        type=validate_url,
        help="Target URL (e.g., http://example.com)"
    )
    parser_tech.add_argument(
        "-l", "--list",
        dest="url_list",
        help="File containing list of URLs to scan"
    )
    parser_tech.add_argument(
        "-o", "--output",
        help="Save results to output file"
    )
    parser_tech.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        help="Output results in JSON format"
    )
    parser_tech.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose/debug output"
    )
    parser_tech.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)"
    )
    add_web_arguments(parser_tech)
    
    return parser


def build_config(args) -> ScanConfig:
    """Build ScanConfig from parsed arguments."""
    config = ScanConfig(
        target=getattr(args, 'domain', None) or getattr(args, 'url', ''),
        wordlist=getattr(args, 'wordlist', '') or getattr(args, 'url_list', ''),
        threads=getattr(args, 'threads', 20),
        timeout=getattr(args, 'timeout', 5),
        delay=getattr(args, 'delay', 0),
        verbose=getattr(args, 'verbose', False),
        output=getattr(args, 'output', None),
        json_output=getattr(args, 'json_output', False),
        resume=getattr(args, 'resume', False),
        record_types=getattr(args, 'types', ['A']),
        user_agent=getattr(args, 'user_agent', DEFAULT_USER_AGENT),
        verify_ssl=getattr(args, 'verify_ssl', True),
        follow_redirects=getattr(args, 'follow_redirects', True),
        status_codes=getattr(args, 'status_codes', None),
        extensions=getattr(args, 'extensions', None),
        base_host=getattr(args, 'base_host', None),
    )
    return config


def main():
    """Main entry point."""
    # Print banner
    print(colored(BANNER, 'cyan'))
    
    # Parse arguments
    parser = create_parser()
    args = parser.parse_args()
    
    # Validate record types for enum
    if args.command == 'enum':
        args.types = validate_record_types(args.types)
    
    # Build configuration
    config = build_config(args)
    
    # Create logger
    logger = Logger(verbose=config.verbose)
    
    try:
        if args.command == 'enum':
            from hawkshot.modules.dns_enum import run_dns_enum
            run_dns_enum(config, logger)
        
        elif args.command == 'dir':
            from hawkshot.modules.web_dir import run_dir_scan
            run_dir_scan(config, logger)
        
        elif args.command == 'vhost':
            from hawkshot.modules.vhost_enum import run_vhost_enum
            run_vhost_enum(config, logger)
        
        elif args.command == 'tech':
            from hawkshot.modules.tech_detect import run_tech_detect
            run_tech_detect(config, logger)
    
    except KeyboardInterrupt:
        logger.warning("Program interrupted by user.")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error: {type(e).__name__}: {e}")
        if config.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
