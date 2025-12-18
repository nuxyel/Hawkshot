"""
HAWKSHOT Technology Detection Module
Identify technologies, frameworks, and CMS from HTTP responses.
"""

import re
import queue
import threading
from typing import List, Dict, Any, Optional, Set

import requests
import urllib3

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from hawkshot.core.config import ScanConfig
from hawkshot.core.output import Logger, format_tech_result, save_results


# Technology fingerprints database
# Format: (name, pattern, location, version_regex)
FINGERPRINTS = [
    # Web Servers
    ('Apache', r'Apache(?:/(\d+\.\d+(?:\.\d+)?))?', 'header:Server', r'Apache/(\d+\.\d+(?:\.\d+)?)'),
    ('Nginx', r'nginx(?:/(\d+\.\d+(?:\.\d+)?))?', 'header:Server', r'nginx/(\d+\.\d+(?:\.\d+)?)'),
    ('IIS', r'Microsoft-IIS(?:/(\d+\.\d+))?', 'header:Server', r'IIS/(\d+\.\d+)'),
    ('LiteSpeed', r'LiteSpeed', 'header:Server', None),
    ('Caddy', r'Caddy', 'header:Server', None),
    
    # Programming Languages
    ('PHP', r'PHP(?:/(\d+\.\d+(?:\.\d+)?))?', 'header:X-Powered-By', r'PHP/(\d+\.\d+(?:\.\d+)?)'),
    ('ASP.NET', r'ASP\.NET', 'header:X-Powered-By', r'ASP\.NET(?:\sVersion:)?[\s]?(\d+\.\d+(?:\.\d+)?)'),
    ('Python', r'Python(?:/(\d+\.\d+))?', 'header:X-Powered-By', r'Python/(\d+\.\d+)'),
    ('Java', r'(?:Java|Servlet)', 'header:X-Powered-By', None),
    
    # Frameworks
    ('Express', r'Express', 'header:X-Powered-By', None),
    ('Django', r'(?:django|csrftoken)', 'cookie', None),
    ('Laravel', r'laravel_session', 'cookie', None),
    ('Rails', r'_rails|X-Rails', 'cookie', None),
    ('Spring', r'JSESSIONID', 'cookie', None),
    ('Next.js', r'__NEXT_DATA__|_next/', 'body', None),
    ('React', r'react(?:\.min)?\.js|_reactRootContainer', 'body', None),
    ('Vue.js', r'vue(?:\.min)?\.js|v-app|Vue\.', 'body', None),
    ('Angular', r'ng-version|angular(?:\.min)?\.js', 'body', r'ng-version="(\d+\.\d+(?:\.\d+)?)"'),
    ('jQuery', r'jquery(?:\.min)?\.js', 'body', r'jquery[/-](\d+\.\d+(?:\.\d+)?)'),
    ('Bootstrap', r'bootstrap(?:\.min)?\.(?:css|js)', 'body', r'bootstrap[/-](\d+\.\d+(?:\.\d+)?)'),
    
    # CMS
    ('WordPress', r'wp-content|wp-includes|/wp-json/', 'body', r'WordPress\s+(\d+\.\d+(?:\.\d+)?)'),
    ('Drupal', r'Drupal|drupal\.js|sites/default', 'body', None),
    ('Joomla', r'/media/jui/|Joomla!', 'body', None),
    ('Magento', r'Mage\.Cookies|/skin/frontend/', 'body', None),
    ('Shopify', r'cdn\.shopify\.com|Shopify\.theme', 'body', None),
    ('Ghost', r'ghost(?:\.min)?\.js|ghost-', 'body', None),
    ('Wix', r'wix\.com|wixstatic\.com', 'body', None),
    ('Squarespace', r'squarespace\.com|sqsp', 'body', None),
    
    # CDN / Proxy
    ('Cloudflare', r'cloudflare|cf-ray', 'header:Server', None),
    ('Fastly', r'fastly', 'header:Via', None),
    ('Akamai', r'akamai', 'header:Via', None),
    ('CloudFront', r'CloudFront|amz', 'header:Via', None),
    ('Varnish', r'varnish|X-Varnish', 'header:Via', None),
    
    # Security
    ('ModSecurity', r'Mod_Security|NOYB', 'header:Server', None),
    ('AWS WAF', r'awselb|awswaf', 'header', None),
    ('Sucuri', r'sucuri', 'header:X-Sucuri', None),
    
    # Analytics / Tags
    ('Google Analytics', r'google-analytics\.com|gtag\(|ga\(', 'body', None),
    ('Google Tag Manager', r'googletagmanager\.com', 'body', None),
    ('Facebook Pixel', r'connect\.facebook\.net|fbq\(', 'body', None),
    ('Hotjar', r'hotjar\.com|hj\(', 'body', None),
    
    # Other
    ('reCAPTCHA', r'recaptcha|grecaptcha', 'body', None),
    ('hCaptcha', r'hcaptcha\.com', 'body', None),
    ('Socket.io', r'socket\.io', 'body', None),
    ('GraphQL', r'/graphql|graphql', 'body', None),
]


def detect_technologies(
    url: str,
    response: requests.Response,
    logger: Logger
) -> List[Dict[str, Any]]:
    """
    Detect technologies from HTTP response.
    
    Args:
        url: Target URL
        response: HTTP response object
        logger: Logger instance
        
    Returns:
        List of detected technology results
    """
    results = []
    detected: Set[str] = set()
    
    for name, pattern, location, version_regex in FINGERPRINTS:
        if name in detected:
            continue
        
        found = False
        version = None
        
        try:
            if location == 'body':
                if re.search(pattern, response.text, re.IGNORECASE):
                    found = True
                    if version_regex:
                        match = re.search(version_regex, response.text, re.IGNORECASE)
                        if match:
                            version = match.group(1)
            
            elif location == 'cookie':
                cookie_str = '; '.join([f"{k}={v}" for k, v in response.cookies.items()])
                if re.search(pattern, cookie_str, re.IGNORECASE):
                    found = True
            
            elif location.startswith('header:'):
                header_name = location.split(':')[1]
                header_value = response.headers.get(header_name, '')
                if re.search(pattern, header_value, re.IGNORECASE):
                    found = True
                    if version_regex:
                        match = re.search(version_regex, header_value, re.IGNORECASE)
                        if match:
                            version = match.group(1)
            
            elif location == 'header':
                # Check all headers
                all_headers = ' '.join([f"{k}: {v}" for k, v in response.headers.items()])
                if re.search(pattern, all_headers, re.IGNORECASE):
                    found = True
        
        except Exception as e:
            logger.debug(f"Error checking {name}: {type(e).__name__}")
            continue
        
        if found:
            detected.add(name)
            result = format_tech_result(url, name, version)
            results.append(result)
    
    return results


def run_tech_detect(config: ScanConfig, logger: Logger) -> List[Dict[str, Any]]:
    """
    Execute technology detection on target URL(s).
    
    Args:
        config: Scan configuration
        logger: Logger instance
        
    Returns:
        List of detected technology results
    """
    # For tech detection, we can also accept a file with URLs
    urls = [config.target]
    
    # If wordlist provided, treat as URL list
    if config.wordlist:
        try:
            with open(config.wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                urls = [line.strip() for line in f if line.strip()]
        except (FileNotFoundError, PermissionError) as e:
            logger.warning(f"Could not load URL list: {e}")
    
    logger.info(f"Targets: {len(urls)} URL(s)")
    logger.info(f"Fingerprints: {len(FINGERPRINTS)} signatures")
    
    logger.header("\n--- Starting Technology Detection ---\n")
    
    all_results: List[Dict[str, Any]] = []
    
    for url in urls:
        # Ensure URL has scheme
        if not url.startswith('http'):
            url = f"http://{url}"
        
        logger.info(f"Analyzing: {url}")
        
        try:
            response = requests.get(
                url,
                timeout=config.timeout,
                verify=config.verify_ssl,
                headers={'User-Agent': config.user_agent},
                allow_redirects=True
            )
            
            results = detect_technologies(url, response, logger)
            
            for result in results:
                logger.result(result['raw'], 'green')
            
            if not results:
                logger.info(f"  No technologies detected")
            
            all_results.extend(results)
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch {url}: {type(e).__name__}")
    
    # Print summary
    logger.header("\n--- Detection Finished ---")
    
    # Group by technology
    tech_counts: Dict[str, int] = {}
    for result in all_results:
        tech = result['technology']
        tech_counts[tech] = tech_counts.get(tech, 0) + 1
    
    if tech_counts:
        logger.success(f"Technologies detected: {len(tech_counts)}")
        for tech, count in sorted(tech_counts.items()):
            logger.info(f"  - {tech}: {count} occurrence(s)")
    else:
        logger.warning("No technologies detected")
    
    # Save results
    if config.output:
        metadata = {
            'module': 'tech_detect',
            'targets': urls,
            'fingerprints': len(FINGERPRINTS)
        }
        if save_results(config.output, all_results, metadata, config.json_output):
            logger.success(f"Results saved to '{config.output}'")
        else:
            logger.error(f"Failed to save results")
    
    return all_results
