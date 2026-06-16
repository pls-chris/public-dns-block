#!/usr/bin/env python3
"""
scrape_dns_servers.py — Scrape public DNS server IPs from publicdns.info

Designed for OPNsense DNS-blocking use cases: collects ALL public DNS IPs
(not just "known-good" ones) to block DNS bypass and force traffic through
a local resolver like Pi-hole.

Also blocks well-known DoT/DoH endpoints by IP.

Source: https://publicdns.info (live-tested every 72 hours)
"""

import re
import sys
import time
import ipaddress
import requests
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- Configuration ---
BASE_URL = "https://publicdns.info"
COUNTRIES_URL = f"{BASE_URL}/countries.html"
MAX_WORKERS = 8  # parallel country page fetches
REQUEST_TIMEOUT = 30
RETRY_COUNT = 3
RETRY_DELAY = 2  # seconds between retries
MIN_DELAY = 0.3  # politeness delay between requests (seconds)

# Output paths
OUTPUT_DIR = Path(__file__).parent.parent
NAMESERVERS_FILE = OUTPUT_DIR / "nameservers.txt"
STATS_FILE = OUTPUT_DIR / "stats.txt"
EXTRA_PROVIDERS_FILE = OUTPUT_DIR / "well_known_providers.txt"

# Well-known public DNS providers that should ALWAYS be blocked
# even if the scraper misses them (DoH/DoT endpoints included)
WELL_KNOWN_DNS = {
    # Google Public DNS
    "8.8.8.8", "8.8.4.4",
    # Cloudflare
    "1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2", "1.1.1.3", "1.0.0.3",
    # Quad9
    "9.9.9.9", "149.112.112.112", "9.9.9.10", "149.112.112.10",
    "9.9.9.11", "149.112.112.11", "9.9.9.12", "149.112.112.12",
    # OpenDNS / Cisco Umbrella
    "208.67.222.222", "208.67.220.220", "208.67.222.123", "208.67.220.123",
    # Comodo Secure DNS
    "8.26.56.26", "8.20.247.20",
    # Level3 / CenturyLink
    "4.2.2.1", "4.2.2.2", "4.2.2.3", "4.2.2.4", "4.2.2.5", "4.2.2.6",
    # Verisign
    "64.6.64.6", "64.6.65.6",
    # DNS.Watch
    "84.200.69.80", "84.200.70.40",
    # Yandex DNS
    "77.88.8.8", "77.88.8.1", "77.88.8.88", "77.88.8.2", "77.88.8.7", "77.88.8.3",
    # AdGuard DNS
    "94.140.14.14", "94.140.15.15", "94.140.14.15", "94.140.15.16",
    "94.140.14.140", "94.140.14.141",
    # CleanBrowsing
    "185.228.168.9", "185.228.169.9", "185.228.168.10", "185.228.169.11",
    "185.228.168.168", "185.228.169.168",
    # Mullvad DNS
    "194.242.2.2", "194.242.2.3", "194.242.2.4", "194.242.2.5",
    "194.242.2.6", "194.242.2.9",
    # NextDNS
    "45.90.28.0", "45.90.30.0",
    # Control D
    "76.76.2.0", "76.76.10.0", "76.76.2.1", "76.76.10.1",
    "76.76.2.2", "76.76.10.2", "76.76.2.3", "76.76.10.3",
    "76.76.2.4", "76.76.10.4", "76.76.2.5", "76.76.10.5",
    # Neustar UltraDNS
    "156.154.70.1", "156.154.71.1", "156.154.70.2", "156.154.71.2",
    "156.154.70.3", "156.154.71.3", "156.154.70.4", "156.154.71.4",
    "156.154.70.5", "156.154.71.5",
    # Alternate DNS
    "76.76.19.19", "76.223.122.150",
    # SafeDNS
    "195.46.39.39", "195.46.39.40",
    # Hurricane Electric
    "74.82.42.42",
    # puntCAT
    "109.69.8.51",
    # FreeDNS (freedns.zone)
    "172.104.237.57", "37.235.1.174", "37.235.1.177",
    # UncensoredDNS
    "91.239.100.100", "89.233.43.71",
    # LibreDNS
    "116.202.176.26",
    # AhaDNS
    "5.2.75.75",
    # DNSForge
    "176.9.93.198", "176.9.1.117",
    # Digitale Gesellschaft (Switzerland)
    "185.95.218.42", "185.95.218.43",
    # Applied Privacy (Austria)
    "146.255.56.98",
    # CIRA Canadian Shield
    "149.112.121.10", "149.112.122.10",
    "149.112.121.20", "149.112.122.20",
    "149.112.121.30", "149.112.122.30",
    # DNS0.eu
    "193.110.81.0", "185.253.5.0",
    # DNS4EU
    "193.17.47.1", "185.12.64.1",
    # Restena Foundation Luxembourg
    "158.64.1.29",
}

# IPv4 regex for extracting IPs from HTML
IPV4_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b'
)

# Pattern to extract country codes from countries page
COUNTRY_CODE_PATTERN = re.compile(r'/country/([a-z]{2})\.html')

# Session for connection pooling
session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) "
                  "Gecko/20100101 Firefox/128.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
})


def errprint(*args, **kwargs):
    print(*args, **kwargs, file=sys.stderr, flush=True)


def load_extra_providers():
    """Load additional provider IPs from well_known_providers.txt."""
    extra = set()
    if not EXTRA_PROVIDERS_FILE.exists():
        return extra
    with open(EXTRA_PROVIDERS_FILE) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                ip = ipaddress.ip_address(line)
                if ip.is_global and not ip.is_multicast:
                    extra.add(str(ip))
            except ValueError:
                errprint(f"  Skipping invalid IP in {EXTRA_PROVIDERS_FILE.name}: {line}")
    return extra


def fetch_page(url, retries=RETRY_COUNT):
    """Fetch a URL with retries and politeness delay."""
    for attempt in range(1, retries + 1):
        try:
            resp = session.get(url, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            time.sleep(MIN_DELAY)  # be polite
            return resp.text
        except requests.RequestException as e:
            if attempt < retries:
                errprint(f"  Retry {attempt}/{retries} for {url}: {e}")
                time.sleep(RETRY_DELAY * attempt)
            else:
                errprint(f"  FAILED after {retries} attempts: {url}: {e}")
                return None


def get_country_codes():
    """Get list of country codes from the countries index page."""
    errprint("Fetching country list...")
    html = fetch_page(COUNTRIES_URL)
    if html is None:
        errprint("FATAL: Cannot fetch countries page")
        sys.exit(1)

    codes = sorted(set(COUNTRY_CODE_PATTERN.findall(html)))
    errprint(f"Found {len(codes)} countries")
    return codes


def extract_ips_from_html(html):
    """Extract valid public IPv4 addresses from HTML content."""
    ips = set()
    # Look for IPs specifically in table cells or code tags
    # The publicdns.info format uses <code>IP</code> in tables
    for ip_str in IPV4_PATTERN.findall(html):
        try:
            ip = ipaddress.ip_address(ip_str)
            # Skip private, loopback, link-local, multicast, reserved
            if ip.is_global and not ip.is_multicast:
                ips.add(ip_str)
        except ValueError:
            continue
    return ips


def scrape_country(country_code):
    """Scrape all DNS server IPs for a given country (handles pagination)."""
    ips = set()
    page = 1

    while True:
        if page == 1:
            url = f"{BASE_URL}/country/{country_code}.html"
        else:
            url = f"{BASE_URL}/country/{country_code}.html?page={page}"

        html = fetch_page(url)
        if html is None:
            break

        page_ips = extract_ips_from_html(html)
        if not page_ips:
            break

        new_ips = page_ips - ips
        ips.update(page_ips)

        # Check if there's a next page link
        if f"?page={page + 1}" in html or f"page={page + 1}" in html:
            page += 1
        else:
            break

    # Also scrape the "DNS issues" page for this country
    # These are servers with NXDOMAIN hijacking etc. — still need to block them
    issues_url = f"{BASE_URL}/dns-issues/{country_code}.html"
    issues_html = fetch_page(issues_url)
    if issues_html:
        issues_ips = extract_ips_from_html(issues_html)
        ips.update(issues_ips)

    return country_code, ips


def main():
    errprint("=" * 60)
    errprint("public-dns-block: Public DNS Server List Generator")
    errprint("Source: publicdns.info")
    errprint("=" * 60)

    # Step 1: Get country codes
    country_codes = get_country_codes()

    # Step 2: Scrape each country (with thread pool for speed)
    all_ips = set()
    country_stats = {}

    errprint(f"\nScraping {len(country_codes)} countries "
             f"(max {MAX_WORKERS} parallel workers)...")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(scrape_country, cc): cc
            for cc in country_codes
        }
        completed = 0
        for future in as_completed(futures):
            cc = futures[future]
            try:
                country_code, ips = future.result()
                country_stats[country_code] = len(ips)
                all_ips.update(ips)
                completed += 1
                if ips:
                    errprint(f"  [{completed}/{len(country_codes)}] "
                             f"{country_code.upper()}: {len(ips)} servers")
                else:
                    errprint(f"  [{completed}/{len(country_codes)}] "
                             f"{country_code.upper()}: no servers found")
            except Exception as e:
                errprint(f"  ERROR processing {cc}: {e}")
                completed += 1

    # Step 3: Add well-known DNS providers (hardcoded + file)
    extra_from_file = load_extra_providers()
    all_known = WELL_KNOWN_DNS | extra_from_file
    well_known_added = all_known - all_ips
    all_ips.update(all_known)
    errprint(f"\nWell-known providers: {len(WELL_KNOWN_DNS)} hardcoded "
             f"+ {len(extra_from_file)} from file")
    errprint(f"Added {len(well_known_added)} well-known DNS IPs "
             f"not found in scrape")

    # Step 4: Validate final list
    errprint(f"\nTotal unique IPs: {len(all_ips)}")

    if len(all_ips) < 500:
        errprint("WARNING: Suspiciously low IP count — possible scraping issue")
        errprint("NOT overwriting existing file")
        sys.exit(1)

    # Step 5: Write sorted output
    sorted_ips = sorted(all_ips, key=lambda x: ipaddress.ip_address(x))
    with open(NAMESERVERS_FILE, "w") as f:
        for ip in sorted_ips:
            f.write(f"{ip}\n")
    errprint(f"Wrote {len(sorted_ips)} IPs to {NAMESERVERS_FILE}")

    # Step 6: Write stats
    with open(STATS_FILE, "w") as f:
        f.write(f"Total servers: {len(sorted_ips)}\n")
        f.write(f"Countries scraped: {len(country_stats)}\n")
        f.write(f"Well-known providers added: {len(well_known_added)}\n")
        f.write(f"Source: publicdns.info\n")
        f.write(f"\nPer-country breakdown:\n")
        for cc in sorted(country_stats.keys()):
            f.write(f"  {cc.upper()}: {country_stats[cc]}\n")

    errprint("\nDone!")


if __name__ == "__main__":
    main()
