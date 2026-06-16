# public-dns-block

A weekly-updated list of **all known public DNS server IPs**, designed for firewall aliases that block DNS bypass and force all DNS through a local resolver (Pi-hole, AdGuard Home, etc.).

## How it works

A CI/CD pipeline scrapes [publicdns.info](https://publicdns.info/) — which live-tests ~28,000+ resolvers across 218 countries on a 72-hour cycle — and compiles a flat IP list in `nameservers.txt`.

The scraper intentionally includes **all** public DNS servers, including ones with NXDOMAIN hijacking or known issues. The goal is DNS **blocking**, not DNS usage — a broken DNS server is still a server that a client could use to bypass your local resolver.

A hardcoded set of well-known providers (Google, Cloudflare, Quad9, AdGuard, Mullvad, OpenDNS, DNS4EU, etc.) is merged as a safety net in case the scrape misses any.

## Files

- `nameservers.txt` — One IPv4 address per line, sorted. Import into your firewall as a URL Table alias. Excluded servers appear as comments at the top.
- `allowed_dns.txt` — DNS servers to exclude from blocking (your organization's upstream resolvers).
- `well_known_providers.txt` — Extra DNS provider IPs to always include in the block list.
- `doh_dot_providers.txt` — Well-known DoH/DoT provider IPs (subset, for reference).
- `stats.txt` — Per-country breakdown from the last scrape.

## Corporate / multi-site usage

If your organization uses a public DNS server as its upstream resolver (e.g. your Pi-hole forwards to 8.8.8.8), you need to exclude it from the block list — otherwise you block your own DNS.

Edit `allowed_dns.txt` and add the IPs with a comment explaining why:

```
# Corporate upstream resolver (Google)
8.8.8.8
8.8.4.4

# Branch office DNS (Cloudflare)
1.1.1.1
```

These IPs will be removed from `nameservers.txt` and listed at the top as comments for visibility:

```
# ============================================
# ALLOWED DNS — excluded from blocking
# (configured in allowed_dns.txt)
# ============================================
# 1.1.1.1 — Branch office DNS (Cloudflare)
# 8.8.8.8 — Corporate upstream resolver (Google)
# 8.8.4.4 — Corporate upstream resolver (Google)
# ============================================

1.0.0.2
1.0.0.3
...
```

This way anyone reviewing the firewall alias can immediately see which servers were intentionally excluded and why.

## OPNsense setup

### 1. Create the alias

**Firewall → Aliases → Add:**

| Field | Value |
|---|---|
| Name | `PublicDNS_Servers` |
| Type | URL Table (IPs) |
| Content | `https://raw.githubusercontent.com/pls-chris/public-dns-block/main/nameservers.txt` |
| Refresh | `7` |
| Description | All known public DNS servers — block to force Pi-hole |

### 2. Create the firewall rules

**Rule 1 — Block all traffic to public DNS servers:**

| Field | Value |
|---|---|
| Action | Block |
| Interface | LAN |
| Direction | in |
| Protocol | any |
| Source | LAN net |
| Destination | `PublicDNS_Servers` |
| Destination port | any |
| Description | Block all traffic to public DNS servers |

This blocks standard DNS (53), DoH (443), DoT (853), and any other protocol to known public DNS IPs.

**Rule 2 — Block DoT globally:**

| Field | Value |
|---|---|
| Action | Block |
| Interface | LAN |
| Direction | in |
| Protocol | TCP |
| Source | LAN net |
| Destination | any |
| Destination port | 853 |
| Description | Block DNS-over-TLS to all destinations |

Port 853 is used exclusively for DNS-over-TLS — nothing legitimate breaks. This catches DoT servers not in the alias.

> **Rule order:** Place both rules **above** your LAN pass rules.

## Running locally

```bash
pip install requests
python public_dns_block/scrape_dns_servers.py
```

## Adding extra providers

The scraper merges IPs from two sources on top of the publicdns.info scrape:

- **Hardcoded list** in `public_dns_block/scrape_dns_servers.py` — ~109 major providers (Google, Cloudflare, Quad9, etc.). These rarely need changing.
- **`well_known_providers.txt`** — editable file at the repo root for any extra or niche providers you want to add.

To add a provider, just edit `well_known_providers.txt` and add one IP per line:

```
# Niche provider X
203.0.113.53
198.51.100.53
```

Lines starting with `#` are comments. Commit and push — the next scheduled run (or a manual workflow trigger) will include them in `nameservers.txt`.

Any IPs already found by the scrape won't be duplicated. The stats output shows how many were added from each source:

```
Well-known providers: 109 hardcoded + 2 from file
Added 42 well-known DNS IPs not found in scrape
```

## Data source

All DNS server data comes from [publicdns.info](https://publicdns.info/) by Lab0, which probes 90,000+ resolvers and publishes ~28,000 confirmed live ones with status, reliability, and DNSSEC info.

## License

GPL-3.0
