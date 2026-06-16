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

## Firewall configuration

Import `nameservers.txt` as a URL-based IP list/alias in your firewall, pointed at the raw GitHub URL:

```
https://raw.githubusercontent.com/pls-chris/public-dns-block/main/nameservers.txt
```

Set it to refresh every 7 days to stay in sync with the weekly scrape.

### Required rules

Three rules cover all DNS bypass vectors. Place them above your default allow/pass rules. If your network has multiple internal interfaces (VLANs, guest networks, IoT segments), apply these rules across all of them — most firewalls support a way to define a rule once and apply it to multiple interfaces rather than duplicating per interface.

**Rule 1 — Block all traffic to public DNS servers.** Using the alias, block all protocols and all ports from your internal networks to the listed IPs. This covers standard DNS (53), DoH (443), DoT (853), and anything else a client might try.

**Rule 2 — Block DoT globally.** Block TCP port 853 from your internal networks to all destinations. Port 853 is used exclusively for DNS-over-TLS — nothing legitimate breaks. This catches DoT servers not in the alias.

**Rule 3 — Force DNS through local forwarder.** The alias blocks known public DNS servers, but a client could still send DNS queries directly to an unknown resolver that isn't in the list, or directly to an allowed public DNS server bypassing any filtering the local resolver might have. To close that gap, block all port 53 (TCP/UDP) traffic unless it's going to or from your local DNS forwarder — this could be a Pi-hole, the firewall itself, Unbound, AdGuard Home, or any internal resolver. The forwarder itself must be excluded so it can still reach its upstream.

### OPNsense example

If you have multiple interfaces, use **Firewall → Rules → Floating** with direction **in** and select all internal interfaces — this avoids duplicating rules per interface.

**Alias:** Firewall → Aliases → Add:

| Field | Value |
|---|---|
| Name | `PublicDNS_Servers` |
| Type | URL Table (IPs) |
| Content | `https://raw.githubusercontent.com/pls-chris/public-dns-block/main/nameservers.txt` |
| Refresh | `7` |

**Rule 1:** Firewall → Rules → LAN:

| Field | Value |
|---|---|
| Action | Block |
| Protocol | any |
| Source | LAN net |
| Destination | `PublicDNS_Servers` |
| Destination port | any |

**Rule 2:**

| Field | Value |
|---|---|
| Action | Block |
| Protocol | TCP |
| Source | LAN net |
| Destination | any |
| Destination port | 853 |

**Rule 3:**

| Field | Value |
|---|---|
| Action | Block |
| Protocol | TCP/UDP |
| Source | ! `<your_dns_forwarder>` |
| Destination | ! `<your_dns_forwarder>` |
| Destination port | 53 |

Replace `<your_dns_forwarder>` with the IP of your internal DNS server. The `!` (invert) means: block DNS traffic from anything that isn't the forwarder, going to anything that isn't the forwarder.

### Notes

**IPv6:** This list currently covers **IPv4 only**. If your network has no IPv6 connectivity (no IPv6 on WAN, no IPv6 address on LAN, no Router Advertisements), this is not a concern — clients cannot reach IPv6 DNS servers without IPv6 routing regardless of what they hardcode on their device. If your network does have IPv6 enabled, be aware that IPv6 DNS servers (e.g. `2001:4860:4860::8888`) are not blocked by this list and represent a potential bypass vector.

**Recursive resolvers (Unbound, Knot, etc.):** This list blocks **public recursive resolvers** — servers that accept DNS queries from anyone on the internet. It does not include root servers, TLD nameservers, or authoritative nameservers, which are a different class of infrastructure. If your local resolver runs in recursive mode (e.g. Unbound talking directly to the root servers instead of forwarding to 8.8.8.8), the block list should not interfere — those servers are not cataloged as public recursive resolvers. If the recursive resolver runs on the firewall itself, firewall-originated traffic bypasses LAN rules entirely. If it runs on a separate LAN machine, make sure that machine is set as your forwarder in Rule 3. There is a small theoretical chance that an authoritative nameserver shares an IP with a public recursive resolver in the list — if you see unexpected resolution failures with a recursive setup, check your firewall logs for blocked IPs and add them to `allowed_dns.txt`.

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
