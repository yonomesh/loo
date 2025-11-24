# loo

A DNS Query Tool

Forked from [ameshkov/dnslookup](https://github.com/ameshkov/dnslookup)

# Install(beta)

```bash

# macos brew
brew install yonomesh/tap/loo
## or
brew tap yonomesh/tap
brew update && brew install loo

# debian
apt-get update
apt-get install ca-certificates curl gnupg
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://yonomesh.github.io/apt/yonomesh.gpg | gpg --dearmor -o /etc/apt/keyrings/yonomesh.gpg
chmod a+r /etc/apt/keyrings/yonomesh.gpg

echo "deb [signed-by=/etc/apt/keyrings/yonomesh.gpg] https://yonomesh.github.io/apt stable main" \
  | tee /etc/apt/sources.list.d/yonomesh.list > /dev/null

apt-get update 
apt-get install loo
```

# Usage

```bash
# Plain DNS using the default system resolver:
loo example.org

# Plain DNS with a specific resolver:
loo example.org 8.8.8.8

# DNS-over-TCP:
loo example.org tcp://8.8.8.8

# DNS-over-TLS:
loo example.org tls://dns.adguard.com

# DNS-over-TLS with bootstrap resolver (8.8.8.8 used for dns.adguard.com):
loo example.org tls://dns.adguard.com 8.8.8.8

# DNS-over-HTTPS (HTTP/2):
loo example.org https://dns.adguard.com/dns-query

# DNS-over-HTTPS with HTTP/3 support (auto-select):
HTTP3=1 loo example.org https://dns.google/dns-query

# DNS-over-HTTPS forcing HTTP/3 only:
loo example.org h3://dns.google/dns-query

# DNS-over-HTTPS with bootstrap resolver (8.8.8.8 used for dns.adguard.com):
loo example.org https://dns.adguard.com/dns-query 8.8.8.8

# DNS-over-HTTPS with basic auth (AdGuard DNS supported):
loo example.org https://username:password@d.adguard-dns.com/dns-query

# DNS-over-QUIC:
loo example.org quic://dns.adguard.com

# PTR query for IPv4 (auto-detected when RRTYPE is omitted):
loo 8.8.8.8

# PTR query for IPv6:
loo 2606:4700:4700::1111

# JSON output:
JSON=1 loo example.org 94.140.14.14

# Disable certificate verification:
VERIFY=0 loo example.org tls://1.1.1.1

# Specify resource record type (default A):
RRTYPE=AAAA loo example.org tls://1.1.1.1
RRTYPE=HTTPS loo example.org tls://1.1.1.1

# Specify DNS class (default IN):
CLASS=CH loo example.org tls://1.1.1.1

# Add EDNS subnet:
SUBNET=1.2.3.4/24 loo example.org tls://8.8.8.8

# Add EDNS0 Padding:
PAD=1 loo example.org tls://1.1.1.1

# Verbose logging:
VERBOSE=1 loo example.org tls://dns.adguard.com

```