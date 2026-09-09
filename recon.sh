#!/usr/bin/env bash
#
# recon.sh - subdomain enum -> live host filter -> JS URL discovery -> JS download
#
# Requires (install once, not included here since they're Go/Python binaries
# that need network access outside this sandbox):
#   subfinder   https://github.com/projectdiscovery/subfinder
#   httpx       https://github.com/projectdiscovery/httpx
#   katana      https://github.com/projectdiscovery/katana
#   gau         https://github.com/lc/gau
#   waymore     https://github.com/xnl-h4ck3r/waymore
#
# Usage: ./recon.sh example.com

set -euo pipefail

DOMAIN="${1:?Usage: $0 <domain>}"
OUTDIR="output/${DOMAIN}"
mkdir -p "$OUTDIR"

# On Kali/Parrot, ProjectDiscovery's httpx is often installed as
# "httpx-toolkit" because the python httpx package already owns "httpx".
if command -v httpx >/dev/null 2>&1; then
    HTTPX_BIN="httpx"
elif command -v httpx-toolkit >/dev/null 2>&1; then
    HTTPX_BIN="httpx-toolkit"
else
    echo "[!] httpx (or httpx-toolkit) not found. Install: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
    exit 1
fi

echo "[*] Subdomain enumeration for $DOMAIN"
subfinder -d "$DOMAIN" -all -silent -o "$OUTDIR/subs_subfinder.txt" || true

if command -v assetfinder >/dev/null 2>&1; then
    assetfinder --subs-only "$DOMAIN" > "$OUTDIR/subs_assetfinder.txt" || true
fi

cat "$OUTDIR"/subs_*.txt 2>/dev/null | sort -u > "$OUTDIR/subs_all.txt"
echo "  -> $(wc -l < "$OUTDIR/subs_all.txt") unique subdomains"

echo "[*] Probing for live hosts"
"$HTTPX_BIN" -l "$OUTDIR/subs_all.txt" -silent -follow-redirects \
    -o "$OUTDIR/live_hosts.txt"
echo "  -> $(wc -l < "$OUTDIR/live_hosts.txt") live hosts"

echo "[*] Historical URL discovery (gau)"
if command -v gau >/dev/null 2>&1; then
    gau --subs "$DOMAIN" > "$OUTDIR/urls_gau.txt" || true
fi

echo "[*] Historical URL discovery (waymore)"
if command -v waymore >/dev/null 2>&1; then
    waymore -i "$DOMAIN" -mode U -oU "$OUTDIR/urls_waymore.txt" || true
fi

echo "[*] Active crawl for JS (katana)"
katana -list "$OUTDIR/live_hosts.txt" -jc -silent -o "$OUTDIR/urls_katana.txt" || true

echo "[*] Merging and filtering to .js URLs"
cat "$OUTDIR"/urls_*.txt 2>/dev/null \
    | grep -Ei '\.js(\?|$)' \
    | sort -u > "$OUTDIR/js_urls.txt"
echo "  -> $(wc -l < "$OUTDIR/js_urls.txt") unique JS URLs"

echo "[*] Done. This script only collects URLs - nothing was downloaded."
echo "[*] Now run: python3 scan_ai_tokens.py $OUTDIR/js_urls.txt"
echo "    (it fetches, follows chunks/source maps, and scans everything in memory)"
