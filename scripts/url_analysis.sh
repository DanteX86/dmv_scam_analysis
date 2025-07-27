#!/bin/bash

# URL/Domain Analysis Script for Scam Investigation
# Usage: ./url_analysis.sh [domain or URL]

URL=$1

if [ -z "$URL" ]; then
    echo "Usage: $0 [domain or URL]"
    echo "Example: $0 suspicious-dmv-site.com"
    exit 1
fi

# Extract domain from URL if full URL is provided
DOMAIN=$(echo "$URL" | sed 's|https\?://||' | cut -d'/' -f1)

echo "=== URL/DOMAIN ANALYSIS: $URL ==="
echo "Domain: $DOMAIN"
echo

echo "=== WHOIS LOOKUP ==="
/opt/homebrew/opt/whois/bin/whois "$DOMAIN"
echo

echo "=== DNS LOOKUP ==="
nslookup "$DOMAIN"
echo

echo "=== SSL CERTIFICATE INFO ==="
echo | openssl s_client -connect "$DOMAIN:443" -servername "$DOMAIN" 2>/dev/null | openssl x509 -noout -text 2>/dev/null | grep -E "(Issuer|Subject|Not Before|Not After)"
echo

echo "=== HTTP HEADERS ==="
curl -I -s "https://$DOMAIN" | head -20
echo

echo "=== NMAP SCAN (Top 100 ports) ==="
nmap -F "$DOMAIN"
