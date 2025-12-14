#!/bin/bash

DOMAIN="heroforge.genialarchitect.io"
EXPECTED_IP="72.60.126.183"

echo "Checking DNS configuration for $DOMAIN"
echo "Expected IP: $EXPECTED_IP"
echo "=========================================="
echo ""

# Check if DNS resolves
if RESOLVED_IP=$(dig +short $DOMAIN | grep -E '^[0-9.]+$' | head -1); then
    if [ -n "$RESOLVED_IP" ]; then
        echo "✓ DNS resolves to: $RESOLVED_IP"

        if [ "$RESOLVED_IP" = "$EXPECTED_IP" ]; then
            echo "✓ IP matches! DNS is configured correctly."
            echo ""
            echo "You can now proceed with deployment:"
            echo "  sudo ./deploy.sh"
            exit 0
        else
            echo "⚠ IP doesn't match expected value"
            echo "  Expected: $EXPECTED_IP"
            echo "  Got: $RESOLVED_IP"
            exit 1
        fi
    else
        echo "✗ DNS does not resolve yet"
        echo ""
        echo "Please add the DNS A record:"
        echo "  Type: A"
        echo "  Name: heroforge"
        echo "  Value: $EXPECTED_IP"
        echo "  TTL: 300"
        exit 1
    fi
else
    echo "✗ DNS does not resolve yet"
    echo ""
    echo "Please add the DNS A record:"
    echo "  Type: A"
    echo "  Name: heroforge"
    echo "  Value: $EXPECTED_IP"
    echo "  TTL: 300"
    exit 1
fi
