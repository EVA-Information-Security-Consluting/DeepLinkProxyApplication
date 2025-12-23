#!/bin/bash

# Comprehensive token monitoring script

echo "========================================="
echo "CoinMaster Token Hunter"
echo "========================================="
echo ""
echo "This will monitor:"
echo "  1. Deep link parameters (query & fragment)"
echo "  2. Network requests (API calls)"
echo "  3. Response bodies containing tokens"
echo ""
echo "Press Ctrl+C to stop"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Clear logs
adb logcat -c

echo "Starting monitoring... Now open CoinMaster with a real deep link!"
echo ""

# Monitor in real-time
adb logcat | grep --line-buffered -E "(DeepLinkProxy|NetworkSpy|🔑|🌐|📤|📥)" | while read line; do
    if echo "$line" | grep -q "🔑"; then
        echo -e "${GREEN}$line${NC}"
    elif echo "$line" | grep -q "SENSITIVE"; then
        echo -e "${RED}$line${NC}"
    elif echo "$line" | grep -q "🌐"; then
        echo -e "${YELLOW}$line${NC}"
    else
        echo "$line"
    fi
done

