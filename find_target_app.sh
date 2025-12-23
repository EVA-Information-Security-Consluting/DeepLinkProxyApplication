#!/bin/bash

# Script to find target app package name and deep link handlers

# Usage: ./find_target_app.sh [KEYWORD]
# Example: ./find_target_app.sh instagram

KEYWORD=${1:-""}

echo "═══════════════════════════════════════════════════════════════"
echo "🔍 Finding Target App Information"
echo "═══════════════════════════════════════════════════════════════"
echo ""

if [ -z "$KEYWORD" ]; then
    echo "Usage: $0 KEYWORD"
    echo "Example: $0 instagram"
    echo ""
    echo "This will search for packages and deep link handlers"
    exit 1
fi

echo "Searching for: $KEYWORD"
echo ""

echo "1. Searching for package..."
echo "──────────────────────────────────────────────────────────────"
PACKAGES=$(adb shell pm list packages | grep -i "$KEYWORD")

if [ -z "$PACKAGES" ]; then
    echo "❌ No packages found matching '$KEYWORD'"
    echo "   Make sure the app is installed on the device"
    echo ""
    echo "💡 Try:"
    echo "   - Different keyword"
    echo "   - adb shell pm list packages (to see all packages)"
else
    echo "✅ Found packages:"
    echo "$PACKAGES"
    
    # Extract package names
    for pkg in $(echo "$PACKAGES" | sed 's/package://g'); do
        echo ""
        echo "📦 Package: $pkg"
        echo "   Checking for deep link handlers..."
        
        # Check for intent filters
        INTENTS=$(adb shell dumpsys package "$pkg" | grep -A 10 "intent-filter" | grep -E "(scheme|host|path)")
        
        if [ ! -z "$INTENTS" ]; then
            echo "   ✅ Deep link handlers found:"
            echo "$INTENTS" | sed 's/^/      /'
        else
            echo "   ⚠️  No deep link handlers found in this package"
        fi
    done
fi

echo ""
echo "2. Proxy app status..."
echo "──────────────────────────────────────────────────────────────"
PROXY_INSTALLED=$(adb shell pm list packages | grep "com.example.deeplink")

if [ -z "$PROXY_INSTALLED" ]; then
    echo "❌ Proxy app NOT installed"
    echo "   Run: ./gradlew assembleDebug && adb install -r app/build/outputs/apk/debug/app-debug.apk"
else
    echo "✅ Proxy app is installed: $PROXY_INSTALLED"
    
    echo "   Checking configured scheme..."
    adb shell dumpsys package com.example.deeplink | grep -A 3 "intent-filter" | grep "scheme"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "📋 Next Steps"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "1. Update config.xml with found package:"
echo "   - target_package: [package from above]"
echo "   - deep_link_scheme: [scheme from deep link handlers]"
echo ""
echo "2. Build and install: ./gradlew assembleDebug && adb install -r app/build/outputs/apk/debug/app-debug.apk"
echo "3. Test: ./test_deeplink.sh"
echo ""
