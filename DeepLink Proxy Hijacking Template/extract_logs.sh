#!/bin/bash

# Script to extract captured data from the device

echo "========================================="
echo "Extract Captured Deep Link Data"
echo "========================================="
echo ""

PACKAGE="com.example.deeplink"
LOG_FILE="captured_data.json"
OUTPUT_DIR="./extracted_logs"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_FILE="$OUTPUT_DIR/captured_data_$TIMESTAMP.json"

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo "📥 Extracting logs from device..."
echo ""

# Method 1: Using run-as (works on debuggable apps)
echo "Attempting extraction using run-as..."
adb shell "run-as $PACKAGE cat /data/data/$PACKAGE/files/$LOG_FILE" > "$OUTPUT_FILE" 2>/dev/null

if [ -s "$OUTPUT_FILE" ]; then
    echo "✅ Successfully extracted logs!"
    echo ""
    echo "📁 Saved to: $OUTPUT_FILE"
    echo ""
    
    # Pretty print the JSON
    if command -v jq &> /dev/null; then
        echo "📊 Summary:"
        echo "-----------------------------------"
        
        TOTAL=$(cat "$OUTPUT_FILE" | jq 'length')
        echo "   Total captures: $TOTAL"
        
        echo ""
        echo "📋 Recent captures:"
        cat "$OUTPUT_FILE" | jq -r '.[] | "\n   Timestamp: \(.captured_at)\n   URI: \(.full_uri)\n   Parameters: \(.parameters | keys | join(", "))"' | tail -20
        
        echo ""
        echo "🔑 Tokens found:"
        cat "$OUTPUT_FILE" | jq -r '.[] | select(.parameters.token != null) | "   \(.captured_at): \(.parameters.token)"'
        
        echo ""
        echo "💾 Full JSON saved to: $OUTPUT_FILE"
        echo ""
        echo "To view full details:"
        echo "   cat $OUTPUT_FILE | jq ."
        
    else
        echo "⚠️  Install 'jq' for better JSON formatting: brew install jq"
        echo ""
        echo "Raw content:"
        cat "$OUTPUT_FILE"
    fi
else
    echo "❌ Failed to extract logs using run-as"
    echo ""
    
    # Method 2: Using adb backup (alternative)
    echo "Attempting alternative method..."
    echo "This requires device authorization and may show a confirmation dialog."
    echo ""
    
    # Try logcat approach to see the stats
    echo "Checking logcat for stats..."
    adb logcat -d | grep "Stats:" | tail -5
    
    echo ""
    echo "Alternative: Trigger the app and check logs"
    echo "   adb logcat | grep DataLogger"
fi

echo ""
echo "========================================="
echo "To view logs in real-time:"
echo "   adb logcat | grep -E '(DeepLinkProxy|DataLogger)'"
echo ""
echo "To clear logs on device:"
echo "   adb shell run-as $PACKAGE rm /data/data/$PACKAGE/files/$LOG_FILE"
echo "========================================="

