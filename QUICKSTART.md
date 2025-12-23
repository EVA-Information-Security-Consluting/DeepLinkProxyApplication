# 🚀 Quick Start Guide

Get up and running in 5 minutes!

## Prerequisites

- ✅ Android device or emulator
- ✅ ADB installed and device connected
- ✅ Target app installed on device
- ✅ Burp Collaborator, webhook, or server URL

## Step-by-Step Setup

### 1. Configure (Choose One Method)

#### Option A: Interactive Setup Script (Recommended)

```bash
./setup.sh
```

Answer the prompts:
- Enter your Burp Collaborator URL
- Enter target app package name
- Enter deep link scheme

#### Option B: Manual Configuration

Edit `app/src/main/res/values/config.xml`:

```xml
<string name="server_url">https://YOUR-ID.oastify.com</string>
<string name="target_package">com.target.app</string>
<string name="deep_link_scheme">targetscheme</string>
```

### 2. Build & Install

```bash
./gradlew assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

### 3. Test

```bash
./test_deeplink.sh
```

Or manually:

```bash
adb shell am start -a android.intent.action.VIEW -d "targetscheme://test"
```

### 4. Monitor & Extract

```bash
# Watch live captures
./monitor_tokens.sh

# Extract saved data
./extract_logs.sh
```

## Finding Configuration Values

### Get Target Package Name

```bash
# List all packages
adb shell pm list packages

# Search for specific app
adb shell pm list packages | grep KEYWORD

# Example: Find Instagram
adb shell pm list packages | grep instagram
# Output: package:com.instagram.android
```

### Get Deep Link Scheme

Multiple ways to find it:

#### Method 1: AndroidManifest.xml

```bash
# Pull APK
adb shell pm path com.target.app
# Example output: package:/data/app/com.target.app-xxx/base.apk

# Pull the APK
adb pull /data/app/com.target.app-xxx/base.apk

# Extract and view manifest
# (Use online APK analyzer or apktool)
```

#### Method 2: Try Common Schemes

Most apps use predictable schemes:
- `instagram://`
- `spotify://`
- `uber://`
- `twitter://` or `x://`
- Usually: `appname://`

#### Method 3: Check App Documentation

Look for:
- OAuth documentation
- Deep linking guides
- Developer documentation

### Get Burp Collaborator URL

1. Open Burp Suite Professional
2. Go to: **Burp → Burp Collaborator client**
3. Click **"Copy to clipboard"**
4. Use this URL in `config.xml`

Alternatively, use free alternatives:
- https://webhook.site (get unique URL)
- https://requestbin.com (create bin)
- https://pipedream.com (free webhook)

## Example Configurations

### Instagram

```xml
<string name="server_url">https://abc123.oastify.com</string>
<string name="target_package">com.instagram.android</string>
<string name="deep_link_scheme">instagram</string>
```

### Spotify

```xml
<string name="server_url">https://webhook.site/xyz789</string>
<string name="target_package">com.spotify.music</string>
<string name="deep_link_scheme">spotify</string>
```

### Custom OAuth App

```xml
<string name="server_url">https://your-server.com/webhook</string>
<string name="target_package">com.company.app</string>
<string name="deep_link_scheme">companyapp</string>
```

## Troubleshooting

### "No device connected"
```bash
# Check device connection
adb devices

# If empty, enable USB debugging on device
```

### "Permission denied"
```bash
# Make scripts executable
chmod +x *.sh
```

### "Deep link not intercepted"
```bash
# 1. Verify scheme is correct
./test_deeplink.sh

# 2. Reinstall proxy app
adb install -r app/build/outputs/apk/debug/app-debug.apk

# 3. Clear default handlers
# Settings → Apps → Default Apps → Reset
```

### "Real app doesn't open"
```bash
# Verify target package is installed
adb shell pm list packages | grep TARGET

# Check package name is correct in config.xml
```

### "No data on server"
```bash
# 1. Check internet connection
adb shell ping -c 1 8.8.8.8

# 2. Verify server URL
# Check config.xml

# 3. View logs
adb logcat | grep DeepLinkProxy
```

## What's Next?

After successful setup:

1. **Monitor captures**: `./monitor_tokens.sh`
2. **Test different deep links**: `./test_deeplink.sh SCHEME://action?params`
3. **Extract data**: `./extract_logs.sh`
4. **Analyze tokens**: Check your Burp Collaborator
5. **Customize**: Edit `config.xml` for different apps

## Advanced Features

See [CONFIG.md](CONFIG.md) for:
- Custom forwarding delays
- Disabling local logging
- Debug mode
- Multiple scheme handling

## Need Help?

- 📖 Full documentation: [README.md](README.md)
- ⚙️ Configuration guide: [CONFIG.md](CONFIG.md)
- 🐛 Issues: Open a GitHub issue
- 💡 Examples: See `README.md` for use cases

## Security Reminder

⚠️ **Only test applications you own or have explicit permission to test**

This tool is for:
- ✅ Your own apps
- ✅ Authorized penetration tests
- ✅ Bug bounty programs (in scope)
- ✅ Educational research (with permission)

Always follow responsible disclosure and applicable laws.

---

**Ready to test?** Run `./setup.sh` to begin! 🚀

