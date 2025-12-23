package com.example.deeplink;

import android.util.Log;
import org.json.JSONException;
import org.json.JSONObject;
import java.io.IOException;
import okhttp3.Interceptor;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;

/**
 * OkHttp interceptor to log all network traffic
 * This helps identify where tokens are actually sent/received
 */
public class NetworkInterceptor implements Interceptor {
    private static final String TAG = "NetworkSpy";
    
    @Override
    public Response intercept(Chain chain) throws IOException {
        Request request = chain.request();
        
        // Log request
        Log.d(TAG, "🌐 REQUEST: " + request.method() + " " + request.url());
        
        // Log headers (might contain tokens)
        if (request.headers().size() > 0) {
            Log.d(TAG, "📤 Headers: " + request.headers().toString());
        }
        
        // Check for authorization headers
        String authHeader = request.header("Authorization");
        if (authHeader != null) {
            Log.d(TAG, "🔑 Authorization: " + authHeader);
        }
        
        String tokenHeader = request.header("X-Auth-Token");
        if (tokenHeader != null) {
            Log.d(TAG, "🔑 X-Auth-Token: " + tokenHeader);
        }
        
        // Execute request
        Response response = chain.proceed(request);
        
        // Log response
        Log.d(TAG, "📥 RESPONSE: " + response.code() + " " + response.request().url());
        
        // Try to read response body (be careful - can only be read once)
        if (response.body() != null) {
            String contentType = response.header("Content-Type");
            if (contentType != null && contentType.contains("json")) {
                try {
                    ResponseBody responseBody = response.body();
                    String bodyString = responseBody.string();
                    
                    // Log if it looks like it contains tokens
                    if (bodyString.contains("token") || 
                        bodyString.contains("auth") || 
                        bodyString.contains("session") ||
                        bodyString.contains("jwt")) {
                        Log.d(TAG, "🔑 RESPONSE BODY (contains token): " + bodyString.substring(0, Math.min(500, bodyString.length())));
                    }
                    
                    // Recreate response with the body we just read
                    response = response.newBuilder()
                        .body(ResponseBody.create(responseBody.contentType(), bodyString))
                        .build();
                        
                } catch (Exception e) {
                    Log.w(TAG, "Failed to read response body", e);
                }
            }
        }
        
        return response;
    }
}

