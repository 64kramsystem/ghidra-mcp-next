package com.xebyte.core;

import java.io.IOException;
import java.io.InputStream;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

/** Shared authoritative payload for every {@code GET /get_version} transport. */
public final class VersionPayload {
    private static String version = "5.15.0";
    private static String appName = "GhidraMCP-next";
    private static String ghidraVersion = "unknown";
    private static String buildTimestamp = "dev";
    private static String buildNumber = "0";

    static {
        try (InputStream input = VersionPayload.class
                .getResourceAsStream("/com/xebyte/version.properties")) {
            if (input != null) {
                Properties properties = new Properties();
                properties.load(input);
                version = properties.getProperty("app.version", version);
                appName = properties.getProperty("app.name", appName);
                ghidraVersion = properties.getProperty(
                    "ghidra.version", ghidraVersion);
                buildTimestamp = properties.getProperty(
                    "build.timestamp", buildTimestamp);
                buildNumber = properties.getProperty(
                    "build.number", buildNumber);
            }
        } catch (IOException ignored) {
            // The stable fallbacks above keep the endpoint usable in dev builds.
        }
    }

    private VersionPayload() {
    }

    public static String getVersion() {
        return version;
    }

    public static String getPluginName() {
        return appName;
    }

    public static String getGhidraVersion() {
        return ghidraVersion;
    }

    public static String getBuildTimestamp() {
        return buildTimestamp;
    }

    public static String getBuildNumber() {
        return buildNumber;
    }

    public static String getFullVersion() {
        return version + " (build " + buildNumber + ", " + buildTimestamp + ")";
    }

    public static Map<String, Object> asMap(String mode, int endpointCount) {
        if (!"gui".equals(mode) && !"headless".equals(mode)) {
            throw new IllegalArgumentException("mode must be gui or headless");
        }
        if (endpointCount < 0) {
            throw new IllegalArgumentException(
                "endpointCount must be non-negative");
        }
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("plugin_name", appName);
        payload.put("plugin_version", version);
        payload.put("build_timestamp", buildTimestamp);
        payload.put("build_number", buildNumber);
        payload.put("full_version", getFullVersion());
        payload.put("ghidra_version", ghidraVersion);
        payload.put("java_version", System.getProperty("java.version", "unknown"));
        payload.put("endpoint_count", endpointCount);
        payload.put("mode", mode);
        return payload;
    }

    public static String toJson(String mode, int endpointCount) {
        return JsonHelper.toJson(asMap(mode, endpointCount));
    }
}
