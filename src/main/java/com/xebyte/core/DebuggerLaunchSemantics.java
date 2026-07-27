package com.xebyte.core;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

final class DebuggerLaunchSemantics {
    private DebuggerLaunchSemantics() {
    }

    static Map<String, String> decodeLauncherArguments(
            Object rawArguments, Set<String> availableParameters) {
        if (rawArguments == null) {
            return Map.of();
        }
        if (!(rawArguments instanceof Map<?, ?> rawMap)) {
            throw new IllegalArgumentException(
                    "launcher_args must be a JSON object keyed by exact launcher parameter name");
        }

        Map<String, String> decoded = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : rawMap.entrySet()) {
            if (!(entry.getKey() instanceof String name) || name.isBlank()) {
                throw new IllegalArgumentException(
                        "launcher_args keys must be non-empty strings");
            }
            if (!availableParameters.contains(name)) {
                throw new IllegalArgumentException(
                        "Unknown launcher parameter '" + name + "'. Available parameters: "
                                + new TreeSet<>(availableParameters));
            }

            Object value = entry.getValue();
            if (!(value instanceof String) &&
                    !(value instanceof Number) &&
                    !(value instanceof Boolean)) {
                throw new IllegalArgumentException(
                        "launcher_args['" + name
                                + "'] must be a string, number, or boolean");
            }
            decoded.put(name, String.valueOf(value));
        }
        return decoded;
    }
}
