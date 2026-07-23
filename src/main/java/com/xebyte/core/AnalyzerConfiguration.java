package com.xebyte.core;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Validation and all-or-nothing mutation core for analyzer configuration.
 *
 * <p>The backend deliberately has no operation for starting analysis. Changing
 * analyzer options and running analyzers are separate user actions.
 */
final class AnalyzerConfiguration {

    interface Backend {
        List<AnalyzerDescriptor> descriptors() throws Exception;

        boolean readEnabled(String analyzer) throws Exception;

        void setEnabled(String analyzer, boolean enabled) throws Exception;

        /** Make Ghidra's schedulers observe the current option values. */
        void synchronize() throws Exception;
    }

    record AnalyzerDescriptor(
            String analyzer,
            String description,
            String analysisType,
            String priority,
            boolean available) {
    }

    record AnalyzerChange(String analyzer, boolean enabled) {
    }

    record AnalyzerState(
            String analyzer,
            boolean before,
            boolean requested,
            boolean after) {
    }

    record Outcome(
            boolean dryRun,
            boolean committed,
            List<AnalyzerState> analyzers) {
        Outcome {
            analyzers = List.copyOf(analyzers);
        }
    }

    private AnalyzerConfiguration() {
    }

    static Outcome configure(
            Backend backend,
            String changesJson,
            boolean dryRun) throws Exception {
        List<AnalyzerChange> changes = parseChanges(changesJson);
        Map<String, AnalyzerDescriptor> descriptors =
            indexDescriptors(backend.descriptors());

        // Resolve the complete request before reading originals or mutating.
        List<AnalyzerDescriptor> resolved = new ArrayList<>(changes.size());
        List<String> availableNames = descriptors.values().stream()
            .filter(AnalyzerDescriptor::available)
            .map(AnalyzerDescriptor::analyzer)
            .sorted()
            .toList();
        for (AnalyzerChange change : changes) {
            AnalyzerDescriptor descriptor = descriptors.get(change.analyzer());
            if (descriptor == null) {
                throw new IllegalArgumentException(
                    "Unknown analyzer '" + change.analyzer() +
                    "'; available analyzers: " + availableNames);
            }
            if (!descriptor.available()) {
                throw new IllegalArgumentException(
                    "Analyzer '" + change.analyzer() +
                    "' is unavailable for this program; available analyzers: " +
                    availableNames);
            }
            resolved.add(descriptor);
        }

        Map<String, Boolean> originals = new LinkedHashMap<>();
        for (AnalyzerDescriptor descriptor : resolved) {
            originals.put(
                descriptor.analyzer(),
                backend.readEnabled(descriptor.analyzer()));
        }

        if (dryRun) {
            List<AnalyzerState> states = new ArrayList<>(changes.size());
            for (AnalyzerChange change : changes) {
                boolean before = originals.get(change.analyzer());
                states.add(new AnalyzerState(
                    change.analyzer(), before, change.enabled(), before));
            }
            return new Outcome(true, false, states);
        }

        try {
            for (AnalyzerChange change : changes) {
                backend.setEnabled(change.analyzer(), change.enabled());
            }
            backend.synchronize();

            List<AnalyzerState> states = new ArrayList<>(changes.size());
            for (AnalyzerChange change : changes) {
                boolean observed = backend.readEnabled(change.analyzer());
                if (observed != change.enabled()) {
                    throw new IllegalStateException(
                        "Analyzer '" + change.analyzer() +
                        "' observed enabled=" + observed +
                        " after requesting enabled=" + change.enabled());
                }
                states.add(new AnalyzerState(
                    change.analyzer(),
                    originals.get(change.analyzer()),
                    change.enabled(),
                    observed));
            }
            return new Outcome(false, true, states);
        }
        catch (Exception failure) {
            restore(backend, originals, failure);
            throw failure;
        }
    }

    static List<AnalyzerChange> parseChanges(String changesJson) {
        if (changesJson == null || changesJson.isBlank()) {
            throw new IllegalArgumentException(
                "changes must contain at least one analyzer");
        }

        JsonElement root;
        try {
            root = JsonParser.parseString(changesJson);
        }
        catch (RuntimeException malformed) {
            throw new IllegalArgumentException(
                "changes must be a JSON array", malformed);
        }
        if (!root.isJsonArray() || root.getAsJsonArray().isEmpty()) {
            throw new IllegalArgumentException(
                "changes must contain at least one analyzer");
        }

        Set<String> names = new HashSet<>();
        List<AnalyzerChange> changes =
            new ArrayList<>(root.getAsJsonArray().size());
        for (int i = 0; i < root.getAsJsonArray().size(); i++) {
            JsonElement element = root.getAsJsonArray().get(i);
            if (!element.isJsonObject()) {
                throw new IllegalArgumentException(
                    "changes[" + i + "] must be an object");
            }
            JsonObject raw = element.getAsJsonObject();
            JsonElement analyzerElement = raw.get("analyzer");
            if (analyzerElement == null ||
                    !analyzerElement.isJsonPrimitive() ||
                    !analyzerElement.getAsJsonPrimitive().isString()) {
                throw new IllegalArgumentException(
                    "changes[" + i +
                    "].analyzer must be a non-empty exact name");
            }
            String analyzer = analyzerElement.getAsString();
            if (analyzer == null || analyzer.isBlank()) {
                throw new IllegalArgumentException(
                    "changes[" + i + "].analyzer must be a non-empty exact name");
            }
            if (!analyzer.equals(analyzer.trim())) {
                throw new IllegalArgumentException(
                    "changes[" + i + "].analyzer must use the exact analyzer name");
            }
            if (!names.add(analyzer)) {
                throw new IllegalArgumentException(
                    "duplicate analyzer: " + analyzer);
            }

            JsonElement enabledElement = raw.get("enabled");
            if (enabledElement == null ||
                    !enabledElement.isJsonPrimitive() ||
                    !enabledElement.getAsJsonPrimitive().isBoolean()) {
                throw new IllegalArgumentException(
                    "changes[" + i + "].enabled must be a boolean");
            }
            changes.add(new AnalyzerChange(
                analyzer, enabledElement.getAsBoolean()));
        }
        return List.copyOf(changes);
    }

    private static Map<String, AnalyzerDescriptor> indexDescriptors(
            List<AnalyzerDescriptor> descriptors) {
        Map<String, AnalyzerDescriptor> byName = new LinkedHashMap<>();
        for (AnalyzerDescriptor descriptor : descriptors) {
            AnalyzerDescriptor previous =
                byName.putIfAbsent(descriptor.analyzer(), descriptor);
            if (previous != null) {
                throw new IllegalStateException(
                    "Duplicate analyzer discovery name: " +
                    descriptor.analyzer());
            }
        }
        return byName;
    }

    private static void restore(
            Backend backend,
            Map<String, Boolean> originals,
            Exception failure) {
        List<Exception> rollbackFailures = new ArrayList<>();
        for (Map.Entry<String, Boolean> original : originals.entrySet()) {
            try {
                backend.setEnabled(original.getKey(), original.getValue());
            }
            catch (Exception rollbackFailure) {
                rollbackFailures.add(rollbackFailure);
            }
        }
        try {
            backend.synchronize();
        }
        catch (Exception rollbackFailure) {
            rollbackFailures.add(rollbackFailure);
        }
        for (Map.Entry<String, Boolean> original : originals.entrySet()) {
            try {
                boolean observed = backend.readEnabled(original.getKey());
                if (observed != original.getValue()) {
                    rollbackFailures.add(new IllegalStateException(
                        "Rollback observed analyzer '" + original.getKey() +
                        "' enabled=" + observed + ", expected=" +
                        original.getValue()));
                }
            }
            catch (Exception rollbackFailure) {
                rollbackFailures.add(rollbackFailure);
            }
        }
        rollbackFailures.forEach(failure::addSuppressed);
    }
}
