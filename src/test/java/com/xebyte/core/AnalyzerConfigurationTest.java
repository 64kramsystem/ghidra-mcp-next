package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

/**
 * Pure unit tests for the validation and atomic mutation core used by both GUI
 * and headless analyzer-configuration endpoints.
 */
public class AnalyzerConfigurationTest {

    private FakeBackend backend;

    @Before
    public void setUp() {
        backend = new FakeBackend(List.of(
            descriptor("Reference", true),
            descriptor("Function Start Search", true),
            descriptor("Unavailable For CPU", false)));
        backend.states.put("Reference", true);
        backend.states.put("Function Start Search", false);
        backend.states.put("Unavailable For CPU", true);
    }

    @Test
    public void exactNameLookupRejectsCaseFoldedNameBeforeMutation() {
        IllegalArgumentException error = assertThrows(
            IllegalArgumentException.class,
            () -> configure(change("reference", false), false));

        assertTrue(error.getMessage(), error.getMessage().contains("reference"));
        assertTrue(
            error.getMessage(),
            error.getMessage().contains("available analyzers"));
        assertEquals(Map.of(
            "Reference", true,
            "Function Start Search", false,
            "Unavailable For CPU", true), backend.states);
        assertTrue(backend.writes.isEmpty());
    }

    @Test
    public void unavailableAnalyzerIsRejectedBeforeMutation() {
        IllegalArgumentException error = assertThrows(
            IllegalArgumentException.class,
            () -> configure(change("Unavailable For CPU", false), false));

        assertTrue(error.getMessage(), error.getMessage().contains("unavailable"));
        assertTrue(backend.writes.isEmpty());
    }

    @Test
    public void duplicateNamesAreRejectedBeforeMutation() {
        IllegalArgumentException error = assertThrows(
            IllegalArgumentException.class,
            () -> AnalyzerConfiguration.configure(
                backend,
                JsonHelper.toJson(List.of(
                    change("Reference", false),
                    change("Reference", true))),
                false));

        assertTrue(error.getMessage(), error.getMessage().contains("duplicate analyzer"));
        assertTrue(backend.writes.isEmpty());
    }

    @Test
    public void allChangesAreValidatedBeforeFirstMutation() {
        IllegalArgumentException error = assertThrows(
            IllegalArgumentException.class,
            () -> AnalyzerConfiguration.configure(
                backend,
                JsonHelper.toJson(List.of(
                    change("Reference", false),
                    change("missing", false))),
                false));

        assertTrue(error.getMessage(), error.getMessage().contains("missing"));
        assertTrue(backend.writes.isEmpty());
        assertTrue(backend.states.get("Reference"));
    }

    @Test
    public void dryRunReportsRequestedAnalyzersOnlyInRequestOrder() throws Exception {
        AnalyzerConfiguration.Outcome result =
            AnalyzerConfiguration.configure(
                backend,
                JsonHelper.toJson(List.of(
                    change("Function Start Search", true),
                    change("Reference", false))),
                true);

        assertTrue(result.dryRun());
        assertFalse(result.committed());
        assertEquals(
            List.of("Function Start Search", "Reference"),
            result.analyzers().stream()
                .map(AnalyzerConfiguration.AnalyzerState::analyzer)
                .toList());
        assertEquals(false, result.analyzers().get(0).before());
        assertEquals(true, result.analyzers().get(0).requested());
        assertEquals(false, result.analyzers().get(0).after());
        assertTrue(backend.writes.isEmpty());
        assertEquals(0, backend.synchronizations);
    }

    @Test
    public void successfulCommitReportsObservedStateAndDoesNotRunAnalysis()
            throws Exception {
        AnalyzerConfiguration.Outcome result =
            configure(change("Reference", false), false);

        assertFalse(result.dryRun());
        assertTrue(result.committed());
        assertEquals(true, result.analyzers().get(0).before());
        assertEquals(false, result.analyzers().get(0).requested());
        assertEquals(false, result.analyzers().get(0).after());
        assertFalse(backend.states.get("Reference"));
        assertEquals(1, backend.synchronizations);
        assertEquals(
            "the configuration core has no analyzer-execution operation",
            0,
            backend.analysisRuns);
    }

    @Test
    public void setterFailureRestoresEveryOriginalState() {
        backend.failSetName = "Function Start Search";

        Exception error = assertThrows(
            Exception.class,
            () -> AnalyzerConfiguration.configure(
                backend,
                JsonHelper.toJson(List.of(
                    change("Reference", false),
                    change("Function Start Search", true))),
                false));

        assertTrue(error.getMessage(), error.getMessage().contains("synthetic set failure"));
        assertTrue(backend.states.get("Reference"));
        assertFalse(backend.states.get("Function Start Search"));
        assertTrue(
            "rollback must synchronize the scheduler after restoring options",
            backend.synchronizations >= 1);
    }

    @Test
    public void observationFailureRestoresEveryOriginalState() {
        backend.mismatchName = "Function Start Search";

        Exception error = assertThrows(
            Exception.class,
            () -> AnalyzerConfiguration.configure(
                backend,
                JsonHelper.toJson(List.of(
                    change("Reference", false),
                    change("Function Start Search", true))),
                false));

        assertTrue(error.getMessage(), error.getMessage().contains("observed"));
        assertTrue(backend.states.get("Reference"));
        assertFalse(backend.states.get("Function Start Search"));
        assertEquals(2, backend.synchronizations);
    }

    @Test
    public void malformedBooleanIsRejectedRatherThanCoerced() {
        IllegalArgumentException error = assertThrows(
            IllegalArgumentException.class,
            () -> configure(Map.of(
                "analyzer", "Reference",
                "enabled", "yes"), false));

        assertTrue(error.getMessage(), error.getMessage().contains("boolean"));
        assertTrue(backend.writes.isEmpty());
    }

    @Test
    public void malformedArrayElementAfterValidChangeCannotBeDropped() {
        IllegalArgumentException error = assertThrows(
            IllegalArgumentException.class,
            () -> AnalyzerConfiguration.configure(
                backend,
                """
                [
                  {"analyzer":"Reference","enabled":false},
                  "not an object"
                ]
                """,
                false));

        assertTrue(error.getMessage(), error.getMessage().contains("must be an object"));
        assertTrue(backend.writes.isEmpty());
        assertTrue(backend.states.get("Reference"));
    }

    private AnalyzerConfiguration.Outcome configure(
            Map<String, Object> change, boolean dryRun) throws Exception {
        return AnalyzerConfiguration.configure(
            backend, JsonHelper.toJson(List.of(change)), dryRun);
    }

    private static Map<String, Object> change(String name, boolean enabled) {
        return Map.of(
            "analyzer", name,
            "enabled", enabled);
    }

    private static AnalyzerConfiguration.AnalyzerDescriptor descriptor(
            String name, boolean available) {
        return new AnalyzerConfiguration.AnalyzerDescriptor(
            name,
            "description for " + name,
            "INSTRUCTION_ANALYZER",
            "DATA_TYPE_PROPOGATION",
            available);
    }

    private static final class FakeBackend
            implements AnalyzerConfiguration.Backend {
        private final List<AnalyzerConfiguration.AnalyzerDescriptor> descriptors;
        private final Map<String, Boolean> states = new LinkedHashMap<>();
        private final List<String> writes = new ArrayList<>();
        private int synchronizations;
        private int analysisRuns;
        private String failSetName;
        private String mismatchName;
        private boolean synchronizedSinceMutation;

        FakeBackend(List<AnalyzerConfiguration.AnalyzerDescriptor> descriptors) {
            this.descriptors = descriptors;
        }

        @Override
        public List<AnalyzerConfiguration.AnalyzerDescriptor> descriptors() {
            return descriptors;
        }

        @Override
        public boolean readEnabled(String analyzer) {
            boolean state = states.get(analyzer);
            if (synchronizedSinceMutation && analyzer.equals(mismatchName)) {
                return !state;
            }
            return state;
        }

        @Override
        public void setEnabled(String analyzer, boolean enabled) {
            writes.add(analyzer + "=" + enabled);
            if (analyzer.equals(failSetName) &&
                    enabled != states.get(analyzer)) {
                throw new IllegalStateException("synthetic set failure");
            }
            states.put(analyzer, enabled);
            synchronizedSinceMutation = false;
        }

        @Override
        public void synchronize() {
            synchronizations++;
            synchronizedSinceMutation = true;
        }
    }
}
