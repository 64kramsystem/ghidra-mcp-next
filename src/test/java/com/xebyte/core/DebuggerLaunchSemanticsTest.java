package com.xebyte.core;

import static org.junit.Assert.assertThrows;

import java.math.BigDecimal;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import junit.framework.TestCase;

public class DebuggerLaunchSemanticsTest extends TestCase {
    public void testDecodesExactOfferParameterNamesAndScalarValues() {
        Map<String, Object> raw = new LinkedHashMap<>();
        raw.put("env:OPT_PRG_FILE", "/tmp/game disk.d64");
        raw.put("env:OPT_PORT", new BigDecimal("6512"));
        raw.put("env:OPT_MUTE_AUDIO", true);

        Map<String, String> decoded = DebuggerLaunchSemantics.decodeLauncherArguments(
                raw,
                Set.of("env:OPT_PRG_FILE", "env:OPT_PORT", "env:OPT_MUTE_AUDIO"));

        assertEquals("/tmp/game disk.d64", decoded.get("env:OPT_PRG_FILE"));
        assertEquals("6512", decoded.get("env:OPT_PORT"));
        assertEquals("true", decoded.get("env:OPT_MUTE_AUDIO"));
    }

    public void testRejectsParameterNamesNotPublishedByTheSelectedOffer() {
        IllegalArgumentException error = assertThrows(
                IllegalArgumentException.class,
                () -> DebuggerLaunchSemantics.decodeLauncherArguments(
                        Map.of("env:NOT_A_PARAMETER", "value"),
                        Set.of("env:OPT_PRG_FILE")));

        assertTrue(error.getMessage().contains("env:NOT_A_PARAMETER"));
        assertTrue(error.getMessage().contains("env:OPT_PRG_FILE"));
    }

    public void testRejectsNestedLauncherParameterValues() {
        IllegalArgumentException error = assertThrows(
                IllegalArgumentException.class,
                () -> DebuggerLaunchSemantics.decodeLauncherArguments(
                        Map.of("env:OPT_EXTRA_VICE_ARGS", List.of("-warp")),
                        Set.of("env:OPT_EXTRA_VICE_ARGS")));

        assertTrue(error.getMessage().contains("must be a string, number, or boolean"));
    }
}
