package com.xebyte.offline;

import com.xebyte.core.EmulationService;
import com.xebyte.core.Response;
import com.xebyte.core.ThreadingStrategy;
import junit.framework.TestCase;

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Graceful-degradation coverage for EmulationService (previously no behavioral tests).
 * emulate_function must return a clean "No program loaded" error rather than throw when no
 * binary is loaded.
 */
public class EmulationServiceValidationTest extends TestCase {

    private EmulationService emulation;

    @Override
    protected void setUp() {
        ThreadingStrategy ts = new NoopThreadingStrategy();
        emulation = new EmulationService(ServiceFactory.stubProvider(), ts);
    }

    public void testEmulateFunctionDegradesGracefully() {
        Response r = emulation.emulateFunction("0x401000", "", "", 10000, "", "");
        assertNotNull(r);
        assertTrue("expected 'No program loaded', got: " + r.toJson(),
                r.toJson().contains("No program loaded"));
    }

    public void testModernEmulatorUsesBoundedInstructionStepping() throws Exception {
        String source = Files.readString(Path.of(System.getProperty("user.dir"),
            "src/main/java/com/xebyte/core/EmulationService.java"));

        assertTrue("Emulation must use Ghidra 12.1's PcodeEmulator",
            source.contains("PcodeEmulator"));
        assertTrue("Emulation must advance with bounded instruction steps",
            source.contains("stepInstruction()"));
        assertFalse("Batch emulation must not use an unbounded run loop",
            source.contains("emu.run("));

        String batchSource = source.substring(source.indexOf("public Response emulateHashBatch"));
        assertTrue("Batch emulation must apply a hard step cap",
            batchSource.contains("DEFAULT_MAX_STEPS"));
    }

    public void testSingleEmulationResponseContractRemainsDocumented() throws Exception {
        String source = Files.readString(Path.of(System.getProperty("user.dir"),
            "src/main/java/com/xebyte/core/EmulationService.java"));
        for (String field : new String[]{
                "success", "steps_executed", "max_steps", "stop_reason",
                "final_pc", "hit_return", "registers"}) {
            assertTrue("single-emulation response field missing: " + field,
                source.contains("result.put(\"" + field + "\""));
        }
    }
}
