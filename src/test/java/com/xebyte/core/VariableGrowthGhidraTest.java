package com.xebyte.core;

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;

import com.xebyte.headless.DirectThreadingStrategy;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.pcode.HighSymbol;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.Test;

public class VariableGrowthGhidraTest {
    @Test
    public void growingDecompiledStackLocalPersists() throws Exception {
        ControlFlowServiceGhidraTest.initializeGhidra();
        ProgramBuilder builder = new ProgramBuilder("stack-growth", "x86:LE:32:default", "gcc", this);
        try {
            var program = builder.getProgram();
            builder.createMemory(".text", "0x1000", 0x1100);
            builder.setBytes("0x1000", Files.readString(
                Path.of("src/test/resources/fixtures/stack-local-growth-x86.hex")).trim());
            builder.setBytes("0x2000", "c3");
            builder.disassemble("0x2000", 1);
            builder.createFunction("0x2000");
            builder.disassemble("0x1000", 30);
            var function = builder.createFunction("0x1000");
            var service = new FunctionService(mock(ProgramProvider.class), new DirectThreadingStrategy());
            var result = service.decompileFunction(function, program);
            assertTrue(result.getErrorMessage(), result.decompileCompleted());
            var symbols = result.getHighFunction().getLocalSymbolMap().getSymbols();
            HighSymbol symbol = null;
            while (symbols.hasNext()) {
                var candidate = symbols.next();
                if (!candidate.isParameter() && candidate.getStorage().isStackStorage()
                        && candidate.getSize() == 4) { symbol = candidate; break; }
            }
            assertNotNull("fixture must have a four-byte stack local", symbol);
            StringBuilder error = new StringBuilder();
            assertTrue(error.toString(), service.updateVariableType(program, symbol,
                LongLongDataType.dataType, new AtomicBoolean(), error));
            assertEquals(8, function.getLocalVariables()[0].getDataType().getLength());
        }
        finally { builder.dispose(); }
    }
}
