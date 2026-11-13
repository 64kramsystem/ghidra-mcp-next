package com.xebyte.core;

import static org.junit.Assert.*;
import org.junit.Test;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.*;
import java.util.concurrent.atomic.AtomicBoolean;
import com.xebyte.headless.DirectThreadingStrategy;
import static org.mockito.Mockito.mock;

public class VariablePointerGhidraTest {
    @Test
    public void opaquePointerTypePersists() throws Exception {
        ControlFlowServiceGhidraTest.initializeGhidra();
        ProgramBuilder builder = new ProgramBuilder("pointer-readback", ProgramBuilder._X64, "gcc", this);
        try {
            var program = builder.getProgram();
            builder.createMemory(".text", "0x1000", 0x1100);
            builder.setBytes("0x1000", "53 e8 fa 0f 00 00 48 89 c3 48 85 c0 74 08 48 89 c7 e8 fa 0f 00 00 48 89 d8 5b c3");
            builder.setBytes("0x2000", "c3");
            builder.setBytes("0x2010", "c3");
            builder.disassemble("0x2000", 1);
            builder.disassemble("0x2010", 1);
            builder.createFunction("0x2000");
            builder.createFunction("0x2010");
            builder.disassemble("0x1000", 27);
            Function function = builder.createFunction("0x1000");
            ProgramProvider provider = mock(ProgramProvider.class);
            FunctionService service = new FunctionService(provider, new DirectThreadingStrategy());
            var result = service.decompileFunction(function, program);
            assertTrue(result.getErrorMessage(), result.decompileCompleted());
            var symbols = result.getHighFunction().getLocalSymbolMap().getSymbols();
            HighSymbol symbol = null;
            while (symbols.hasNext()) {
                HighSymbol candidate = symbols.next();
                if (!candidate.isParameter() && !candidate.getName().startsWith("unaff_")
                        && !candidate.getName().startsWith("in_")
                        && !candidate.getName().startsWith("extraout_")) {
                    symbol = candidate;
                    break;
                }
            }
            assertNotNull(symbol);
            DataType requested = ServiceUtils.resolveDataType(program.getDataTypeManager(), "void *");
            StringBuilder error = new StringBuilder();
            assertTrue(error.toString(), service.updateVariableType(
                program, symbol, requested, new AtomicBoolean(), error));
            Variable persisted = HighFunctionDBUtil.getFunctionVariable(symbol);
            assertNotNull(persisted);
            assertTrue("requested=" + requested + ", stored=" + persisted.getDataType(),
                requested.isEquivalent(persisted.getDataType()));
        } finally { builder.dispose(); }
    }
}
