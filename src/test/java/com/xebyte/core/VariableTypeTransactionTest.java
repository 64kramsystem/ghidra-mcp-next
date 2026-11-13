package com.xebyte.core;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.Test;
import org.mockito.MockedStatic;
import com.xebyte.headless.DirectThreadingStrategy;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.SourceType;

public class VariableTypeTransactionTest {
    @Test
    public void commitsOnlyWhenDatabaseReadbackMatches() {
        Program program = mock(Program.class);
        Function function = mock(Function.class);
        HighSymbol symbol = mock(HighSymbol.class);
        DataType requested = mock(DataType.class);
        DataType persisted = mock(DataType.class);
        Variable variable = mock(Variable.class);
        when(program.startTransaction(anyString())).thenReturn(42);
        when(symbol.getName()).thenReturn("local");
        when(variable.getName()).thenReturn("local");
        when(variable.getDataType()).thenReturn(persisted);
        when(function.getAllVariables()).thenReturn(new Variable[] {variable});
        FunctionService service = new FunctionService(mock(ProgramProvider.class), new DirectThreadingStrategy());
        try (MockedStatic<HighFunctionDBUtil> update = mockStatic(HighFunctionDBUtil.class)) {
            AtomicBoolean success = new AtomicBoolean();
            StringBuilder error = new StringBuilder();
            assertFalse(service.updateVariableType(program, function, symbol, requested, success, error));
            assertFalse(success.get());
            assertTrue(error.toString().contains("did not persist"));
            verify(program).endTransaction(42, false);
            when(persisted.isEquivalent(requested)).thenReturn(true);
            assertTrue(service.updateVariableType(program, function, symbol, requested, success, new StringBuilder()));
            assertTrue(success.get());
            verify(program).endTransaction(42, true);
            update.verify(() -> HighFunctionDBUtil.updateDBVariable(symbol, "local", requested, SourceType.USER_DEFINED), times(2));
        }
    }
}
