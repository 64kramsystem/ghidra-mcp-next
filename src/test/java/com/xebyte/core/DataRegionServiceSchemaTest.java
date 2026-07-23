package com.xebyte.core;

import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class DataRegionServiceSchemaTest {
    @Test
    public void regionsSchemaKeepsNestedFlatUnion() {
        AnnotationScanner scanner = new AnnotationScanner(
            new DataRegionService(new EmptyProvider(), new DirectThreading()));
        String schema = scanner.generateSchema();
        assertTrue(schema.contains("\"path\": \"/apply_data_regions\""));
        assertTrue(schema.contains("\"oneOf\""));
        assertTrue(schema.contains("\"pointers\""));
        assertTrue(schema.contains("\"split_pointer_table\""));
    }

    private static final class EmptyProvider implements ProgramProvider {
        public ghidra.program.model.listing.Program getCurrentProgram() {
            return null;
        }
        public ghidra.program.model.listing.Program getProgram(String name) {
            return null;
        }
        public ghidra.program.model.listing.Program[] getAllOpenPrograms() {
            return new ghidra.program.model.listing.Program[0];
        }
        public void setCurrentProgram(
                ghidra.program.model.listing.Program program) {
        }
    }

    private static final class DirectThreading implements ThreadingStrategy {
        @Override
        public <T> T executeRead(java.util.concurrent.Callable<T> action)
                throws Exception {
            return action.call();
        }

        @Override
        public <T> T executeWrite(
                ghidra.program.model.listing.Program program,
                String description,
                java.util.concurrent.Callable<T> action) throws Exception {
            return action.call();
        }

        @Override
        public boolean isHeadless() {
            return true;
        }
    }
}
