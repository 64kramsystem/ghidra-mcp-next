package com.xebyte.core;

import junit.framework.TestCase;

/** Unit tests for struct resize rules. */
public class DataTypeServiceStructResizeTest extends TestCase {

    public void testValidateStructResizeAllowsGrow() {
        assertNull(DataTypeService.validateStructResize(120, "TestStruct", 240, false));
    }

    public void testValidateStructResizeRejectsShrinkWithoutForce() {
        String err = DataTypeService.validateStructResize(120, "TestStruct", 64, false);
        assertNotNull(err);
        assertTrue(err.contains("Cannot shrink"));
        assertTrue(err.contains("120"));
    }

    public void testValidateStructResizeAllowsShrinkWithForce() {
        assertNull(DataTypeService.validateStructResize(120, "TestStruct", 64, true));
    }

    public void testValidateStructResizeRejectsNonPositiveSize() {
        String err = DataTypeService.validateStructResize(8, "TestStruct", 0, true);
        assertNotNull(err);
        assertTrue(err.contains("positive"));
    }
}
