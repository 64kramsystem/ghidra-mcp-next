package com.xebyte.core;

import junit.framework.TestCase;

/**
 * Offline checks for {@code this} routing and pointer normalization helpers.
 */
public class FunctionServiceThisTypeTest extends TestCase {

    public void testResolveThisPointerTypeReturnsNullWithoutDataTypeManager() {
        assertNull(FunctionService.resolveThisPointerType(null, "MyStruct"));
        assertNull(FunctionService.resolveThisPointerType(null, "  "));
        assertNull(FunctionService.resolveThisPointerType(null, ""));
    }
}
