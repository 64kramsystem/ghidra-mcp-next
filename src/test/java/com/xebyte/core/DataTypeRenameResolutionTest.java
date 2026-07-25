package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Iterator;
import java.util.List;

import org.junit.Test;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;

/**
 * Name resolution for rename_data_type.
 *
 * <p>ServiceUtils.findDataTypeByNameInAllCategories, which upstream's version of this endpoint
 * calls, compares {@code getName()} only. A category-qualified name therefore never matches it,
 * and two same-named types in different categories resolve to whichever the iterator reaches
 * first -- renaming the wrong type, silently. These pin the stricter behaviour.
 */
public class DataTypeRenameResolutionTest {

    private static DataType type(String name, String pathName) {
        DataType dt = mock(DataType.class);
        when(dt.getName()).thenReturn(name);
        when(dt.getPathName()).thenReturn(pathName);
        return dt;
    }

    private static DataTypeManager managerOf(List<DataType> types) {
        DataTypeManager dtm = mock(DataTypeManager.class);
        when(dtm.getAllDataTypes()).thenAnswer(invocation -> {
            Iterator<DataType> it = types.iterator();
            return it;
        });
        return dtm;
    }

    @Test
    public void aUniqueBareNameResolves() {
        DataType foo = type("Foo", "/Foo");
        StringBuilder problem = new StringBuilder();

        DataType found = DataTypeService.resolveExactDataType(
                managerOf(List.of(foo)), "Foo", problem);

        assertEquals(foo, found);
        assertEquals("", problem.toString());
    }

    @Test
    public void anAmbiguousBareNameIsRefusedAndListsThePaths() {
        DataType a = type("Foo", "/CatA/Foo");
        DataType b = type("Foo", "/CatB/Foo");
        StringBuilder problem = new StringBuilder();

        DataType found = DataTypeService.resolveExactDataType(
                managerOf(List.of(a, b)), "Foo", problem);

        assertNull("must not silently pick one", found);
        assertTrue(problem.toString(), problem.toString().contains("Ambiguous"));
        assertTrue(problem.toString(), problem.toString().contains("/CatA/Foo"));
        assertTrue(problem.toString(), problem.toString().contains("/CatB/Foo"));
    }

    @Test
    public void aQualifiedNameResolvesByExactPath() {
        DataType b = type("Foo", "/CatB/Foo");
        DataTypeManager dtm = managerOf(List.of(type("Foo", "/CatA/Foo"), b));
        when(dtm.getDataType("/CatB/Foo")).thenReturn(b);
        StringBuilder problem = new StringBuilder();

        DataType found = DataTypeService.resolveExactDataType(dtm, "/CatB/Foo", problem);

        assertEquals(b, found);
        assertNotNull(found);
    }

    @Test
    public void aQualifiedNameThatMatchesNothingSaysSo() {
        DataTypeManager dtm = managerOf(List.of());
        when(dtm.getDataType("/Nope/Foo")).thenReturn(null);
        StringBuilder problem = new StringBuilder();

        assertNull(DataTypeService.resolveExactDataType(dtm, "/Nope/Foo", problem));
        assertTrue(problem.toString(), problem.toString().contains("not found at path"));
    }

    @Test
    public void anUnknownBareNameSaysSo() {
        StringBuilder problem = new StringBuilder();

        assertNull(DataTypeService.resolveExactDataType(
                managerOf(List.of(type("Bar", "/Bar"))), "Foo", problem));
        assertTrue(problem.toString(), problem.toString().contains("Data type not found: Foo"));
    }
}
