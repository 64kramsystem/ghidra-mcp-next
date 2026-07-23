package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.google.gson.JsonParser;
import java.util.List;
import org.junit.Test;

public class SymbolProfileParserTest {

    @Test
    public void parsesAndNormalizesTheCompleteVersionOneSchema() {
        SymbolProfileParser.SymbolProfile profile = parse("""
            {
              "schema_version": 1,
              "id": "example.machine",
              "version": "2026.07",
              "description": "Example profile",
              "symbols": [{
                "address": "ram:1000",
                "name": "START",
                "namespace": "Example::ROM",
                "kind": "entry_point",
                "primary": true,
                "source_note": "manual"
              }],
              "equates": [{
                "name": "MASK",
                "value": 128,
                "description": "high bit",
                "applications": [{
                  "address": "ram:1010",
                  "operand_index": 1,
                  "scalar_index": 0
                }]
              }],
              "comments": [{
                "address": "ram:1020",
                "type": "plate",
                "text": "header"
              }],
              "memory_blocks": [{
                "name": "io",
                "start": "ram:d000",
                "length": 4096,
                "fill": 255,
                "overlay": false,
                "read": true,
                "write": true,
                "execute": false,
                "comment": "registers"
              }]
            }
            """);

        assertEquals(1, profile.schemaVersion());
        assertEquals("example.machine", profile.id());
        assertEquals("2026.07", profile.version());
        assertEquals(SymbolProfileParser.SymbolKind.ENTRY_POINT,
            profile.symbols().get(0).kind());
        assertEquals("Example::ROM", profile.symbols().get(0).namespace());
        assertTrue(profile.symbols().get(0).primary());
        assertEquals(128L, profile.equates().get(0).value());
        assertEquals(1,
            profile.equates().get(0).applications().get(0).operandIndex());
        assertEquals(Integer.valueOf(0),
            profile.equates().get(0).applications().get(0).scalarIndex());
        assertEquals(SymbolProfileParser.CommentType.PLATE,
            profile.comments().get(0).type());
        assertEquals(4096L, profile.memoryBlocks().get(0).length());
        assertEquals(Integer.valueOf(255),
            profile.memoryBlocks().get(0).fill());
    }

    @Test
    public void absentCollectionsAndOptionalFieldsNormalizeImmutably() {
        SymbolProfileParser.SymbolProfile profile = parse("""
            {"schema_version":1,"id":"minimal","version":"1"}
            """);

        assertEquals(List.of(), profile.symbols());
        assertEquals(List.of(), profile.equates());
        assertEquals(List.of(), profile.comments());
        assertEquals(List.of(), profile.memoryBlocks());
        assertEquals("", profile.description());
        assertThrows(UnsupportedOperationException.class,
            () -> profile.symbols().add(null));
    }

    @Test
    public void rejectsUnknownFieldsAtEveryObjectLevel() {
        assertRejected("""
            {"schema_version":1,"id":"x","version":"1","extra":true}
            """, "unknown field 'extra'");
        assertRejected("""
            {"schema_version":1,"id":"x","version":"1",
             "symbols":[{"address":"1000","name":"X","extra":true}]}
            """, "symbols[0]: unknown field 'extra'");
        assertRejected("""
            {"schema_version":1,"id":"x","version":"1",
             "equates":[{"name":"X","value":1,
               "applications":[{"address":"1000","operand_index":0,"extra":true}]}]}
            """, "applications[0]: unknown field 'extra'");
        assertRejected("""
            {"schema_version":1,"id":"x","version":"1",
             "comments":[{"address":"1000","type":"plate","text":"x","extra":true}]}
            """, "comments[0]: unknown field 'extra'");
        assertRejected("""
            {"schema_version":1,"id":"x","version":"1",
             "memory_blocks":[{"name":"x","start":"1000","length":1,"extra":true}]}
            """, "memory_blocks[0]: unknown field 'extra'");
    }

    @Test
    public void rejectsDuplicateObjectIdentitiesBeforeProgramLookup() {
        assertRejected("""
            {"schema_version":1,"id":"x","version":"1","symbols":[
              {"address":"ram:1000","name":"X","namespace":"A"},
              {"address":"ram:1001","name":"X","namespace":"A"}]}
            """, "duplicate symbol identity");
        assertRejected("""
            {"schema_version":1,"id":"x","version":"1","equates":[
              {"name":"MASK","value":1},{"name":"MASK","value":1}]}
            """, "duplicate equate identity");
        assertRejected("""
            {"schema_version":1,"id":"x","version":"1","comments":[
              {"address":"1000","type":"plate","text":"a"},
              {"address":"1000","type":"plate","text":"b"}]}
            """, "duplicate comment identity");
        assertRejected("""
            {"schema_version":1,"id":"x","version":"1","memory_blocks":[
              {"name":"ram","start":"1000","length":1},
              {"name":"ram","start":"2000","length":1}]}
            """, "duplicate memory block identity");
        assertRejected("""
            {"schema_version":1,"id":"x","version":"1","equates":[{
              "name":"MASK","value":1,"applications":[
                {"address":"1000","operand_index":0,"scalar_index":0},
                {"address":"1000","operand_index":0,"scalar_index":0}]}]}
            """, "duplicate equate application identity");
    }

    @Test
    public void enforcesStrictScalarTypesEnumsNamesAndBounds() {
        assertRejected("""
            {"schema_version":"1","id":"x","version":"1"}
            """, "schema_version must be an integer");
        assertRejected("""
            {"schema_version":2,"id":"x","version":"1"}
            """, "unsupported schema_version");
        assertRejected("""
            {"schema_version":1,"id":"","version":"1"}
            """, "id must not be blank");
        assertRejected("""
            {"schema_version":1,"id":"x","version":"1","symbols":[{
              "address":"1000","name":"bad name"}]}
            """, "invalid symbol name");
        assertRejected("""
            {"schema_version":1,"id":"x","version":"1","symbols":[{
              "address":"1000","name":"X","kind":"function"}]}
            """, "kind");
        assertRejected("""
            {"schema_version":1,"id":"x","version":"1","equates":[{
              "name":"X","value":1.5}]}
            """, "value must be an integer");
        assertRejected("""
            {"schema_version":1,"id":"x","version":"1","comments":[{
              "address":"1000","type":"invalid","text":"x"}]}
            """, "type");
        assertRejected("""
            {"schema_version":1,"id":"x","version":"1","memory_blocks":[{
              "name":"x","start":"1000","length":0}]}
            """, "length must be positive");
        assertRejected("""
            {"schema_version":1,"id":"x","version":"1","memory_blocks":[{
              "name":"x","start":"1000","length":1,"fill":256}]}
            """, "fill");
        assertRejected("""
            {"schema_version":1,"id":"x","version":"1","memory_blocks":[{
              "name":"bad\\nname","start":"1000","length":1}]}
            """, "invalid memory block name");
    }

    private static SymbolProfileParser.SymbolProfile parse(String json) {
        return new SymbolProfileParser().parse(
            JsonParser.parseString(json));
    }

    private static void assertRejected(String json, String messageFragment) {
        IllegalArgumentException error = assertThrows(
            IllegalArgumentException.class, () -> parse(json));
        assertTrue(
            "Expected '" + messageFragment + "' in: " + error.getMessage(),
            error.getMessage().contains(messageFragment));
    }
}
