package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

/**
 * Offline coverage for {@code /search_address_encodings}.
 *
 * <p>The endpoint reports byte windows that numerically decode into a destination range,
 * so it carries false positives by construction; what it must never do is attribute one
 * overlay occupant's references to another. Two of the fixtures below query the same
 * offsets in two spaces for exactly that reason.</p>
 */
public class SearchAddressEncodingsTest {

    private static final GenericAddressSpace RAM =
        new GenericAddressSpace("RAM", 16, AddressSpace.TYPE_RAM, 0);
    private static final GenericAddressSpace PLAYER =
        new GenericAddressSpace("SND_PLAYER", 16, AddressSpace.TYPE_RAM, 1);
    private static final GenericAddressSpace WIDE =
        new GenericAddressSpace("WIDE", 64, AddressSpace.TYPE_RAM, 2);

    // ---------------------------------------------------------------- fixture

    private static final class Fixture {
        final Program program = mock(Program.class);
        final Memory memory = mock(Memory.class);
        final Listing listing = mock(Listing.class);
        final SymbolTable symbols = mock(SymbolTable.class);
        final ReferenceManager references = mock(ReferenceManager.class);
        final AddressFactory factory = mock(AddressFactory.class);
        final ProgramProvider provider = mock(ProgramProvider.class);
        final Map<String, byte[]> images = new HashMap<>();
        final List<AddressSpace> spaces = new ArrayList<>();
        final List<MemoryBlock> blocks = new ArrayList<>();
        final AddressSet initialized = new AddressSet();
        final Map<String, Instruction> instructions = new HashMap<>();
        final Map<String, Data> definedData = new HashMap<>();
        final Map<String, List<Reference>> outgoing = new HashMap<>();
        final Map<String, Symbol> primarySymbols = new HashMap<>();
        final com.xebyte.offline.RecordingThreadingStrategy threading =
            new com.xebyte.offline.RecordingThreadingStrategy();
        long modificationNumber = 4213;
        long uniqueProgramId = 0x1234L;
        boolean bumpModificationOnRead;
        boolean bumpModificationOnReferenceRead;

        Fixture block(String name, AddressSpace space, byte[] image) {
            images.put(space.getName(), image);
            if (!spaces.contains(space)) spaces.add(space);
            MemoryBlock block = mock(MemoryBlock.class);
            when(block.getName()).thenReturn(name);
            when(block.getStart()).thenReturn(space.getAddress(0));
            when(block.getEnd()).thenReturn(space.getAddress(image.length - 1));
            blocks.add(block);
            initialized.add(space.getAddress(0), space.getAddress(image.length - 1));
            return this;
        }

        /** Two blocks over one image, so a block seam exists at {@code seam}. */
        Fixture splitBlock(AddressSpace space, byte[] image, long seam) {
            images.put(space.getName(), image);
            if (!spaces.contains(space)) spaces.add(space);
            MemoryBlock low = mock(MemoryBlock.class);
            when(low.getName()).thenReturn("low");
            when(low.getStart()).thenReturn(space.getAddress(0));
            when(low.getEnd()).thenReturn(space.getAddress(seam - 1));
            MemoryBlock high = mock(MemoryBlock.class);
            when(high.getName()).thenReturn("high");
            when(high.getStart()).thenReturn(space.getAddress(seam));
            when(high.getEnd()).thenReturn(space.getAddress(image.length - 1));
            blocks.add(low);
            blocks.add(high);
            initialized.add(space.getAddress(0), space.getAddress(image.length - 1));
            return this;
        }

        Fixture instruction(AddressSpace space, long start, int length, String mnemonic) {
            Instruction unit = mock(Instruction.class);
            when(unit.getMinAddress()).thenReturn(space.getAddress(start));
            when(unit.getMaxAddress()).thenReturn(space.getAddress(start + length - 1));
            when(unit.getLength()).thenReturn(length);
            when(unit.toString()).thenReturn(mnemonic);
            for (long at = start; at < start + length; at++) {
                instructions.put(key(space, at), unit);
            }
            return this;
        }

        Fixture data(AddressSpace space, long start, int length, String rendering,
                Map<Long, Long> primitiveStarts) {
            Data unit = mock(Data.class);
            when(unit.getMinAddress()).thenReturn(space.getAddress(start));
            when(unit.getMaxAddress()).thenReturn(space.getAddress(start + length - 1));
            when(unit.getLength()).thenReturn(length);
            when(unit.toString()).thenReturn(rendering);
            for (Map.Entry<Long, Long> entry : primitiveStarts.entrySet()) {
                Data primitive = mock(Data.class);
                when(primitive.getMinAddress())
                    .thenReturn(space.getAddress(entry.getValue()));
                when(primitive.getMaxAddress())
                    .thenReturn(space.getAddress(entry.getValue() + 1));
                when(primitive.toString()).thenReturn("dw");
                when(unit.getPrimitiveAt(entry.getKey().intValue())).thenReturn(primitive);
            }
            for (long at = start; at < start + length; at++) {
                definedData.put(key(space, at), unit);
            }
            return this;
        }

        Fixture reference(AddressSpace fromSpace, long from, AddressSpace toSpace,
                long to, RefType type, SourceType source, int operand) {
            Reference reference = mock(Reference.class);
            when(reference.getFromAddress()).thenReturn(fromSpace.getAddress(from));
            when(reference.getToAddress()).thenReturn(toSpace.getAddress(to));
            when(reference.getReferenceType()).thenReturn(type);
            when(reference.getSource()).thenReturn(source);
            when(reference.getOperandIndex()).thenReturn(operand);
            when(reference.isPrimary()).thenReturn(true);
            outgoing.computeIfAbsent(key(fromSpace, from), ignored -> new ArrayList<>())
                .add(reference);
            return this;
        }

        Fixture symbol(AddressSpace space, long at, String name) {
            Symbol symbol = mock(Symbol.class);
            when(symbol.getName()).thenReturn(name);
            when(symbol.getAddress()).thenReturn(space.getAddress(at));
            primarySymbols.put(key(space, at), symbol);
            return this;
        }

        private static String key(AddressSpace space, long offset) {
            return space.getName() + ":" + offset;
        }

        AddressEncodingSearchService build() {
            when(program.getName()).thenReturn("fixture");
            when(program.getUniqueProgramID()).thenAnswer(i -> uniqueProgramId);
            when(program.getMemory()).thenReturn(memory);
            when(program.getListing()).thenReturn(listing);
            when(program.getSymbolTable()).thenReturn(symbols);
            when(program.getReferenceManager()).thenReturn(references);
            when(program.getAddressFactory()).thenReturn(factory);
            when(program.getModificationNumber()).thenAnswer(i -> modificationNumber);
            when(factory.getAddressSpaces())
                .thenReturn(spaces.toArray(new AddressSpace[0]));
            when(factory.getDefaultAddressSpace()).thenReturn(spaces.get(0));
            when(factory.getAddress(anyString())).thenAnswer(invocation -> {
                String text = invocation.getArgument(0);
                String name = spaces.get(0).getName();
                String offset = text;
                int colon = text.lastIndexOf(':');
                if (colon >= 0) {
                    name = text.substring(0, colon).replace(":", "");
                    offset = text.substring(colon + 1);
                }
                for (AddressSpace space : spaces) {
                    if (space.getName().equals(name)) {
                        return space.getAddress(Long.parseUnsignedLong(offset, 16));
                    }
                }
                return null;
            });
            when(memory.getBlocks()).thenReturn(blocks.toArray(new MemoryBlock[0]));
            when(memory.getAllInitializedAddressSet()).thenReturn(initialized);
            try {
                when(memory.getBytes(any(Address.class), any(byte[].class),
                        anyInt(), anyInt()))
                    .thenAnswer(invocation -> {
                        Address at = invocation.getArgument(0);
                        byte[] buffer = invocation.getArgument(1);
                        int destination = invocation.getArgument(2);
                        int length = invocation.getArgument(3);
                        byte[] image = images.get(at.getAddressSpace().getName());
                        for (int index = 0; index < length; index++) {
                            buffer[destination + index] =
                                image[(int) at.getOffset() + index];
                        }
                        if (bumpModificationOnRead) modificationNumber++;
                        return length;
                    });
            }
            catch (Exception impossible) {
                throw new IllegalStateException(impossible);
            }
            when(listing.getInstructionContaining(any(Address.class)))
                .thenAnswer(invocation -> lookup(instructions, invocation.getArgument(0)));
            when(listing.getDefinedDataContaining(any(Address.class)))
                .thenAnswer(invocation -> lookup(definedData, invocation.getArgument(0)));
            when(symbols.getPrimarySymbol(any(Address.class)))
                .thenAnswer(invocation -> lookup(primarySymbols, invocation.getArgument(0)));
            when(references.getReferencesFrom(any(Address.class)))
                .thenAnswer(invocation -> {
                    if (bumpModificationOnReferenceRead) modificationNumber++;
                    List<Reference> found = lookup(outgoing, invocation.getArgument(0));
                    return found == null
                        ? new Reference[0] : found.toArray(new Reference[0]);
                });
            when(provider.getCurrentProgram()).thenReturn(program);
            when(provider.getProgram(anyString())).thenReturn(program);
            when(provider.getAllOpenPrograms()).thenReturn(new Program[] {program});
            return new AddressEncodingSearchService(provider, threading);
        }

        private static <T> T lookup(Map<String, T> map, Address address) {
            return map.get(address.getAddressSpace().getName() + ":" + address.getOffset());
        }
    }

    private static byte[] image(int size, Map<Integer, Integer> bytes) {
        byte[] image = new byte[size];
        for (Map.Entry<Integer, Integer> entry : bytes.entrySet()) {
            image[entry.getKey()] = entry.getValue().byteValue();
        }
        return image;
    }

    /** Little-endian 16-bit word written at {@code offset}. */
    private static Map<Integer, Integer> word(int offset, int value) {
        Map<Integer, Integer> map = new HashMap<>();
        map.put(offset, value & 0xff);
        map.put(offset + 1, (value >> 8) & 0xff);
        return map;
    }

    @SafeVarargs
    private static Map<Integer, Integer> merge(Map<Integer, Integer>... parts) {
        Map<Integer, Integer> all = new HashMap<>();
        for (Map<Integer, Integer> part : parts) all.putAll(part);
        return all;
    }

    /**
     * The response as a map, parsed from its wire JSON rather than from the service's
     * internal object: {@code cursor: null} is part of the contract, and a test reading
     * the map directly could not tell an emitted null from a dropped key.
     */
    private static Map<String, Object> body(Response response) {
        assertNotNull(response);
        assertFalse("unexpected error: " + response.toJson(),
            response instanceof Response.Err);
        String json = response.toJson();
        assertTrue("cursor must be present even when null: " + json,
            json.contains("\"cursor\""));
        return WIRE_JSON.fromJson(json,
            new com.google.gson.reflect.TypeToken<Map<String, Object>>() { }.getType());
    }

    /** Integral JSON numbers must arrive as Long, not Double, for exact assertions. */
    private static final com.google.gson.Gson WIRE_JSON = new com.google.gson.GsonBuilder()
        .setObjectToNumberStrategy(com.google.gson.ToNumberPolicy.LONG_OR_DOUBLE)
        .create();

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> rows(Response response) {
        return (List<Map<String, Object>>) body(response).get("encodings");
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> refs(Map<String, Object> row) {
        return (List<Map<String, Object>>) row.get("matching_references");
    }

    private static boolean isError(Response response) {
        return response instanceof Response.Err;
    }

    private static List<String> encodingAddresses(Response response) {
        List<String> found = new ArrayList<>();
        for (Map<String, Object> row : rows(response)) {
            found.add((String) row.get("encoding_address"));
        }
        return found;
    }

    // ------------------------------------------------------------- site kinds

    @Test
    public void aPointerInUndefinedBytesIsReportedWithNoReferences() {
        AddressEncodingSearchService service = new Fixture()
            .block("ram", RAM, image(0x20, word(0x10, 0x9680)))
            .build();

        List<Map<String, Object>> rows =
            rows(service.searchAddressEncodings("9680", "9680", 2, "little",
                "", "", 1000, "", ""));

        assertEquals(1, rows.size());
        Map<String, Object> row = rows.get(0);
        assertEquals("RAM:0010", row.get("encoding_address"));
        assertEquals("RAM:0010", row.get("site_address"));
        assertEquals("RAM", row.get("site_space"));
        assertEquals("undefined", row.get("site"));
        assertEquals("9680", row.get("decoded_offset"));
        assertEquals("RAM:9680", row.get("decoded_target"));
        assertEquals(List.of(), refs(row));
        assertFalse("no containing unit means no rendering",
            row.containsKey("site_rendering"));
    }

    @Test
    public void anInstructionSiteCarriesItsReferenceAndTheOperandOffset() {
        // A three-byte JSR at $a884: the window sits one byte past the site.
        AddressEncodingSearchService service = new Fixture()
            .block("ram", RAM, image(0xb000, word(0xa885, 0x9695)))
            .instruction(RAM, 0xa884, 3, "JSR 0x9695")
            .reference(RAM, 0xa884, RAM, 0x9695,
                RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0)
            .build();

        List<Map<String, Object>> rows =
            rows(service.searchAddressEncodings("9695", "9695", 2, "little",
                "", "", 1000, "", ""));

        assertEquals(1, rows.size());
        Map<String, Object> row = rows.get(0);
        assertEquals("RAM:a885", row.get("encoding_address"));
        assertEquals("RAM:a884", row.get("site_address"));
        assertEquals("inside_instruction", row.get("site"));
        assertEquals("JSR 0x9695", row.get("site_rendering"));
        assertEquals(1, refs(row).size());
        assertEquals("RAM:9695", refs(row).get(0).get("to"));
        assertEquals("UNCONDITIONAL_CALL", refs(row).get(0).get("type"));
        assertEquals("user_defined", refs(row).get(0).get("source_kind"));
        assertEquals(0L, refs(row).get(0).get("operand_index"));
        assertEquals(Boolean.TRUE, refs(row).get(0).get("primary"));
    }

    @Test
    public void windowsOnAnOpcodeByteAndAcrossAUnitBoundaryMakeNoOperandClaim() {
        // Both defeat the weaker "instruction_operand" classification: one starts on
        // the opcode, the other straddles two code units. Neither is an operand, and
        // the endpoint says only that the window lies inside instruction bytes.
        byte[] image = image(0x100, merge(
            // $0010: bytes 80 96 -> $9680 read from the opcode byte itself.
            Map.of(0x10, 0x80, 0x11, 0x96),
            // $0020-$0021 is the tail of one unit, $0022 the start of the next.
            Map.of(0x21, 0x81, 0x22, 0x96)));
        AddressEncodingSearchService service = new Fixture()
            .block("ram", RAM, image)
            .instruction(RAM, 0x10, 2, "opcode-unit")
            .instruction(RAM, 0x20, 2, "first-unit")
            .instruction(RAM, 0x22, 2, "second-unit")
            .build();

        List<Map<String, Object>> rows =
            rows(service.searchAddressEncodings("9680", "9681", 2, "little",
                "", "", 1000, "", ""));

        assertEquals(List.of("RAM:0010", "RAM:0021"),
            List.of(rows.get(0).get("encoding_address"),
                rows.get(1).get("encoding_address")));
        assertEquals("inside_instruction", rows.get(0).get("site"));
        assertEquals("RAM:0010", rows.get(0).get("site_address"));
        assertEquals("inside_instruction", rows.get(1).get("site"));
        assertEquals("the straddling window belongs to the unit it starts in",
            "RAM:0020", rows.get(1).get("site_address"));
        for (Map<String, Object> row : rows) {
            assertFalse(row.containsKey("operand_index"));
        }
    }

    @Test
    public void anEncodingInsideAnArrayNamesItsContainerAndReadsTheEntrysReferences() {
        // A dw[4] table at $0300. The window at $0304 is the third entry; references
        // are read from that entry's start, not from the array's.
        AddressEncodingSearchService service = new Fixture()
            .block("ram", RAM, image(0x400, word(0x304, 0x9680)))
            .data(RAM, 0x300, 8, "dw[4]", Map.of(4L, 0x304L))
            .symbol(RAM, 0x300, "DISPATCH_TABLE")
            .reference(RAM, 0x304, RAM, 0x9680, RefType.DATA, SourceType.ANALYSIS, -1)
            .reference(RAM, 0x300, RAM, 0x9680, RefType.DATA, SourceType.ANALYSIS, -1)
            .build();

        Map<String, Object> row =
            rows(service.searchAddressEncodings("9680", "9680", 2, "little",
                "", "", 1000, "", "")).get(0);

        assertEquals("inside_data_unit", row.get("site"));
        assertEquals("RAM:0304", row.get("site_address"));
        @SuppressWarnings("unchecked")
        Map<String, Object> container = (Map<String, Object>) row.get("container");
        assertEquals("RAM:0300", container.get("address"));
        assertEquals("DISPATCH_TABLE", container.get("name"));
        assertEquals(4L, container.get("offset"));
        // Exactly one: the array's own reference must not be attributed to the entry.
        assertEquals(1, refs(row).size());
    }

    @Test
    public void containerIsAbsentOnNonDataSites() {
        AddressEncodingSearchService service = new Fixture()
            .block("ram", RAM, image(0x20, word(0x10, 0x9680)))
            .build();
        assertFalse(rows(service.searchAddressEncodings("9680", "9680", 2, "little",
            "", "", 1000, "", "")).get(0).containsKey("container"));
    }

    // ------------------------------------------------------ space exclusivity

    /**
     * Both occupants of $9680-$98ff, plus the two RAM windows the motivating program
     * has: a player call at $a884 recorded into the overlay, and a disk-loader call at
     * $0453 recorded into RAM. Whichever space is queried, the other's references must
     * not appear.
     */
    private Fixture bothOccupants() {
        return new Fixture()
            .block("ram", RAM, image(0xb000, merge(
                word(0xa885, 0x9695),
                word(0x0454, 0x9700))))
            .block("player", PLAYER, image(0x9900, Map.of()))
            .instruction(RAM, 0xa884, 3, "JSR SND_PLAYER:SND_TICK")
            .instruction(RAM, 0x0453, 3, "JSR DISK_LOADER_ENTRY")
            .reference(RAM, 0xa884, PLAYER, 0x9695,
                RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0)
            .reference(RAM, 0x0453, RAM, 0x9700,
                RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0);
    }

    @Test
    public void anOverlayQueryShowsOnlyTheOverlaysOwnReferences() {
        AddressEncodingSearchService service = bothOccupants().build();

        List<Map<String, Object>> rows = rows(service.searchAddressEncodings(
            "SND_PLAYER:9680", "SND_PLAYER:98ff", 2, "little",
            "RAM:0", "RAM:afff", 1000, "", ""));

        assertEquals(List.of("RAM:0454", "RAM:a885"), encodingAddresses(
            service.searchAddressEncodings("SND_PLAYER:9680", "SND_PLAYER:98ff", 2,
                "little", "RAM:0", "RAM:afff", 1000, "", "")));
        Map<String, Object> loader = rows.get(0);
        assertEquals("SND_PLAYER:9700", loader.get("decoded_target"));
        assertEquals("a real byte window whose recorded reference targets RAM",
            List.of(), refs(loader));
        Map<String, Object> player = rows.get(1);
        assertEquals("SND_PLAYER:9695", player.get("decoded_target"));
        assertEquals(1, refs(player).size());
        assertEquals("SND_PLAYER:9695", refs(player).get(0).get("to"));
    }

    @Test
    public void aRamQueryInvertsExactlyThat() {
        AddressEncodingSearchService service = bothOccupants().build();

        List<Map<String, Object>> rows = rows(service.searchAddressEncodings(
            "RAM:9680", "RAM:98ff", 2, "little", "RAM:0", "RAM:afff", 1000, "", ""));

        assertEquals(2, rows.size());
        assertEquals("RAM:9700", rows.get(0).get("decoded_target"));
        assertEquals(1, refs(rows.get(0)).size());
        assertEquals("RAM:9700", refs(rows.get(0)).get(0).get("to"));
        assertEquals("RAM:9695", rows.get(1).get("decoded_target"));
        assertEquals("the player call targets the overlay, not RAM",
            List.of(), refs(rows.get(1)));
    }

    @Test
    public void aReferenceMatchingOnlyByOffsetIsNotAMatch() {
        // Mutation guard on the space half of the comparison: same offset, wrong space.
        AddressEncodingSearchService service = new Fixture()
            .block("ram", RAM, image(0x20, word(0x10, 0x9695)))
            .block("player", PLAYER, image(0x9700, Map.of()))
            .instruction(RAM, 0x10, 2, "dw")
            .reference(RAM, 0x10, RAM, 0x9695,
                RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0)
            .build();

        Map<String, Object> row = rows(service.searchAddressEncodings(
            "SND_PLAYER:9695", "SND_PLAYER:9695", 2, "little",
            "RAM:0", "RAM:1f", 1000, "", "")).get(0);
        assertEquals(List.of(), refs(row));
    }

    @Test
    public void aReferenceMatchingOnlyBySpaceIsNotAMatch() {
        // Mutation guard on the offset half.
        AddressEncodingSearchService service = new Fixture()
            .block("ram", RAM, image(0x20, word(0x10, 0x9695)))
            .instruction(RAM, 0x10, 2, "dw")
            .reference(RAM, 0x10, RAM, 0x9696,
                RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0)
            .build();

        Map<String, Object> row = rows(service.searchAddressEncodings(
            "9695", "9695", 2, "little", "", "", 1000, "", "")).get(0);
        assertEquals(List.of(), refs(row));
    }

    // ------------------------------------------------------- widths and order

    @Test
    public void everyWidthFromOneToEightDecodesLittleEndian() {
        for (int width = 1; width <= 8; width++) {
            byte[] image = new byte[0x40];
            // A value of 0x10 encoded in `width` little-endian bytes at $0020.
            image[0x20] = 0x10;
            AddressEncodingSearchService service = new Fixture()
                .block("wide", WIDE, image)
                .build();

            Response response = service.searchAddressEncodings(
                "WIDE:10", "WIDE:10", width, "little", "", "", 1000, "", "");
            List<String> found = encodingAddresses(response);
            assertTrue("width " + width + " found " + found,
                found.contains(WIDE.getAddress(0x20).toString(true)));
            assertEquals((long) width, body(response).get("width_bytes"));
        }
    }

    @Test
    public void bigEndianDoesNotMatchTheLittleEndianEncoding() {
        AddressEncodingSearchService service = new Fixture()
            .block("ram", RAM, image(0x40, word(0x10, 0x9680)))
            .build();

        assertEquals(List.of("RAM:0010"), encodingAddresses(
            service.searchAddressEncodings("9680", "9680", 2, "little",
                "", "", 1000, "", "")));
        assertEquals(List.of(), encodingAddresses(
            service.searchAddressEncodings("9680", "9680", 2, "big",
                "", "", 1000, "", "")));
        // ...and the big-endian encoding of the same value is 96 80.
        AddressEncodingSearchService bigEndian = new Fixture()
            .block("ram", RAM, image(0x40, Map.of(0x10, 0x96, 0x11, 0x80)))
            .build();
        assertEquals(List.of("RAM:0010"), encodingAddresses(
            bigEndian.searchAddressEncodings("9680", "9680", 2, "big",
                "", "", 1000, "", "")));
    }

    @Test
    public void aDestinationBoundUnrepresentableInTheWidthIsRejected() {
        AddressEncodingSearchService service = new Fixture()
            .block("ram", RAM, new byte[0x40])
            .build();
        // $9680 needs two bytes; asking for one-byte encodings of it can only
        // ever return nothing, which would read as a clean sweep.
        assertTrue(isError(service.searchAddressEncodings(
            "9680", "9680", 1, "little", "", "", 1000, "", "")));
        assertFalse(isError(service.searchAddressEncodings(
            "00", "ff", 1, "little", "", "", 1000, "", "")));
    }

    @Test
    public void invalidWidthsAndByteOrdersAreRejected() {
        AddressEncodingSearchService service = new Fixture()
            .block("ram", RAM, new byte[0x40])
            .build();
        assertTrue(isError(service.searchAddressEncodings(
            "00", "ff", 0, "little", "", "", 1000, "", "")));
        assertTrue(isError(service.searchAddressEncodings(
            "00", "ff", 9, "little", "", "", 1000, "", "")));
        assertTrue(isError(service.searchAddressEncodings(
            "00", "ff", 2, "middle", "", "", 1000, "", "")));
    }

    @Test
    public void rangeValidationMatchesTheSiblingEndpoint() {
        AddressEncodingSearchService service = new Fixture()
            .block("ram", RAM, new byte[0x40])
            .block("player", PLAYER, new byte[0x40])
            .build();
        assertTrue("reversed destination", isError(service.searchAddressEncodings(
            "20", "10", 2, "little", "", "", 1000, "", "")));
        assertTrue("destination across spaces", isError(service.searchAddressEncodings(
            "10", "SND_PLAYER:20", 2, "little", "", "", 1000, "", "")));
        assertTrue("unresolvable", isError(service.searchAddressEncodings(
            "nonsense", "20", 2, "little", "", "", 1000, "", "")));
        assertTrue("source_start without source_end", isError(
            service.searchAddressEncodings("10", "20", 2, "little", "0", "", 1000, "", "")));
        assertTrue("reversed source", isError(service.searchAddressEncodings(
            "10", "20", 2, "little", "20", "10", 1000, "", "")));
        assertTrue("source across spaces", isError(service.searchAddressEncodings(
            "10", "20", 2, "little", "0", "SND_PLAYER:20", 1000, "", "")));
        assertTrue("limit bounds", isError(service.searchAddressEncodings(
            "10", "20", 2, "little", "", "", 0, "", "")));
        assertTrue("limit bounds", isError(service.searchAddressEncodings(
            "10", "20", 2, "little", "", "", 10_001, "", "")));
    }

    // ------------------------------------------------------------- windowing

    @Test
    public void unalignedAndOverlappingWindowsAreBothReported() {
        // $0011 and $0012 both decode into the range; 6502 operands are unaligned,
        // so either could be the real one and both are separate rows.
        byte[] image = image(0x40, Map.of(0x11, 0x80, 0x12, 0x96, 0x13, 0x96));
        AddressEncodingSearchService service = new Fixture()
            .block("ram", RAM, image)
            .build();

        assertEquals(List.of("RAM:0011", "RAM:0012"), encodingAddresses(
            service.searchAddressEncodings("9680", "96ff", 2, "little",
                "", "", 1000, "", "")));
    }

    @Test
    public void aWindowStraddlingTheSourceRangeEdgeIsAbsent() {
        AddressEncodingSearchService service = new Fixture()
            .block("ram", RAM, image(0x40, word(0x10, 0x9680)))
            .build();

        assertEquals(List.of("RAM:0010"), encodingAddresses(
            service.searchAddressEncodings("9680", "9680", 2, "little",
                "0", "11", 1000, "", "")));
        assertEquals("the window's last byte falls outside the source range",
            List.of(), encodingAddresses(service.searchAddressEncodings(
                "9680", "9680", 2, "little", "0", "10", 1000, "", "")));
    }

    @Test
    public void aWindowStraddlingABlockEdgeIsAbsent() {
        AddressEncodingSearchService service = new Fixture()
            .splitBlock(RAM, image(0x40, word(0x1f, 0x9680)), 0x20)
            .build();

        assertEquals(List.of(), encodingAddresses(
            service.searchAddressEncodings("9680", "9680", 2, "little",
                "", "", 1000, "", "")));
    }

    @Test
    public void theResponseEchoesTheQueryAndItsScope() {
        AddressEncodingSearchService service = new Fixture()
            .block("ram", RAM, new byte[0x40])
            .block("player", PLAYER, new byte[0x40])
            .build();

        Map<String, Object> body = body(service.searchAddressEncodings(
            "SND_PLAYER:9680", "SND_PLAYER:98ff", 2, "little", "", "", 1000, "", ""));
        assertEquals("SND_PLAYER:9680 - SND_PLAYER:98ff", body.get("destination_range"));
        assertEquals("little", body.get("byte_order"));
        assertEquals("byte_encodings_of_destination_range", body.get("scope"));
        assertEquals(4213L, body.get("program_modification_number"));
        @SuppressWarnings("unchecked")
        Map<String, Object> sourceScope = (Map<String, Object>) body.get("source_scope");
        assertEquals("all_initialized_memory", sourceScope.get("mode"));
        assertEquals(List.of("RAM", "SND_PLAYER"), sourceScope.get("spaces"));
    }

    // ------------------------------------------------------ cursor traversal

    /** {@code count} sparse matches at $0010, $0020, ... all decoding to $9680. */
    private Fixture sparseMatches(int count) {
        Map<Integer, Integer> bytes = new HashMap<>();
        for (int index = 0; index < count; index++) {
            bytes.putAll(word(0x10 + index * 0x10, 0x9680));
        }
        return new Fixture().block("ram", RAM, image(0x10 + count * 0x10 + 0x10, bytes));
    }

    private Response page(AddressEncodingSearchService service, int limit, String cursor) {
        return service.searchAddressEncodings(
            "9680", "9680", 2, "little", "", "", limit, cursor, "");
    }

    @Test
    public void theLookaheadMatchIsReturnedOnTheNextPageRatherThanLost() {
        // Exactly limit + 1 matches: the (limit+1)th is the lookahead that established
        // has_more, and binding the next UNTESTED address would drop it.
        AddressEncodingSearchService service = sparseMatches(4).build();

        Response first = page(service, 3, "");
        assertEquals(List.of("RAM:0010", "RAM:0020", "RAM:0030"),
            encodingAddresses(first));
        assertEquals(Boolean.TRUE, body(first).get("has_more"));
        String cursor = (String) body(first).get("cursor");
        assertNotNull(cursor);

        Response second = page(service, 3, cursor);
        assertEquals(List.of("RAM:0040"), encodingAddresses(second));
        assertEquals(Boolean.FALSE, body(second).get("has_more"));
        assertNull(body(second).get("cursor"));
    }

    @Test
    public void exactlyLimitMatchesEndWithoutATrailingEmptyPage() {
        AddressEncodingSearchService service = sparseMatches(3).build();

        Response only = page(service, 3, "");
        assertEquals(3, rows(only).size());
        assertEquals(Boolean.FALSE, body(only).get("has_more"));
        assertNull("nothing follows, so there is no page to ask for",
            body(only).get("cursor"));
    }

    @Test
    public void continuationCoversEveryRowExactlyOnce() {
        AddressEncodingSearchService service = sparseMatches(7).build();

        List<String> seen = new ArrayList<>();
        String cursor = "";
        int pages = 0;
        do {
            Response response = page(service, 2, cursor);
            seen.addAll(encodingAddresses(response));
            cursor = (String) body(response).get("cursor");
            pages++;
        }
        while (cursor != null);

        assertEquals(7, seen.size());
        assertEquals(7, new java.util.LinkedHashSet<>(seen).size());
        assertEquals("RAM:0010", seen.get(0));
        assertEquals("RAM:0070", seen.get(6));
        assertTrue(pages >= 4);
    }

    @Test
    public void continuationSurvivesInitializedHolesAndLongNonMatchingSpans() {
        // Dense adjacent hits would not exercise a resume that lands in the middle of
        // a long empty stretch, or one that must cross into the next range.
        byte[] image = image(0x200, merge(word(0x10, 0x9680), word(0x1a0, 0x9680)));
        Fixture fixture = new Fixture();
        fixture.images.put(RAM.getName(), image);
        fixture.spaces.add(RAM);
        MemoryBlock block = mock(MemoryBlock.class);
        when(block.getName()).thenReturn("ram");
        when(block.getStart()).thenReturn(RAM.getAddress(0));
        when(block.getEnd()).thenReturn(RAM.getAddress(0x1ff));
        fixture.blocks.add(block);
        fixture.initialized.add(RAM.getAddress(0x00), RAM.getAddress(0x7f));
        fixture.initialized.add(RAM.getAddress(0x100), RAM.getAddress(0x1ff));
        AddressEncodingSearchService service = fixture.build();

        Response first = page(service, 1, "");
        assertEquals(List.of("RAM:0010"), encodingAddresses(first));
        Response second = page(service, 1, (String) body(first).get("cursor"));
        assertEquals(List.of("RAM:01a0"), encodingAddresses(second));
        assertEquals(Boolean.FALSE, body(second).get("has_more"));
    }

    @Test
    public void limitMayChangeBetweenPages() {
        AddressEncodingSearchService service = sparseMatches(5).build();
        Response first = page(service, 2, "");
        Response second = page(service, 3, (String) body(first).get("cursor"));
        assertEquals(List.of("RAM:0030", "RAM:0040", "RAM:0050"),
            encodingAddresses(second));
    }

    @Test
    public void aTamperedCursorIsRejected() {
        AddressEncodingSearchService service = sparseMatches(4).build();
        String cursor = (String) body(page(service, 2, "")).get("cursor");

        String[] parts = cursor.split("\\.", -1);
        char first = parts[1].charAt(0);
        String tamperedMac = parts[0] + "." + (first == 'A' ? 'B' : 'A')
            + parts[1].substring(1);
        assertTrue(isError(page(service, 2, tamperedMac)));

        String payload = new String(Base64.getUrlDecoder().decode(parts[0]),
            java.nio.charset.StandardCharsets.UTF_8);
        String tamperedPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(
            payload.replace("0030", "0010")
                .getBytes(java.nio.charset.StandardCharsets.UTF_8))
            + "." + parts[1];
        assertTrue(isError(page(service, 2, tamperedPayload)));
        assertTrue(isError(page(service, 2, "not-a-cursor")));
    }

    @Test
    public void aCursorIsRejectedWhenAnyBoundValueChanges() {
        Fixture fixture = sparseMatches(4);
        AddressEncodingSearchService service = fixture.build();
        String cursor = (String) body(page(service, 2, "")).get("cursor");

        assertTrue("destination range", isError(service.searchAddressEncodings(
            "9680", "9681", 2, "little", "", "", 2, cursor, "")));
        assertTrue("source range", isError(service.searchAddressEncodings(
            "9680", "9680", 2, "little", "0", "ff", 2, cursor, "")));
        assertTrue("width", isError(service.searchAddressEncodings(
            "9680", "9680", 3, "little", "", "", 2, cursor, "")));
        assertTrue("byte order", isError(service.searchAddressEncodings(
            "9680", "9680", 2, "big", "", "", 2, cursor, "")));

        fixture.modificationNumber++;
        assertTrue("modification number", isError(page(service, 2, cursor)));
        fixture.modificationNumber--;

        fixture.uniqueProgramId = 0x9999L;
        assertTrue("program identity", isError(page(service, 2, cursor)));
    }

    // ------------------------------------------------------------ concurrency

    @Test
    public void anEditDuringTheScanFailsTheRequest() {
        Fixture fixture = sparseMatches(2);
        fixture.bumpModificationOnRead = true;
        assertTrue(isError(page(fixture.build(), 10, "")));
    }

    @Test
    public void anEditDuringReferenceEnrichmentFailsTheRequest() {
        // The post-page check is load-bearing, not decorative: enrichment happens
        // after the scan, and an edit landing there tears the page just as badly.
        Fixture fixture = new Fixture()
            .block("ram", RAM, image(0x40, word(0x10, 0x9680)))
            .instruction(RAM, 0x10, 2, "dw");
        fixture.bumpModificationOnReferenceRead = true;
        assertTrue(isError(fixture.build().searchAddressEncodings(
            "9680", "9680", 2, "little", "", "", 10, "", "")));
    }

    @Test
    public void modelReadsHappenInsideTheReadHop() {
        Fixture fixture = new Fixture().block("ram", RAM, new byte[0x40]);
        AddressEncodingSearchService service = fixture.build();
        assertFalse(isError(service.searchAddressEncodings(
            "10", "20", 2, "little", "", "", 10, "", "")));
        assertEquals(1, fixture.threading.readCount());
        assertEquals(0, fixture.threading.writeCount());
    }
}
