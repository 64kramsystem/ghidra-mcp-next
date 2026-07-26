package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Offline coverage for the reworked {@code /search_byte_patterns}.
 *
 * <p>Two properties drive most of these fixtures: the declared {@code mask} used to be
 * accepted and ignored, and a failed block read used to be indistinguishable from a miss.
 * Both are asserted with cases that would pass under the old behaviour only by accident.</p>
 */
public class SearchBytePatternsTest {

    private static final GenericAddressSpace RAM =
        new GenericAddressSpace("RAM", 32, AddressSpace.TYPE_RAM, 0);
    private static final GenericAddressSpace PLAYER =
        new GenericAddressSpace("SND_PLAYER", 32, AddressSpace.TYPE_RAM, 1);

    // ---------------------------------------------------------------- fixture

    private static final class Fixture {
        final Program program = mock(Program.class);
        final Memory memory = mock(Memory.class);
        final AddressFactory factory = mock(AddressFactory.class);
        final ProgramProvider provider = mock(ProgramProvider.class);
        final Map<String, byte[]> images = new HashMap<>();
        final List<AddressSpace> spaces = new ArrayList<>();
        final List<MemoryBlock> blocks = new ArrayList<>();
        final AddressSet initialized = new AddressSet();
        final com.xebyte.offline.RecordingThreadingStrategy threading =
            new com.xebyte.offline.RecordingThreadingStrategy();
        long modificationNumber = 4213;
        boolean bumpModificationOnRead;
        int failReadAt = -1;
        int shortReadAt = -1;
        int reads;

        Fixture block(String name, AddressSpace space, byte[] image) {
            return block(name, space, image, 0, image.length - 1);
        }

        /** A block whose initialized extent is only part of its mapped extent. */
        Fixture block(String name, AddressSpace space, byte[] image,
                long initializedFrom, long initializedTo) {
            images.put(space.getName(), image);
            if (!spaces.contains(space)) spaces.add(space);
            MemoryBlock block = mock(MemoryBlock.class);
            when(block.getName()).thenReturn(name);
            when(block.getStart()).thenReturn(space.getAddress(0));
            when(block.getEnd()).thenReturn(space.getAddress(image.length - 1));
            blocks.add(block);
            initialized.add(
                space.getAddress(initializedFrom), space.getAddress(initializedTo));
            return this;
        }

        /** Adds a second block over the same image, so a block seam exists. */
        Fixture splitBlock(String lowName, String highName, AddressSpace space,
                byte[] image, long seam) {
            images.put(space.getName(), image);
            if (!spaces.contains(space)) spaces.add(space);
            MemoryBlock low = mock(MemoryBlock.class);
            when(low.getName()).thenReturn(lowName);
            when(low.getStart()).thenReturn(space.getAddress(0));
            when(low.getEnd()).thenReturn(space.getAddress(seam - 1));
            MemoryBlock high = mock(MemoryBlock.class);
            when(high.getName()).thenReturn(highName);
            when(high.getStart()).thenReturn(space.getAddress(seam));
            when(high.getEnd()).thenReturn(space.getAddress(image.length - 1));
            blocks.add(low);
            blocks.add(high);
            initialized.add(space.getAddress(0), space.getAddress(image.length - 1));
            return this;
        }

        AnalysisService build() {
            when(program.getName()).thenReturn("fixture");
            when(program.getMemory()).thenReturn(memory);
            when(program.getAddressFactory()).thenReturn(factory);
            when(program.getModificationNumber())
                .thenAnswer(invocation -> modificationNumber);
            when(factory.getAddressSpaces())
                .thenReturn(spaces.toArray(new AddressSpace[0]));
            when(factory.getDefaultAddressSpace()).thenReturn(RAM);
            when(factory.getAddress(anyString())).thenAnswer(invocation -> {
                String text = invocation.getArgument(0);
                String name = RAM.getName();
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
            when(memory.getBlocks())
                .thenReturn(blocks.toArray(new MemoryBlock[0]));
            when(memory.getAllInitializedAddressSet()).thenReturn(initialized);
            try {
                when(memory.getBytes(any(Address.class), any(byte[].class),
                        anyInt(), anyInt()))
                    .thenAnswer(invocation -> {
                        reads++;
                        if (reads == failReadAt) {
                            throw new MemoryAccessException("block is not readable");
                        }
                        Address at = invocation.getArgument(0);
                        byte[] buffer = invocation.getArgument(1);
                        int destination = invocation.getArgument(2);
                        int length = invocation.getArgument(3);
                        if (reads == shortReadAt) length = Math.max(0, length - 1);
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
            when(provider.getCurrentProgram()).thenReturn(program);
            when(provider.getProgram(anyString())).thenReturn(program);
            when(provider.getAllOpenPrograms()).thenReturn(new Program[] {program});
            return new AnalysisService(provider, threading,
                new FunctionService(provider, threading));
        }
    }

    private static byte[] image(int size, Map<Integer, Integer> bytes) {
        byte[] image = new byte[size];
        for (Map.Entry<Integer, Integer> entry : bytes.entrySet()) {
            image[entry.getKey()] = entry.getValue().byteValue();
        }
        return image;
    }

    private static Map<Integer, Integer> at(int offset, int... values) {
        Map<Integer, Integer> map = new LinkedHashMap<>();
        for (int index = 0; index < values.length; index++) {
            map.put(offset + index, values[index]);
        }
        return map;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> body(Response response) {
        assertNotNull(response);
        assertFalse("unexpected error: " + response.toJson(),
            response instanceof Response.Err);
        return (Map<String, Object>) ((Response.Ok) response).data();
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> matches(Response response) {
        return (List<Map<String, Object>>) body(response).get("matches");
    }

    private static List<String> addresses(Response response) {
        List<String> found = new ArrayList<>();
        for (Map<String, Object> match : matches(response)) {
            found.add((String) match.get("address_full"));
        }
        return found;
    }

    private static boolean isError(Response response) {
        return response instanceof Response.Err;
    }

    // ------------------------------------------------------------ validation

    @Test
    public void malformedPatternsAreRejected() {
        AnalysisService service = new Fixture().block("ram", RAM, new byte[16]).build();
        assertTrue("odd digit count", isError(
            service.searchBytePatterns("20 9", "", "", "", 1000, 0, "")));
        assertTrue("a lone ? is not a wildcard byte", isError(
            service.searchBytePatterns("20 ? 97", "", "", "", 1000, 0, "")));
        assertTrue("non-hex", isError(
            service.searchBytePatterns("zz", "", "", "", 1000, 0, "")));
        assertTrue("empty", isError(
            service.searchBytePatterns("   ", "", "", "", 1000, 0, "")));
    }

    @Test
    public void aMaskOfADifferentLengthIsRejected() {
        AnalysisService service = new Fixture().block("ram", RAM, new byte[16]).build();
        assertTrue(isError(
            service.searchBytePatterns("2097", "ff", "", "", 1000, 0, "")));
        assertTrue(isError(
            service.searchBytePatterns("2097", "ffffff", "", "", 1000, 0, "")));
        assertTrue("mask digits must be hex", isError(
            service.searchBytePatterns("2097", "ff??", "", "", 1000, 0, "")));
    }

    @Test
    public void anOversizedPatternIsRejected() {
        AnalysisService service = new Fixture().block("ram", RAM, new byte[16]).build();
        assertTrue(isError(service.searchBytePatterns(
            "00".repeat(65_537), "", "", "", 1000, 0, "")));
    }

    @Test
    public void limitAndOffsetBoundsArePinned() {
        AnalysisService service = new Fixture().block("ram", RAM, new byte[16]).build();
        assertTrue(isError(service.searchBytePatterns("00", "", "", "", 0, 0, "")));
        assertTrue(isError(service.searchBytePatterns("00", "", "", "", 10_001, 0, "")));
        assertTrue(isError(service.searchBytePatterns("00", "", "", "", 1000, -1, "")));
        assertFalse(isError(
            service.searchBytePatterns("00", "", "", "", 10_000, 0, "")));
    }

    @Test
    public void aRangeNeedsBothEndpointsInOneSpaceAndInOrder() {
        AnalysisService service = new Fixture()
            .block("ram", RAM, new byte[16])
            .block("player", PLAYER, new byte[16])
            .build();
        assertTrue("start without end", isError(
            service.searchBytePatterns("00", "", "0", "", 1000, 0, "")));
        assertTrue("end without start", isError(
            service.searchBytePatterns("00", "", "", "f", 1000, 0, "")));
        assertTrue("reversed", isError(
            service.searchBytePatterns("00", "", "f", "0", 1000, 0, "")));
        assertTrue("two spaces", isError(
            service.searchBytePatterns("00", "", "0", "SND_PLAYER:f", 1000, 0, "")));
    }

    // ------------------------------------------------------------------ mask

    @Test
    public void anExplicitMaskMatchesOnlyTheSelectedBits() {
        // $a5 and $af both match a0/f0; $b0 does not. Under the old
        // accepted-and-ignored mask this returns nothing at all.
        AnalysisService service = new Fixture()
            .block("ram", RAM, image(8, Map.of(1, 0xa5, 3, 0xaf, 5, 0xb0)))
            .build();

        Response response =
            service.searchBytePatterns("a0", "f0", "", "", 1000, 0, "");
        assertEquals(List.of("RAM:00000001", "RAM:00000003"), addresses(response));
        assertEquals("f0", body(response).get("effective_mask"));
        assertEquals(0, body(response).get("wildcard_count"));
    }

    @Test
    public void ignoringTheMaskWouldChangeTheResultSet() {
        // The regression guard for the original defect: with the mask honoured this
        // is one match, and with it ignored it is none.
        AnalysisService service = new Fixture()
            .block("ram", RAM, image(8, Map.of(2, 0xa5)))
            .build();

        assertEquals(List.of("RAM:00000002"),
            addresses(service.searchBytePatterns("a0", "f0", "", "", 1000, 0, "")));
        assertEquals(List.of(),
            addresses(service.searchBytePatterns("a0", "", "", "", 1000, 0, "")));
    }

    @Test
    public void anExplicitMaskIsAndedWithTheWildcardDefault() {
        // Neither mechanism can re-enable a bit the other waived: the ?? byte stays
        // fully waived even though the supplied mask byte is ff.
        AnalysisService service = new Fixture()
            .block("ram", RAM, image(8, Map.of(0, 0x20, 1, 0x11, 2, 0x97)))
            .build();

        Response response =
            service.searchBytePatterns("20??97", "ffffff", "", "", 1000, 0, "");
        assertEquals(List.of("RAM:00000000"), addresses(response));
        assertEquals("ff00ff", body(response).get("effective_mask"));
        // Defined as fully waived BYTES, not as ?? tokens typed by the caller.
        assertEquals(1, body(response).get("wildcard_count"));
    }

    @Test
    public void anExplicitZeroMaskByteCountsAsAWildcardEvenWithoutAQuestionMark() {
        AnalysisService service = new Fixture()
            .block("ram", RAM, image(4, Map.of(0, 0x20, 1, 0x55)))
            .build();

        Response response =
            service.searchBytePatterns("2011", "ff00", "", "", 1000, 0, "");
        assertEquals("ff00", body(response).get("effective_mask"));
        assertEquals(1, body(response).get("wildcard_count"));
        assertEquals(List.of("RAM:00000000"), addresses(response));
    }

    @Test
    public void thePatternIsEchoedNormalized() {
        AnalysisService service = new Fixture().block("ram", RAM, new byte[8]).build();
        assertEquals("20??97", body(
            service.searchBytePatterns(" 20 ?? 97 ", "", "", "", 1000, 0, ""))
            .get("pattern"));
    }

    // ---------------------------------------------------------------- scoping

    @Test
    public void aWholeMatchInsideTheRangeIsFoundAndOneOverrunningTheEndIsNot() {
        AnalysisService service = new Fixture()
            .block("ram", RAM, image(16, Map.of(4, 0x11, 5, 0x22, 6, 0x33,
                                                7, 0x11, 8, 0x22, 9, 0x33)))
            .build();

        // [0,9] contains both windows; [0,8] cuts the second one's last byte.
        assertEquals(List.of("RAM:00000004", "RAM:00000007"), addresses(
            service.searchBytePatterns("112233", "", "0", "9", 1000, 0, "")));
        assertEquals("the entire match must fit inside the range",
            List.of("RAM:00000004"), addresses(
                service.searchBytePatterns("112233", "", "0", "8", 1000, 0, "")));
    }

    @Test
    public void aRangeSearchesOnlyItsOwnSpace() {
        Fixture fixture = new Fixture()
            .block("ram", RAM, image(8, Map.of(2, 0x5a)))
            .block("player", PLAYER, image(8, Map.of(2, 0x5a)));
        AnalysisService service = fixture.build();

        Response ram = service.searchBytePatterns("5a", "", "0", "7", 1000, 0, "");
        assertEquals(List.of("RAM:00000002"), addresses(ram));
        Map<String, Object> scope = scope(ram);
        assertEquals("range", scope.get("mode"));
        assertEquals(List.of("RAM"), scope.get("spaces"));

        Response player = service.searchBytePatterns(
            "5a", "", "SND_PLAYER:0", "SND_PLAYER:7", 1000, 0, "");
        assertEquals(List.of("SND_PLAYER:00000002"), addresses(player));
        assertEquals(List.of("SND_PLAYER"), scope(player).get("spaces"));
    }

    @Test
    public void anUninitializedHoleInsideABlockIsSkipped() {
        // The bytes are present in the fixture image, but only [0,3] is initialized;
        // scanning the hole would read memory that does not exist.
        AnalysisService service = new Fixture()
            .block("ram", RAM, image(16, Map.of(2, 0x5a, 10, 0x5a)), 0, 3)
            .build();

        assertEquals(List.of("RAM:00000002"),
            addresses(service.searchBytePatterns("5a", "", "", "", 1000, 0, "")));
    }

    @Test
    public void wholeMemoryScopeNamesEverySpaceItCovered() {
        AnalysisService service = new Fixture()
            .block("ram", RAM, new byte[8])
            .block("player", PLAYER, new byte[8])
            .build();

        Map<String, Object> scope =
            scope(service.searchBytePatterns("00", "", "", "", 1000, 0, ""));
        assertEquals("all_initialized_memory", scope.get("mode"));
        assertEquals(List.of("RAM", "SND_PLAYER"), scope.get("spaces"));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> scope(Response response) {
        return (Map<String, Object>) body(response).get("scope");
    }

    // --------------------------------------------------------------- matching

    @Test
    public void identicalOffsetsInTwoSpacesAreBothReturnedAndQualified() {
        AnalysisService service = new Fixture()
            .block("ram", RAM, image(8, Map.of(3, 0x20, 4, 0x97)))
            .block("player", PLAYER, image(8, Map.of(3, 0x20, 4, 0x97)))
            .build();

        Response response = service.searchBytePatterns("2097", "", "", "", 1000, 0, "");
        assertEquals(List.of("RAM:00000003", "SND_PLAYER:00000003"),
            addresses(response));
        List<Map<String, Object>> matches = matches(response);
        assertEquals("00000003", matches.get(0).get("address"));
        assertEquals("RAM", matches.get(0).get("address_space"));
        assertEquals("SND_PLAYER", matches.get(1).get("address_space"));
    }

    @Test
    public void overlappingMatchesAreAllReturned() {
        AnalysisService service = new Fixture()
            .block("ram", RAM, image(8, Map.of(1, 0x55, 2, 0x55, 3, 0x55)))
            .build();

        assertEquals(List.of("RAM:00000001", "RAM:00000002"),
            addresses(service.searchBytePatterns("5555", "", "", "", 1000, 0, "")));
    }

    @Test
    public void aMatchStraddlingABlockSeamIsNotReported() {
        // Documented limitation, asserted rather than left for a caller to discover.
        AnalysisService service = new Fixture()
            .splitBlock("low", "high", RAM, image(16, Map.of(7, 0x20, 8, 0x97)), 8)
            .build();

        assertEquals(List.of(),
            addresses(service.searchBytePatterns("2097", "", "", "", 1000, 0, "")));
    }

    @Test
    public void zeroMatchesReturnsAnEmptyArrayRatherThanANote() {
        Response response = new Fixture().block("ram", RAM, new byte[8]).build()
            .searchBytePatterns("ff", "", "", "", 1000, 0, "");
        assertEquals(List.of(), body(response).get("matches"));
        assertEquals(0L, body(response).get("total_matched"));
        assertEquals(Boolean.FALSE, body(response).get("has_more"));
    }

    // ---------------------------------------------------------------- paging

    @Test
    public void orderingIsTotalAcrossSpacesBlocksAndOffsets() {
        AnalysisService service = new Fixture()
            .splitBlock("low", "high", RAM,
                image(16, Map.of(1, 0x5a, 9, 0x5a, 12, 0x5a)), 8)
            .block("player", PLAYER, image(8, Map.of(0, 0x5a)))
            .build();

        assertEquals(
            List.of("RAM:00000001", "RAM:00000009", "RAM:0000000c",
                "SND_PLAYER:00000000"),
            addresses(service.searchBytePatterns("5a", "", "", "", 1000, 0, "")));
    }

    @Test
    public void aMidListOffsetReturnsTheExpectedSlice() {
        AnalysisService service = new Fixture()
            .block("ram", RAM, image(8, Map.of(0, 0x5a, 2, 0x5a, 4, 0x5a, 6, 0x5a)))
            .build();

        Response response = service.searchBytePatterns("5a", "", "", "", 2, 1, "");
        assertEquals(List.of("RAM:00000002", "RAM:00000004"), addresses(response));
        assertEquals(4L, body(response).get("total_matched"));
        assertEquals(2, body(response).get("returned"));
        assertEquals(1, body(response).get("offset"));
        assertEquals(Boolean.TRUE, body(response).get("has_more"));
    }

    @Test
    public void anOffsetPastTheEndIsAnEmptyPageWithTheTotalIntact() {
        AnalysisService service = new Fixture()
            .block("ram", RAM, image(8, Map.of(0, 0x5a, 2, 0x5a)))
            .build();

        Response response = service.searchBytePatterns("5a", "", "", "", 10, 99, "");
        assertEquals(List.of(), body(response).get("matches"));
        assertEquals(2L, body(response).get("total_matched"));
        assertEquals(Boolean.FALSE, body(response).get("has_more"));
    }

    @Test
    public void hasMoreIsFalseExactlyAtTheBoundary() {
        AnalysisService service = new Fixture()
            .block("ram", RAM, image(8, Map.of(0, 0x5a, 2, 0x5a, 4, 0x5a)))
            .build();

        Response response = service.searchBytePatterns("5a", "", "", "", 2, 1, "");
        assertEquals(2, body(response).get("returned"));
        assertEquals(Boolean.FALSE, body(response).get("has_more"));
    }

    @Test
    public void anAllWildcardScanIsPagedWithoutReturningEveryMatch() {
        // An all-zero effective mask matches at nearly every offset. Retaining them
        // all would be an unbounded allocation by another route; only the page is kept.
        int size = 1 << 20;
        AnalysisService service = new Fixture()
            .block("ram", RAM, new byte[size])
            .build();

        Response response = service.searchBytePatterns("????", "", "", "", 5, 0, "");
        assertEquals(5, matches(response).size());
        assertEquals((long) size - 1, body(response).get("total_matched"));
        assertEquals(Boolean.TRUE, body(response).get("has_more"));
        assertEquals(2, body(response).get("wildcard_count"));
    }

    @Test
    public void theLastLegalCandidateInAWholeMemoryScanEndsAtTheRangeEnd() {
        AnalysisService service = new Fixture()
            .block("ram", RAM, image(4, Map.of(2, 0x20, 3, 0x97)))
            .build();

        assertEquals(List.of("RAM:00000002"),
            addresses(service.searchBytePatterns("2097", "", "", "", 1000, 0, "")));
    }

    // ------------------------------------------------------ failures, tearing

    @Test
    public void aThrowingReadIsAnErrorRatherThanAMiss() {
        Fixture fixture = new Fixture().block("CODE", RAM, new byte[8]);
        fixture.failReadAt = 1;
        Response response =
            fixture.build().searchBytePatterns("5a", "", "", "", 1000, 0, "");

        assertTrue(isError(response));
        String message = ((Response.Err) response).message();
        assertTrue(message, message.contains("CODE"));
        assertTrue(message, message.contains("RAM:00000000"));
    }

    @Test
    public void aShortReadIsAnErrorRatherThanASilentlyShortTotal() {
        Fixture fixture = new Fixture().block("CODE", RAM, new byte[8]);
        fixture.shortReadAt = 1;
        Response response =
            fixture.build().searchBytePatterns("5a", "", "", "", 1000, 0, "");

        assertTrue(isError(response));
        assertTrue(((Response.Err) response).message().contains("CODE"));
    }

    @Test
    public void anEditLandingMidScanFailsTheRequest() {
        Fixture fixture = new Fixture().block("ram", RAM, new byte[8]);
        fixture.bumpModificationOnRead = true;
        Response response =
            fixture.build().searchBytePatterns("5a", "", "", "", 1000, 0, "");

        assertTrue("a torn total_matched was never true of any program state",
            isError(response));
    }

    @Test
    public void theModificationNumberIsEchoed() {
        Response response = new Fixture().block("ram", RAM, new byte[8]).build()
            .searchBytePatterns("5a", "", "", "", 1000, 0, "");
        assertEquals(4213L, body(response).get("program_modification_number"));
    }

    @Test
    public void twoPagesTakenAroundAnEditCarryDifferentModificationNumbers() {
        // Paging is only continuous while the program is unchanged; the echo is how a
        // caller notices two pages came from different revisions instead of stitching them.
        Fixture fixture = new Fixture()
            .block("ram", RAM, image(8, Map.of(0, 0x5a, 2, 0x5a, 4, 0x5a)));
        AnalysisService service = fixture.build();

        Response first = service.searchBytePatterns("5a", "", "", "", 2, 0, "");
        fixture.modificationNumber++;
        Response second = service.searchBytePatterns("5a", "", "", "", 2, 2, "");

        assertEquals(4213L, body(first).get("program_modification_number"));
        assertEquals(4214L, body(second).get("program_modification_number"));
    }

    @Test
    public void modelReadsHappenInsideTheReadHop() {
        Fixture fixture = new Fixture().block("ram", RAM, new byte[8]);
        AnalysisService service = fixture.build();
        assertFalse(isError(
            service.searchBytePatterns("5a", "", "", "", 1000, 0, "")));
        assertEquals(1, fixture.threading.readCount());
        assertEquals(0, fixture.threading.writeCount());
    }

    @Test
    public void theAnnotationDeclaresTheSearchCategory() {
        // The catalog already said `search`; the annotation said `analysis`.
        java.lang.reflect.Method method = Arrays.stream(
                AnalysisService.class.getMethods())
            .filter(candidate -> {
                McpTool tool = candidate.getAnnotation(McpTool.class);
                return tool != null && "/search_byte_patterns".equals(tool.path());
            })
            .findFirst()
            .orElseThrow();
        assertEquals("search", method.getAnnotation(McpTool.class).category());
    }
}
