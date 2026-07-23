package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

import javax.swing.SwingUtilities;

import org.junit.Before;
import org.junit.Test;

import ghidra.framework.model.DomainFile;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;

public class GuiContextServiceTest {

    private ProgramProvider provider;
    private FakeGuiAccess gui;
    private RecordingThreadingStrategy threading;
    private GuiContextService service;

    @Before
    public void setUp() {
        provider = mock(ProgramProvider.class);
        gui = new FakeGuiAccess();
        threading = new RecordingThreadingStrategy();
        service = new GuiContextService(gui, provider, threading);
    }

    @Test
    public void noProgramAndNoLocationUseNormalizedNulls() {
        Map<String, Object> result = parse(service.getCurrentAddress());

        assertEquals(Boolean.FALSE, result.get("has_program"));
        assertNull(result.get("program"));
        assertEquals(Boolean.FALSE, result.get("has_address"));
        assertNull(result.get("address"));
        assertNull(result.get("address_space"));
        assertEquals(Boolean.FALSE, result.get("mapped"));
        assertTrue(threading.readCalled);
    }

    @Test
    public void cachedProviderProgramIsNotAnActiveGuiContext() {
        Program program = program("/games/story", "story", null, false);
        when(provider.getCurrentProgram()).thenReturn(program);

        Map<String, Object> result = parse(service.getCurrentAddress());

        assertEquals(Boolean.FALSE, result.get("has_program"));
        assertNull(result.get("program"));
        assertEquals(Boolean.FALSE, result.get("has_address"));
        assertNull(result.get("address"));
        assertNull(result.get("address_space"));
        assertEquals(Boolean.FALSE, result.get("mapped"));
    }

    @Test
    public void currentAddressReportsProgramSpaceAndMapping() {
        Address address = address("ram:1000", "ram");
        Program program = program("/games/story", "story", address, true);
        gui.location = location(program, address);

        Map<String, Object> result = parse(service.getCurrentAddress());

        assertEquals(Boolean.TRUE, result.get("has_program"));
        assertEquals("/games/story", result.get("program"));
        assertEquals(Boolean.TRUE, result.get("has_address"));
        assertEquals("ram:1000", result.get("address"));
        assertEquals("ram", result.get("address_space"));
        assertEquals(Boolean.TRUE, result.get("mapped"));
    }

    @Test
    public void emptySelectionUsesNormalizedContextAndEmptyRanges() {
        Program program = program("/games/story", "story", null, false);
        gui.activeProgram = program;
        gui.selection = new ProgramSelection();

        Map<String, Object> result = parse(service.getCurrentSelection());

        assertEquals(Boolean.TRUE, result.get("has_program"));
        assertEquals(Boolean.FALSE, result.get("has_address"));
        assertEquals(Boolean.FALSE, result.get("has_selection"));
        assertEquals(List.of(), result.get("ranges"));
    }

    @Test
    public void selectionPreservesEveryOrderedAddressSpace() {
        Address firstStart = address("ram:1000", "ram");
        Address firstEnd = address("ram:1003", "ram");
        Address secondStart = address("overlay:2000", "overlay");
        Address secondEnd = address("overlay:2001", "overlay");
        AddressRange first = range(firstStart, firstEnd);
        AddressRange second = range(secondStart, secondEnd);
        ProgramSelection selection = mock(ProgramSelection.class);
        AddressRangeIterator iterator = iterator(first, second);
        when(selection.isEmpty()).thenReturn(false);
        when(selection.getAddressRanges()).thenReturn(iterator);
        gui.selection = selection;
        Program program = program("/games/story", "story", firstStart, true);
        gui.location = location(program, firstStart);

        Map<String, Object> result = parse(service.getCurrentSelection());
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> ranges =
            (List<Map<String, Object>>) result.get("ranges");

        assertEquals(Boolean.TRUE, result.get("has_selection"));
        assertEquals(2, ranges.size());
        assertEquals("ram:1000", ranges.get(0).get("start"));
        assertEquals("ram:1003", ranges.get(0).get("end"));
        assertEquals("ram", ranges.get(0).get("address_space"));
        assertEquals("overlay:2000", ranges.get(1).get("start"));
        assertEquals("overlay:2001", ranges.get(1).get("end"));
        assertEquals("overlay", ranges.get(1).get("address_space"));
    }

    @Test
    public void selectionReportsOneInclusiveRange() {
        Address start = address("ram:3000", "ram");
        Address end = address("ram:3007", "ram");
        AddressRange range = range(start, end);
        ProgramSelection selection = mock(ProgramSelection.class);
        when(selection.isEmpty()).thenReturn(false);
        when(selection.getAddressRanges()).thenReturn(iterator(range));
        gui.selection = selection;
        Program program = program("/games/story", "story", start, true);
        gui.location = location(program, start);

        Map<String, Object> result = parse(service.getCurrentSelection());
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> ranges =
            (List<Map<String, Object>>) result.get("ranges");

        assertEquals(1, ranges.size());
        assertEquals("ram:3000", ranges.get(0).get("start"));
        assertEquals("ram:3007", ranges.get(0).get("end"));
    }

    @Test
    public void navigationActivatesNamedProgramAndReportsFinalContext() {
        Address previousAddress = address("ram:1000", "ram");
        Address targetAddress = address("ram:2000", "ram");
        Program previous = program("/games/old", "old", previousAddress, true);
        Program target = program("/games/story", "story", targetAddress, true);
        gui.location = location(previous, previousAddress);
        gui.activeProgram = previous;
        gui.navigableProgram = target;
        gui.openPrograms = List.of(previous, target);
        gui.onNavigate = () ->
            gui.location = location(target, targetAddress);

        Map<String, Object> result =
            parse(service.goToAddress("ram:2000", "/games/story"));

        assertEquals(Boolean.TRUE, result.get("success"));
        assertEquals(Boolean.TRUE, result.get("changed"));
        assertContext(result, "previous_context", "/games/old", "ram:1000");
        assertContext(result, "current_context", "/games/story", "ram:2000");
        assertEquals(1, gui.activationCount);
        assertEquals(1, gui.navigationCount);
    }

    @Test
    public void navigationRejectsMissingActiveProgramBeforeGuiMutation() {
        Map<String, Object> result = parse(service.goToAddress("ram:2000", ""));

        assertEquals(Boolean.FALSE, result.get("success"));
        assertEquals(Boolean.FALSE, result.get("changed"));
        assertTrue(result.get("error").toString().contains("No active program"));
        assertEquals(0, gui.activationCount);
        assertEquals(0, gui.navigationCount);
    }

    @Test
    public void cachedProviderProgramCannotSatisfyOmittedNavigation() {
        Address address = address("ram:2000", "ram");
        Program cached =
            program("/games/cached", "cached", address, true);
        when(provider.getCurrentProgram()).thenReturn(cached);
        gui.navigableProgram = cached;

        Map<String, Object> result =
            parse(service.goToAddress("ram:2000", ""));

        assertEquals(Boolean.FALSE, result.get("success"));
        assertEquals(Boolean.FALSE, result.get("changed"));
        assertTrue(result.get("error").toString().contains(
            "No active program"));
        assertEquals(0, gui.activationCount);
        assertEquals(0, gui.navigationCount);
        assertContext(result, "previous_context", null, null);
        assertContext(result, "current_context", null, null);
    }

    @Test
    public void providerOnlyOpenProgramCannotSatisfyNamedGuiTarget() {
        Address address = address("ram:2000", "ram");
        Program cached =
            program("/games/cached", "cached", address, true);
        when(provider.getAllOpenPrograms()).thenReturn(
            new Program[] { cached });
        gui.navigableProgram = cached;

        Map<String, Object> result =
            parse(service.goToAddress(
                "ram:2000", "/games/cached"));

        assertEquals(Boolean.FALSE, result.get("success"));
        assertEquals(Boolean.FALSE, result.get("changed"));
        assertTrue(result.get("error").toString().contains(
            "Open program not found"));
        assertEquals(0, gui.activationCount);
        assertEquals(0, gui.navigationCount);
    }

    @Test
    public void navigationRejectsInvalidAddressBeforeProgramActivation() {
        Program program = program("/games/story", "story", null, false);
        gui.openPrograms = List.of(program);
        gui.navigableProgram = program;

        Map<String, Object> result =
            parse(service.goToAddress("not-an-address", "/games/story"));

        assertEquals(Boolean.FALSE, result.get("success"));
        assertEquals(Boolean.FALSE, result.get("changed"));
        assertTrue(result.get("error").toString().contains("Invalid address"));
        assertEquals(0, gui.activationCount);
        assertEquals(0, gui.navigationCount);
    }

    @Test
    public void navigationRejectsUnknownNamedProgram() {
        Map<String, Object> result =
            parse(service.goToAddress("ram:2000", "/games/missing"));

        assertEquals(Boolean.FALSE, result.get("success"));
        assertEquals(Boolean.FALSE, result.get("changed"));
        assertTrue(result.get("error").toString().contains("Open program not found"));
        assertEquals(0, gui.activationCount);
        assertEquals(0, gui.navigationCount);
    }

    @Test
    public void navigationFailureAfterActivationReportsActualFinalContext() {
        Address previousAddress = address("ram:1000", "ram");
        Address targetAddress = address("ram:2000", "ram");
        Program previous = program("/games/old", "old", previousAddress, true);
        Program target = program("/games/story", "story", targetAddress, true);
        gui.location = location(previous, previousAddress);
        gui.activeProgram = previous;
        gui.navigableProgram = target;
        gui.openPrograms = List.of(previous, target);
        gui.navigateResult = false;
        gui.onActivate = () -> gui.location = null;

        Map<String, Object> result =
            parse(service.goToAddress("ram:2000", "/games/story"));

        assertEquals(Boolean.FALSE, result.get("success"));
        assertEquals(Boolean.TRUE, result.get("changed"));
        assertTrue(result.get("error").toString().contains("could not navigate"));
        assertContext(result, "previous_context", "/games/old", "ram:1000");
        assertContext(result, "current_context", "/games/story", null);
    }

    @Test
    public void swingStrategyRunsReadsAndNavigationOnTheEventThread() {
        Address address = address("ram:2000", "ram");
        Program program = program("/games/story", "story", address, true);
        gui.requireEdt = true;
        gui.location = location(program, address);
        gui.activeProgram = program;
        gui.navigableProgram = program;
        gui.openPrograms = List.of(program);
        gui.selection = new ProgramSelection();
        GuiContextService swingService =
            new GuiContextService(gui, provider, new SwingThreadingStrategy());

        Map<String, Object> selection =
            parse(swingService.getCurrentSelection());
        Map<String, Object> navigation =
            parse(swingService.goToAddress("ram:2000", "/games/story"));

        assertEquals(Boolean.FALSE, selection.get("has_selection"));
        assertEquals(Boolean.TRUE, navigation.get("success"));
        assertEquals(1, gui.navigationCount);
    }

    private Program program(String path, String name, Address parsedAddress,
            boolean mapped) {
        Program program = mock(Program.class);
        DomainFile domainFile = mock(DomainFile.class);
        AddressFactory factory = mock(AddressFactory.class);
        Memory memory = mock(Memory.class);
        when(domainFile.getPathname()).thenReturn(path);
        when(program.getDomainFile()).thenReturn(domainFile);
        when(program.getName()).thenReturn(name);
        when(program.getAddressFactory()).thenReturn(factory);
        when(factory.getAddress(any(String.class))).thenAnswer(invocation ->
            "ram:2000".equals(invocation.getArgument(0)) ? parsedAddress : null);
        when(program.getMemory()).thenReturn(memory);
        when(memory.contains(any(Address.class))).thenReturn(mapped);
        return program;
    }

    private Address address(String text, String spaceName) {
        Address address = mock(Address.class);
        AddressSpace space = mock(AddressSpace.class);
        when(address.toString()).thenReturn(text);
        when(address.getAddressSpace()).thenReturn(space);
        when(space.getName()).thenReturn(spaceName);
        return address;
    }

    private AddressRange range(Address start, Address end) {
        AddressRange range = mock(AddressRange.class);
        AddressSpace space = start.getAddressSpace();
        when(range.getMinAddress()).thenReturn(start);
        when(range.getMaxAddress()).thenReturn(end);
        when(range.getAddressSpace()).thenReturn(space);
        return range;
    }

    private ProgramLocation location(Program program, Address address) {
        ProgramLocation location = mock(ProgramLocation.class);
        when(location.getProgram()).thenReturn(program);
        when(location.getAddress()).thenReturn(address);
        return location;
    }

    private AddressRangeIterator iterator(AddressRange... ranges) {
        var values = List.of(ranges).iterator();
        return new AddressRangeIterator() {
            @Override
            public boolean hasNext() {
                return values.hasNext();
            }

            @Override
            public AddressRange next() {
                return values.next();
            }
        };
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> parse(Response response) {
        return JsonHelper.parseJson(response.toJson());
    }

    @SuppressWarnings("unchecked")
    private void assertContext(Map<String, Object> result, String key,
            String program, String address) {
        Map<String, Object> context = (Map<String, Object>) result.get(key);
        assertEquals(program, context.get("program"));
        assertEquals(address, context.get("address"));
    }

    private static final class RecordingThreadingStrategy
            implements ThreadingStrategy {
        private boolean readCalled;

        @Override
        public <T> T executeRead(Callable<T> action) throws Exception {
            readCalled = true;
            return action.call();
        }

        @Override
        public <T> T executeWrite(Program program, String name,
                Callable<T> action) throws Exception {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean isHeadless() {
            return false;
        }
    }

    private static final class FakeGuiAccess
            implements GuiContextService.GuiAccess, GuiContextService.Navigation {
        private ProgramLocation location;
        private ProgramSelection selection;
        private Program activeProgram;
        private Program navigableProgram;
        private List<Program> openPrograms = List.of();
        private boolean navigateResult = true;
        private Runnable onActivate = () -> {};
        private Runnable onNavigate = () -> {};
        private int activationCount;
        private int navigationCount;
        private boolean requireEdt;

        @Override
        public ProgramLocation currentLocation() {
            assertEventThread();
            return location;
        }

        @Override
        public ProgramSelection currentSelection() {
            assertEventThread();
            return selection;
        }

        @Override
        public Program currentProgram() {
            assertEventThread();
            return activeProgram;
        }

        @Override
        public List<Program> openPrograms() {
            assertEventThread();
            return openPrograms;
        }

        @Override
        public GuiContextService.Navigation navigationFor(Program program) {
            assertEventThread();
            return program == navigableProgram ? this : null;
        }

        @Override
        public void activate(Program program) {
            assertEventThread();
            activationCount++;
            activeProgram = program;
            onActivate.run();
        }

        @Override
        public boolean goTo(Address address, Program program) {
            assertEventThread();
            navigationCount++;
            onNavigate.run();
            return navigateResult;
        }

        private void assertEventThread() {
            if (requireEdt) {
                assertTrue(SwingUtilities.isEventDispatchThread());
            }
        }
    }
}
