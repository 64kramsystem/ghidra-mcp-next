package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.symbol.RefType;

public class FlowDisassemblyPlannerTest {

    private static final GenericAddressSpace RAM =
        new GenericAddressSpace("ram", 16, AddressSpace.TYPE_RAM, 0);

    @Test
    public void followsBranchAndFallthroughButNotUnreachedBytes() {
        FakeSource source = new FakeSource();
        source.define(instruction(0x1000, 2, RefType.CONDITIONAL_JUMP, 0x1002L, 0x1008));
        source.define(instruction(0x1002, 1, RefType.TERMINATOR, null));
        source.define(instruction(0x1008, 1, RefType.TERMINATOR, null));
        source.define(instruction(0x1004, 1, RefType.TERMINATOR, null));

        FlowDisassemblyService.FlowPlan plan =
            new FlowDisassemblyService.FlowPlanner(source).plan(
                request(List.of(address(0x1000)), true, true, 100));

        assertEquals(List.of(0x1000L, 0x1002L, 0x1008L),
            plan.instructions().stream()
                .map(record -> record.address().getOffset())
                .toList());
        assertFalse(plan.instructions().stream()
            .anyMatch(record -> record.address().equals(address(0x1004))));
    }

    @Test
    public void recordsCallsWithoutTraversingThemWhenDisabled() {
        FakeSource source = new FakeSource();
        source.define(instruction(0x1000, 3, RefType.UNCONDITIONAL_CALL, 0x1003L, 0x2000));
        source.define(instruction(0x1003, 1, RefType.TERMINATOR, null));
        source.define(instruction(0x2000, 1, RefType.TERMINATOR, null));

        FlowDisassemblyService.FlowPlan plan =
            new FlowDisassemblyService.FlowPlanner(source).plan(
                request(List.of(address(0x1000)), false, true, 100));

        assertEquals(List.of(address(0x2000)), plan.directCallTargets());
        assertFalse(plan.instructions().stream()
            .anyMatch(record -> record.address().equals(address(0x2000))));
    }

    @Test
    public void computedFlowIsReportedWithoutGuessingTarget() {
        FakeSource source = new FakeSource();
        source.define(instruction(0x1000, 3, RefType.COMPUTED_JUMP, null, 0x2000));

        FlowDisassemblyService.FlowPlan plan =
            new FlowDisassemblyService.FlowPlanner(source).plan(
                request(List.of(address(0x1000)), true, true, 100));

        assertEquals(1, plan.instructions().size());
        assertEquals(1, plan.unresolvedFlows().size());
        assertEquals(address(0x1000), plan.unresolvedFlows().get(0).from());
        assertTrue(plan.directBranchTargets().isEmpty());
        assertFalse(plan.instructions().stream()
            .anyMatch(record -> record.address().equals(address(0x2000))));
    }

    @Test
    public void enforcesInstructionCapBeforeNextDecode() {
        FakeSource source = new FakeSource();
        source.define(instruction(0x1000, 1, RefType.CONDITIONAL_JUMP, 0x1001L, 0x1002));
        source.define(instruction(0x1001, 1, RefType.TERMINATOR, null));
        source.define(instruction(0x1002, 1, RefType.TERMINATOR, null));

        FlowDisassemblyService.FlowPlan plan =
            new FlowDisassemblyService.FlowPlanner(source).plan(
                request(List.of(address(0x1000)), true, true, 1));

        assertEquals(1, plan.instructions().size());
        assertTrue(plan.instructionCapReached());
        assertTrue(plan.stopReasons().stream()
            .anyMatch(stop -> "instruction_cap".equals(stop.reason())));
    }

    @Test
    public void definedDataIsBarrierByDefaultAndClearCandidateWhenAuthorized() {
        FakeSource source = new FakeSource();
        source.define(instruction(0x1000, 1, RefType.TERMINATOR, null));
        source.locate(FlowDisassemblyService.Location.data(
            address(0x1000), address(0x1000), address(0x1000)));

        FlowDisassemblyService.FlowPlan preserved =
            new FlowDisassemblyService.FlowPlanner(source).plan(
                request(List.of(address(0x1000)), true, true, 100));
        assertTrue(preserved.instructions().isEmpty());
        assertEquals("defined_data", preserved.conflicts().get(0).reason());

        FlowDisassemblyService.FlowPlan cleared =
            new FlowDisassemblyService.FlowPlanner(source).plan(
                request(List.of(address(0x1000)), true, false, 100));
        assertEquals(1, cleared.instructions().size());
        assertEquals(List.of(new FlowDisassemblyService.DataUnit(
            address(0x1000), address(0x1000))), cleared.clearedData());
    }

    @Test
    public void traversesExistingInstructionButRejectsMiddleOfCodeUnit() {
        FakeSource source = new FakeSource();
        FlowDisassemblyService.DecodedInstruction existing =
            instruction(0x1000, 2, RefType.FLOW, 0x1002L);
        source.locate(FlowDisassemblyService.Location.existing(existing));
        source.locate(FlowDisassemblyService.Location.middle(
            address(0x1001), address(0x1000), address(0x1001)));
        source.define(instruction(0x1002, 1, RefType.TERMINATOR, null));

        FlowDisassemblyService.FlowPlan plan =
            new FlowDisassemblyService.FlowPlanner(source).plan(
                request(List.of(address(0x1000), address(0x1001)), true, true, 100));

        assertEquals(List.of(address(0x1000), address(0x1002)),
            plan.instructions().stream()
                .map(FlowDisassemblyService.InstructionRecord::address)
                .toList());
        assertTrue(plan.instructions().get(0).existing());
        assertEquals("middle_of_code_unit", plan.conflicts().get(0).reason());
    }

    @Test
    public void rejectsInstructionThatCrossesRestrictionRatherThanClipping() {
        FakeSource source = new FakeSource();
        source.define(instruction(0x2fff, 2, RefType.TERMINATOR, null));

        FlowDisassemblyService.FlowPlan plan =
            new FlowDisassemblyService.FlowPlanner(source).plan(
                request(List.of(address(0x2fff)), true, true, 100));

        assertTrue(plan.instructions().isEmpty());
        assertEquals("restricted_boundary", plan.stopReasons().get(0).reason());
    }

    @Test
    public void createsSeparateBodiesForSeedsAndFollowedCallTargets() {
        FakeSource source = new FakeSource();
        source.define(instruction(0x1000, 3, RefType.UNCONDITIONAL_CALL, 0x1003L, 0x2000));
        source.define(instruction(0x1003, 1, RefType.TERMINATOR, null));
        source.define(instruction(0x2000, 1, RefType.TERMINATOR, null));
        FlowDisassemblyService.FlowRequest request = new FlowDisassemblyService.FlowRequest(
            List.of(address(0x1000)),
            new AddressSet(address(0x1000), address(0x2fff)),
            true,
            true,
            true,
            false,
            100);

        FlowDisassemblyService.FlowPlan plan =
            new FlowDisassemblyService.FlowPlanner(source).plan(request);

        assertEquals(List.of(address(0x1000), address(0x2000)),
            plan.functions().stream()
                .map(FlowDisassemblyService.FunctionPlan::entry)
                .toList());
        assertTrue(plan.functions().get(0).body()
            .contains(address(0x1000), address(0x1003)));
        assertFalse(plan.functions().get(0).body().contains(address(0x2000)));
        assertTrue(plan.functions().get(1).body().contains(address(0x2000)));
    }

    @Test
    public void normalizesQueueOrderAndMergesAdjacentCandidateBytes() {
        FakeSource source = new FakeSource();
        source.define(instruction(
            0x1000, 1, RefType.CONDITIONAL_JUMP, 0x1001L, 0x1003));
        source.define(instruction(0x1001, 2, RefType.TERMINATOR, null));
        source.define(instruction(0x1003, 1, RefType.TERMINATOR, null));

        FlowDisassemblyService.FlowPlan reversed =
            new FlowDisassemblyService.FlowPlanner(source).plan(
                request(
                    List.of(address(0x1003), address(0x1000)),
                    true,
                    true,
                    100));
        FlowDisassemblyService.FlowPlan sorted =
            new FlowDisassemblyService.FlowPlanner(source).plan(
                request(
                    List.of(address(0x1000), address(0x1003)),
                    true,
                    true,
                    100));

        assertEquals(sorted.normalizedSeeds(), reversed.normalizedSeeds());
        assertEquals(sorted.instructions(), reversed.instructions());
        assertEquals(sorted.directBranchTargets(), reversed.directBranchTargets());
        assertEquals(1, reversed.plannedNewInstructions().getNumAddressRanges());
        assertTrue(reversed.plannedNewInstructions()
            .contains(address(0x1000), address(0x1003)));
    }

    @Test
    public void decodeFailureStopsThatPathWithoutInventingAnInstruction() {
        FakeSource source = new FakeSource();

        FlowDisassemblyService.FlowPlan plan =
            new FlowDisassemblyService.FlowPlanner(source).plan(
                request(List.of(address(0x1000)), true, true, 100));

        assertTrue(plan.instructions().isEmpty());
        assertEquals("decode_failure", plan.stopReasons().get(0).reason());
    }

    private static FlowDisassemblyService.FlowRequest request(
            List<Address> seeds,
            boolean followCalls,
            boolean preserveDefinedData,
            int maxInstructions) {
        return new FlowDisassemblyService.FlowRequest(
            seeds,
            new AddressSet(address(0x1000), address(0x2fff)),
            followCalls,
            preserveDefinedData,
            false,
            false,
            maxInstructions);
    }

    private static FlowDisassemblyService.DecodedInstruction instruction(
            long offset,
            int length,
            ghidra.program.model.symbol.FlowType flowType,
            Long fallThrough,
            long... flows) {
        return new FlowDisassemblyService.DecodedInstruction(
            address(offset),
            length,
            "instruction " + Long.toHexString(offset),
            fallThrough != null ? address(fallThrough) : null,
            java.util.Arrays.stream(flows).mapToObj(FlowDisassemblyPlannerTest::address).toList(),
            flowType);
    }

    private static Address address(long offset) {
        return RAM.getAddress(offset);
    }

    private static final class FakeSource
            implements FlowDisassemblyService.InstructionSource {
        private final Map<Address, FlowDisassemblyService.DecodedInstruction> decoded =
            new HashMap<>();

        void define(FlowDisassemblyService.DecodedInstruction instruction) {
            decoded.put(instruction.address(), instruction);
        }

        private final Map<Address, FlowDisassemblyService.Location> locations =
            new HashMap<>();

        void locate(FlowDisassemblyService.Location location) {
            locations.put(location.address(), location);
        }

        @Override
        public FlowDisassemblyService.Location inspect(Address address) {
            return locations.getOrDefault(
                address, FlowDisassemblyService.Location.undefined(address));
        }

        @Override
        public FlowDisassemblyService.DecodedInstruction decode(Address address) {
            return decoded.get(address);
        }

        @Override
        public List<FlowDisassemblyService.Location> intersecting(
                Address start,
                Address end) {
            return locations.values().stream()
                .filter(location -> location.unitStart() != null)
                .filter(location -> location.unitStart().compareTo(end) <= 0)
                .filter(location -> location.unitEnd().compareTo(start) >= 0)
                .toList();
        }
    }
}
