package com.xebyte.core;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Transaction-neutral planning and application for exact-address comments.
 *
 * <p>Callers own the transaction. Planning intentionally reads the previous
 * value, so callers that need atomic read-before-write behavior must plan and
 * apply inside the same write transaction.
 */
final class AddressCommentCore {

    enum WriteMode {
        REPLACE,
        REMOVE,
        APPEND_IDEMPOTENT
    }

    record Plan(
            Address address,
            CommentType type,
            String previous,
            String requested,
            String resulting,
            boolean changed) {
    }

    /**
     * Resolve an address without silently choosing between mapped spaces that
     * share an unqualified offset.
     */
    Address resolveAddress(Program program, String addressText) {
        Objects.requireNonNull(program, "program");
        if (addressText == null || addressText.isBlank()) {
            throw new IllegalArgumentException("Address is required");
        }

        Address resolved = ServiceUtils.parseAddress(program, addressText);
        if (resolved == null) {
            throw new IllegalArgumentException(ServiceUtils.getLastParseError());
        }
        if (!addressText.contains(":")) {
            List<Address> candidates =
                mappedCandidatesAtOffset(program, resolved.getOffset());
            if (candidates.size() > 1) {
                String choices = candidates.stream()
                    .map(Address::toString)
                    .toList()
                    .toString();
                throw new IllegalArgumentException(
                    "Ambiguous unqualified address '" + addressText
                        + "' maps to multiple program address spaces: "
                        + choices
                        + ". Use a qualified <space>:<hex> address.");
            }
        }
        validateAddress(program, resolved);
        return resolved;
    }

    Plan plan(
            Program program,
            Address address,
            CommentType type,
            String text,
            WriteMode mode) {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(address, "address");
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(text, "text");
        Objects.requireNonNull(mode, "mode");
        validateAddress(program, address);

        String previous =
            program.getListing().getComment(type, address);
        String resulting = switch (mode) {
            case REMOVE -> null;
            case REPLACE -> text;
            case APPEND_IDEMPOTENT ->
                appendOnce(previous, text);
        };
        return new Plan(
            address,
            type,
            previous,
            text,
            resulting,
            !Objects.equals(previous, resulting));
    }

    void apply(Program program, Plan plan) {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(plan, "plan");
        validateAddress(program, plan.address());
        if (plan.changed()) {
            program.getListing().setComment(
                plan.address(), plan.type(), plan.resulting());
        }
    }

    private static void validateAddress(
            Program program, Address address) {
        AddressSpace space = address.getAddressSpace();
        if (space.getType() == AddressSpace.TYPE_EXTERNAL
                || address.isExternalAddress()) {
            throw new IllegalArgumentException(
                "External addresses cannot receive program comments: "
                    + address);
        }

        AddressSpace programSpace =
            program.getAddressFactory().getAddressSpace(space.getName());
        // Address does not carry a Program owner. Space identity is therefore
        // the strongest available ownership boundary (and is decisive for
        // program-local overlay spaces); service callers additionally resolve
        // raw address text through the target program's own factory.
        if (programSpace == null || programSpace != space) {
            throw new IllegalArgumentException(
                "Address does not belong to the target program: "
                    + address);
        }
        Address programAddress;
        try {
            programAddress =
                programSpace.getAddress(address.getOffset());
        }
        catch (RuntimeException e) {
            throw new IllegalArgumentException(
                "Address does not belong to the target program: "
                    + address,
                e);
        }
        if (!programAddress.equals(address)) {
            throw new IllegalArgumentException(
                "Address does not belong to the target program: "
                    + address);
        }
        if (!program.getMemory().contains(address)) {
            throw new IllegalArgumentException(
                "Address is not mapped in program memory: " + address);
        }
    }

    private static String appendOnce(
            String previous, String requested) {
        if (previous == null || previous.isEmpty()) {
            return requested;
        }
        for (String line : previous.split("\\R", -1)) {
            if (line.equals(requested)) {
                return previous;
            }
        }
        return previous + "\n" + requested;
    }

    private static List<Address> mappedCandidatesAtOffset(
            Program program, long offset) {
        Set<Address> candidates = new LinkedHashSet<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            Address start = block.getStart();
            Address end = block.getEnd();
            if (Long.compareUnsigned(offset, start.getOffset()) < 0
                    || Long.compareUnsigned(
                        offset, end.getOffset()) > 0) {
                continue;
            }
            try {
                Address candidate =
                    start.getAddressSpace().getAddress(offset);
                if (block.contains(candidate)) {
                    candidates.add(candidate);
                }
            }
            catch (RuntimeException ignored) {
                // The offset is outside this address space.
            }
        }
        return new ArrayList<>(candidates);
    }
}
