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

    /**
     * An address resolved by this core for one exact Program instance.
     *
     * <p>Ghidra physical {@link AddressSpace} objects can be shared by
     * same-language programs, so a raw {@link Address} cannot carry sufficient
     * ownership evidence by itself.
     */
    record ResolvedAddress(Program owner, Address address) {
        ResolvedAddress {
            Objects.requireNonNull(owner, "owner");
            Objects.requireNonNull(address, "address");
        }
    }

    record Plan(
            ResolvedAddress target,
            CommentType type,
            String previous,
            String requested,
            String resulting,
            boolean changed) {

        Address address() {
            return target.address();
        }
    }

    /**
     * Resolve an address without silently choosing between mapped spaces that
     * share an unqualified offset.
     */
    ResolvedAddress resolveAddress(
            Program program, String addressText) {
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
        return new ResolvedAddress(program, resolved);
    }

    Plan plan(
            Program program,
            ResolvedAddress target,
            CommentType type,
            String text,
            WriteMode mode) {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(text, "text");
        Objects.requireNonNull(mode, "mode");
        validateTarget(program, target);

        String previous =
            program.getListing().getComment(
                type, target.address());
        String resulting = switch (mode) {
            case REMOVE -> null;
            case REPLACE -> text;
            case APPEND_IDEMPOTENT ->
                appendOnce(previous, text);
        };
        return new Plan(
            target,
            type,
            previous,
            text,
            resulting,
            !Objects.equals(previous, resulting));
    }

    void apply(Program program, Plan plan) {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(plan, "plan");
        validateTarget(program, plan.target());
        if (plan.changed()) {
            program.getListing().setComment(
                plan.address(), plan.type(), plan.resulting());
        }
    }

    private static void validateTarget(
            Program program, ResolvedAddress target) {
        if (target.owner() != program) {
            throw new IllegalArgumentException(
                "Resolved address belongs to a different target program");
        }
        validateAddress(program, target.address());
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
        // Space identity remains useful for rejecting foreign program-local
        // overlays. Physical spaces may be shared, so owner identity is
        // enforced separately by ResolvedAddress.
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
        if (previous.equals(requested)
                || previous.startsWith(requested + "\n")
                || previous.endsWith("\n" + requested)
                || previous.contains("\n" + requested + "\n")) {
            return previous;
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
