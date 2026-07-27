package com.xebyte.core;

import java.util.Objects;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;

/**
 * Transaction-neutral planning and application for exact-address comments.
 *
 * <p>Callers own the transaction. Planning intentionally reads the previous
 * value, so callers that need atomic read-before-write behavior must plan and
 * apply inside the same write transaction.
 */
final class AddressCommentCore {

    /**
     * Supplies the default "no extra ranges" argument for a mapped-address check.
     *
     * <p>A fresh set each time rather than a shared constant: {@link AddressSet}
     * is mutable, and one shared empty instance would be a global that a cast
     * could corrupt for every caller at once.
     */
    private static AddressSetView noAdditionalMapped() {
        return new AddressSet();
    }

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
        return resolveAddress(program, addressText, true);
    }

    /**
     * @param requireMapped when false, an address outside mapped memory resolves instead of
     *     failing. Deleting a reference whose target is unmapped is legitimate -- a stale
     *     {@code JMP $FFFF} edge is exactly the kind worth removing -- and the reference
     *     manager stores such edges perfectly well.
     */
    ResolvedAddress resolveAddress(
            Program program, String addressText, boolean requireMapped) {
        return resolveAddress(
            program, addressText, requireMapped, noAdditionalMapped());
    }

    /**
     * @param additionalMapped ranges to treat as mapped on top of the program's current
     *     memory. This exists for a caller that plans memory-block creation and the
     *     annotations landing inside those blocks in one pass: during planning the blocks
     *     do not exist yet, so {@code Memory.contains} is not yet the whole truth. Pass
     *     an empty set -- or use an overload without this parameter -- to validate strictly
     *     against current memory.
     */
    ResolvedAddress resolveAddress(
            Program program,
            String addressText,
            boolean requireMapped,
            AddressSetView additionalMapped) {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(additionalMapped, "additionalMapped");
        if (addressText == null || addressText.isBlank()) {
            throw new IllegalArgumentException("Address is required");
        }

        Address resolved = ServiceUtils.parseAddress(program, addressText);
        if (resolved == null) {
            throw new IllegalArgumentException(ServiceUtils.getLastParseError());
        }
        String ambiguity = ServiceUtils.ambiguousUnqualifiedAddressError(
            program, addressText, resolved);
        if (ambiguity != null) {
            throw new IllegalArgumentException(ambiguity);
        }
        validateAddress(
            program, resolved, requireMapped, additionalMapped);
        return new ResolvedAddress(program, resolved);
    }

    Plan plan(
            Program program,
            ResolvedAddress target,
            CommentType type,
            String text,
            WriteMode mode) {
        return plan(
            program, target, type, text, mode, noAdditionalMapped());
    }

    /**
     * @param additionalMapped see
     *     {@link #resolveAddress(Program, String, boolean, AddressSetView)}.
     */
    Plan plan(
            Program program,
            ResolvedAddress target,
            CommentType type,
            String text,
            WriteMode mode,
            AddressSetView additionalMapped) {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(text, "text");
        Objects.requireNonNull(mode, "mode");
        Objects.requireNonNull(additionalMapped, "additionalMapped");
        validateTarget(program, target, additionalMapped);

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

    /**
     * Applies a planned comment. Validation here is always strict: by the time a caller
     * applies, any memory block the plan depended on must already have been created.
     */
    void apply(Program program, Plan plan) {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(plan, "plan");
        validateTarget(program, plan.target(), noAdditionalMapped());
        if (plan.changed()) {
            program.getListing().setComment(
                plan.address(), plan.type(), plan.resulting());
        }
    }

    private static void validateTarget(
            Program program,
            ResolvedAddress target,
            AddressSetView additionalMapped) {
        if (target.owner() != program) {
            throw new IllegalArgumentException(
                "Resolved address belongs to a different target program");
        }
        validateAddress(
            program, target.address(), true, additionalMapped);
    }

    private static void validateAddress(
            Program program,
            Address address,
            boolean requireMapped,
            AddressSetView additionalMapped) {
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
        if (requireMapped
                && !program.getMemory().contains(address)
                && !additionalMapped.contains(address)) {
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
}
