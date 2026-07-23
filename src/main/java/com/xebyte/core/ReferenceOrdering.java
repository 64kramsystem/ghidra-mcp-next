package com.xebyte.core;

import java.util.Comparator;
import java.util.Locale;

import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;

/**
 * Shared deterministic reference ordering for listing and xref continuations.
 */
final class ReferenceOrdering {

    private static final Comparator<Reference> PER_DESTINATION =
        Comparator.comparing((Reference reference) -> reference.getFromAddress())
            .thenComparing(reference -> reference.getReferenceType().getName())
            .thenComparingInt(Reference::getOperandIndex)
            .thenComparing(reference -> sourceKind(reference.getSource()))
            .thenComparing(reference -> reference.getToAddress());

    private static final Comparator<Reference> INCOMING =
        Comparator.comparing((Reference reference) -> reference.getToAddress())
            .thenComparing(PER_DESTINATION);

    private static final Comparator<Reference> OUTGOING =
        Comparator.comparing((Reference reference) -> reference.getFromAddress())
            .thenComparing(reference -> reference.getToAddress())
            .thenComparing(reference -> reference.getReferenceType().getName())
            .thenComparingInt(Reference::getOperandIndex)
            .thenComparing(reference -> sourceKind(reference.getSource()));

    private ReferenceOrdering() {
    }

    static Comparator<Reference> perDestination() {
        return PER_DESTINATION;
    }

    static Comparator<Reference> incoming() {
        return INCOMING;
    }

    static Comparator<Reference> outgoing() {
        return OUTGOING;
    }

    static String sourceKind(SourceType source) {
        return source == null ? "" : source.name().toLowerCase(Locale.ROOT);
    }
}
