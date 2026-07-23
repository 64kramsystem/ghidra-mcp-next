package com.xebyte.core;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;

/**
 * Precise, function-independent mutations of Ghidra's mixed listing.
 */
@McpToolGroup(value = "listing", description = "Targeted mixed-listing mutations")
public final class ListingMutationService {

    private static final Gson OUTPUT_JSON = new GsonBuilder()
        .disableHtmlEscaping()
        .serializeNulls()
        .create();

    @FunctionalInterface
    interface Planner {
        ListingClearCore.Plan plan(
            Program program,
            AddressSetView requested,
            ListingClearCore.Selection selection,
            ListingClearCore.Preservation preservation);
    }

    @FunctionalInterface
    interface Applier {
        void apply(Program program, ListingClearCore.Plan plan) throws Exception;
    }

    record RangeRecord(String start, String end) {
    }

    record CodeUnitRecord(String start, String end, String kind) {
    }

    record AnnotationCounts(int labels, int comments, int bookmarks, int references) {
    }

    record EffectiveFlags(
            boolean clear_instructions,
            boolean clear_data,
            boolean preserve_labels,
            boolean preserve_comments,
            boolean preserve_bookmarks,
            boolean preserve_user_references,
            boolean remove_intersecting_functions,
            boolean dry_run) {
    }

    record SourceRules(
            List<String> preserved_label_sources,
            List<String> preserved_outgoing_reference_sources,
            String incoming_references) {
    }

    record Result(
            String program,
            RangeRecord requested_range,
            RangeRecord expanded_range,
            List<RangeRecord> expanded_ranges,
            List<CodeUnitRecord> affected_code_units,
            AnnotationCounts preserved_annotation_counts,
            AnnotationCounts removed_annotation_counts,
            Map<String, Integer> removed_references_by_source_type,
            List<Map<String, String>> removed_functions,
            List<String> conflicts,
            EffectiveFlags effective_flags,
            SourceRules source_rules,
            boolean committed) {
    }

    private record Request(
            String startText,
            String endText,
            ListingClearCore.Selection selection,
            ListingClearCore.Preservation preservation,
            EffectiveFlags effectiveFlags) {
    }

    private record Planned(
            Address requestedStart,
            Address requestedEnd,
            ListingClearCore.Plan plan) {
    }

    private record Execution(Planned planned, boolean committed) {
    }

    private final ProgramProvider programProvider;
    private final ThreadingStrategy threadingStrategy;
    private final Planner planner;
    private final Applier applier;

    public ListingMutationService(
            ProgramProvider programProvider,
            ThreadingStrategy threadingStrategy) {
        this(programProvider, threadingStrategy, new ListingClearCore());
    }

    private ListingMutationService(
            ProgramProvider programProvider,
            ThreadingStrategy threadingStrategy,
            ListingClearCore core) {
        this(programProvider, threadingStrategy, core::plan, core::apply);
    }

    ListingMutationService(
            ProgramProvider programProvider,
            ThreadingStrategy threadingStrategy,
            Planner planner,
            Applier applier) {
        if (programProvider == null) {
            throw new IllegalArgumentException("programProvider is required");
        }
        if (threadingStrategy == null) {
            throw new IllegalArgumentException("threadingStrategy is required");
        }
        if (planner == null) {
            throw new IllegalArgumentException("planner is required");
        }
        if (applier == null) {
            throw new IllegalArgumentException("applier is required");
        }
        this.programProvider = programProvider;
        this.threadingStrategy = threadingStrategy;
        this.planner = planner;
        this.applier = applier;
    }

    @McpTool(path = "/undefine_range", method = "POST",
        description = "Preview or atomically clear complete instructions and/or data units",
        category = "listing")
    public Response undefineRange(
            @Param(value = "start", source = ParamSource.BODY, paramType = "address",
                description = "Inclusive start address") String start,
            @Param(value = "end", source = ParamSource.BODY, paramType = "address",
                description = "Inclusive end address") String end,
            @Param(value = "clear_instructions", source = ParamSource.BODY,
                defaultValue = "true",
                description = "Clear complete intersecting instruction units")
                boolean clearInstructions,
            @Param(value = "clear_data", source = ParamSource.BODY,
                defaultValue = "true",
                description = "Clear complete intersecting defined-data units")
                boolean clearData,
            @Param(value = "preserve_labels", source = ParamSource.BODY,
                defaultValue = "true",
                description = "Restore USER_DEFINED and IMPORTED labels")
                boolean preserveLabels,
            @Param(value = "preserve_comments", source = ParamSource.BODY,
                defaultValue = "true",
                description = "Retain all comments on affected units")
                boolean preserveComments,
            @Param(value = "preserve_bookmarks", source = ParamSource.BODY,
                defaultValue = "true",
                description = "Retain all bookmarks on affected units")
                boolean preserveBookmarks,
            @Param(value = "preserve_user_references", source = ParamSource.BODY,
                defaultValue = "true",
                description = "Restore USER_DEFINED and IMPORTED outgoing references")
                boolean preserveUserReferences,
            @Param(value = "remove_intersecting_functions", source = ParamSource.BODY,
                defaultValue = "false",
                description = "Explicitly remove every function intersecting cleared instructions")
                boolean removeIntersectingFunctions,
            @Param(value = "dry_run", source = ParamSource.BODY,
                defaultValue = "true",
                description = "Return the exact mutation plan without changing the program")
                boolean dryRun,
            @Param(value = "program", defaultValue = "",
                description = "Target program name") String programName) {
        if (!clearInstructions && !clearData) {
            return Response.err(
                "At least one of clear_instructions or clear_data must be true.");
        }

        ServiceUtils.ProgramOrError resolved =
            ServiceUtils.getProgramOrError(programProvider, programName);
        if (resolved.hasError()) {
            return resolved.error();
        }

        ListingClearCore.Selection selection = new ListingClearCore.Selection(
            clearInstructions, clearData, removeIntersectingFunctions);
        ListingClearCore.Preservation preservation = new ListingClearCore.Preservation(
            preserveLabels, preserveComments, preserveBookmarks, preserveUserReferences);
        EffectiveFlags flags = new EffectiveFlags(
            clearInstructions, clearData,
            preserveLabels, preserveComments, preserveBookmarks, preserveUserReferences,
            removeIntersectingFunctions, dryRun);
        Request request = new Request(start, end, selection, preservation, flags);
        Program program = resolved.program();

        try {
            Execution execution;
            if (dryRun) {
                Planned planned =
                    threadingStrategy.executeRead(() -> plan(program, request));
                execution = new Execution(planned, false);
            }
            else {
                execution = threadingStrategy.executeWrite(
                    program, "Undefine listing range", () -> {
                        Planned planned = plan(program, request);
                        if (!planned.plan().conflicts().isEmpty()) {
                            return new Execution(planned, false);
                        }
                        applier.apply(program, planned.plan());
                        return new Execution(planned, true);
                    });
            }
            if (!dryRun && !execution.planned().plan().conflicts().isEmpty()) {
                return Response.err(
                    "Cannot clear instructions in functions unless "
                        + "remove_intersecting_functions=true: "
                        + String.join("; ",
                            execution.planned().plan().conflicts()));
            }
            return Response.text(
                OUTPUT_JSON.toJson(toResult(program, request, execution)));
        }
        catch (Exception exception) {
            String message = exception.getMessage() != null
                ? exception.getMessage()
                : exception.toString();
            return Response.err("Error undefining listing range: " + message);
        }
    }

    private Planned plan(Program program, Request request) {
        Address start = ServiceUtils.parseAddress(program, request.startText());
        if (start == null) {
            throw new IllegalArgumentException("Invalid start address: "
                + usefulParseError(request.startText()));
        }
        Address end = ServiceUtils.parseAddress(program, request.endText());
        if (end == null) {
            throw new IllegalArgumentException("Invalid end address: "
                + usefulParseError(request.endText()));
        }
        if (!start.getAddressSpace().equals(end.getAddressSpace())) {
            throw new IllegalArgumentException(
                "start and end must be in the same address space");
        }
        if (start.compareTo(end) > 0) {
            throw new IllegalArgumentException("start must not be after end");
        }
        if (!program.getMemory().contains(start, end)) {
            throw new IllegalArgumentException(
                "every address in the requested range must be mapped");
        }
        AddressSet requested = new AddressSet(start, end);
        ListingClearCore.Plan clearPlan = planner.plan(
            program, requested, request.selection(), request.preservation());
        if (!clearPlan.expanded().isEmpty()
                && !program.getMemory().contains(clearPlan.expanded())) {
            throw new IllegalArgumentException(
                "expanded code-unit boundaries include unmapped addresses");
        }
        return new Planned(start, end, clearPlan);
    }

    private static String usefulParseError(String requested) {
        String detail = ServiceUtils.getLastParseError();
        return detail == null || detail.isBlank() ? requested : detail;
    }

    private static Result toResult(
            Program program, Request request, Execution execution) {
        Planned planned = execution.planned();
        ListingClearCore.Plan plan = planned.plan();

        List<RangeRecord> expandedRanges = new ArrayList<>();
        for (AddressRange range : plan.expanded()) {
            expandedRanges.add(new RangeRecord(
                address(range.getMinAddress()), address(range.getMaxAddress())));
        }
        RangeRecord expandedRange = expandedRanges.isEmpty()
            ? null
            : new RangeRecord(
                address(plan.expanded().getMinAddress()),
                address(plan.expanded().getMaxAddress()));

        List<CodeUnitRecord> units = plan.units().stream()
            .map(unit -> new CodeUnitRecord(
                address(unit.start()),
                address(unit.end()),
                unit.kind().name().toLowerCase()))
            .toList();
        List<Map<String, String>> functions = plan.functions().stream()
            .map(function -> {
                Map<String, String> result = new LinkedHashMap<>();
                result.put("entry", address(function.entry()));
                result.put("name", function.name());
                return result;
            })
            .toList();
        ListingClearCore.AnnotationSnapshot preserved = plan.annotations();
        ListingClearCore.AnnotationSnapshot removed = plan.removedAnnotations();
        AnnotationCounts preservedCounts = new AnnotationCounts(
            preserved.labels().size(),
            preserved.comments().size(),
            preserved.bookmarks().size(),
            preserved.references().size());
        AnnotationCounts removedCounts = new AnnotationCounts(
            removed.labels().size(),
            removed.comments().size(),
            removed.bookmarks().size(),
            removed.references().size());
        Map<String, Integer> removedReferencesBySource = new LinkedHashMap<>();
        for (var entry : plan.removedReferencesBySource().entrySet()) {
            removedReferencesBySource.put(entry.getKey().name(), entry.getValue());
        }

        return new Result(
            program.getName(),
            new RangeRecord(address(planned.requestedStart()), address(planned.requestedEnd())),
            expandedRange,
            List.copyOf(expandedRanges),
            units,
            preservedCounts,
            removedCounts,
            Collections.unmodifiableMap(
                new LinkedHashMap<>(removedReferencesBySource)),
            functions,
            plan.conflicts(),
            request.effectiveFlags(),
            new SourceRules(
                request.preservation().labels()
                    ? List.of("USER_DEFINED", "IMPORTED")
                    : List.of(),
                request.preservation().userReferences()
                    ? List.of("USER_DEFINED", "IMPORTED")
                    : List.of(),
                "untouched"),
            execution.committed());
    }

    private static String address(Address address) {
        return address == null ? null : address.toString();
    }
}
