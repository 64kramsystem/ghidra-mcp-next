package com.xebyte.core;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.DynamicHash;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateReference;
import ghidra.program.model.symbol.EquateTable;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.task.TaskMonitor;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Platform-neutral validation and atomic application of symbol profiles.
 *
 * <p>Planning performs every program-dependent lookup before mutation. The
 * caller's {@link ThreadingStrategy} owns the single application transaction.
 */
@McpToolGroup(
    value = "symbols",
    description = "Validate and atomically apply generic symbol profiles")
public final class SymbolProfileService {
    static final String PROFILE_SCHEMA =
        "{\"type\":\"object\",\"additionalProperties\":false,"
        + "\"required\":[\"schema_version\",\"id\",\"version\"],"
        + "\"properties\":{"
        + "\"schema_version\":{\"const\":1},"
        + "\"id\":{\"type\":\"string\",\"minLength\":1},"
        + "\"version\":{\"type\":\"string\",\"minLength\":1},"
        + "\"description\":{\"type\":\"string\"},"
        + "\"symbols\":{\"type\":\"array\",\"items\":{"
        + "\"type\":\"object\",\"additionalProperties\":false,"
        + "\"required\":[\"address\",\"name\"],\"properties\":{"
        + "\"address\":{\"type\":\"string\"},"
        + "\"name\":{\"type\":\"string\"},"
        + "\"namespace\":{\"type\":\"string\"},"
        + "\"kind\":{\"enum\":[\"label\",\"entry_point\"],"
        + "\"default\":\"label\"},"
        + "\"primary\":{\"type\":\"boolean\",\"default\":false},"
        + "\"source_note\":{\"type\":\"string\"}}}},"
        + "\"equates\":{\"type\":\"array\",\"items\":{"
        + "\"type\":\"object\",\"additionalProperties\":false,"
        + "\"required\":[\"name\",\"value\"],\"properties\":{"
        + "\"name\":{\"type\":\"string\"},"
        + "\"value\":{\"type\":\"integer\"},"
        + "\"description\":{\"type\":\"string\"},"
        + "\"applications\":{\"type\":\"array\",\"items\":{"
        + "\"type\":\"object\",\"additionalProperties\":false,"
        + "\"required\":[\"address\",\"operand_index\"],"
        + "\"properties\":{"
        + "\"address\":{\"type\":\"string\"},"
        + "\"operand_index\":{\"type\":\"integer\",\"minimum\":0},"
        + "\"scalar_index\":{\"type\":\"integer\",\"minimum\":0}}}}}}},"
        + "\"comments\":{\"type\":\"array\",\"items\":{"
        + "\"type\":\"object\",\"additionalProperties\":false,"
        + "\"required\":[\"address\",\"type\",\"text\"],"
        + "\"properties\":{"
        + "\"address\":{\"type\":\"string\"},"
        + "\"type\":{\"enum\":[\"plate\",\"pre\",\"post\","
        + "\"eol\",\"repeatable\"]},"
        + "\"text\":{\"type\":\"string\"}}}},"
        + "\"memory_blocks\":{\"type\":\"array\",\"items\":{"
        + "\"type\":\"object\",\"additionalProperties\":false,"
        + "\"required\":[\"name\",\"start\",\"length\"],"
        + "\"properties\":{"
        + "\"name\":{\"type\":\"string\"},"
        + "\"start\":{\"type\":\"string\"},"
        + "\"length\":{\"type\":\"integer\",\"minimum\":1},"
        + "\"fill\":{\"type\":\"integer\",\"minimum\":0,\"maximum\":255},"
        + "\"overlay\":{\"type\":\"boolean\",\"default\":false},"
        + "\"read\":{\"type\":\"boolean\",\"default\":true},"
        + "\"write\":{\"type\":\"boolean\",\"default\":false},"
        + "\"execute\":{\"type\":\"boolean\",\"default\":false},"
        + "\"comment\":{\"type\":\"string\"}}}}}}";

    private static final String CONFLICT_ERROR = "error";
    private static final String CONFLICT_KEEP = "keep";
    private static final String CONFLICT_REPLACE = "replace";

    private final ProgramProvider programProvider;
    private final ThreadingStrategy threading;
    private final SymbolProfileParser parser;
    private final AddressCommentCore commentCore;
    private final MemoryBlockCore blockCore;
    private final TaskMonitor monitor;

    public SymbolProfileService(
            ProgramProvider programProvider,
            ThreadingStrategy threading) {
        this(
            programProvider,
            threading,
            new SymbolProfileParser(),
            new AddressCommentCore(),
            new MemoryBlockCore(),
            TaskMonitor.DUMMY);
    }

    SymbolProfileService(
            ProgramProvider programProvider,
            ThreadingStrategy threading,
            SymbolProfileParser parser,
            AddressCommentCore commentCore,
            MemoryBlockCore blockCore,
            TaskMonitor monitor) {
        this.programProvider =
            Objects.requireNonNull(programProvider, "programProvider");
        this.threading = Objects.requireNonNull(threading, "threading");
        this.parser = Objects.requireNonNull(parser, "parser");
        this.commentCore = Objects.requireNonNull(commentCore, "commentCore");
        this.blockCore = Objects.requireNonNull(blockCore, "blockCore");
        this.monitor = Objects.requireNonNull(monitor, "monitor");
    }

    @McpTool(
        path = "/validate_symbol_profile",
        method = "POST",
        description =
            "Strictly validate and normalize a generic symbol profile",
        category = "symbols")
    public Response validateSymbolProfile(
            @Param(
                value = "profile",
                source = ParamSource.BODY,
                schemaFragment = PROFILE_SCHEMA,
                description = "Generic symbol profile schema version 1")
                Object profileValue,
            @Param(
                value = "program",
                defaultValue = "",
                description =
                    "Optional target program for address and conflict checks")
                String programName) {
        SymbolProfileParser.SymbolProfile profile;
        try {
            profile = parser.parse(profileValue);
        }
        catch (Exception error) {
            return Response.ok(invalidValidation(error));
        }

        boolean programChecks =
            programName != null && !programName.isBlank();
        if (!programChecks) {
            return Response.ok(validationResult(
                profile, false, List.of(), schemaWarnings(profile)));
        }

        try {
            Program program = requireProgram(programName);
            Plan plan = threading.executeRead(
                () -> {
                    revalidateProgram(programName, program);
                    return plan(
                        program,
                        profile,
                        CONFLICT_ERROR,
                        false,
                        true);
                });
            return Response.ok(validationResult(
                profile, true, plan.conflicts(), plan.warnings()));
        }
        catch (Exception error) {
            return Response.ok(validationResult(
                profile,
                true,
                List.of(message(error)),
                schemaWarnings(profile)));
        }
    }

    @McpTool(
        path = "/apply_symbol_profile",
        method = "POST",
        description =
            "Preview or atomically apply a generic symbol profile",
        category = "symbols",
        supportsSyntheticDryRun = false)
    public Response applySymbolProfile(
            @Param(
                value = "profile",
                source = ParamSource.BODY,
                schemaFragment = PROFILE_SCHEMA,
                description = "Generic symbol profile schema version 1")
                Object profileValue,
            @Param(
                value = "dry_run",
                source = ParamSource.BODY,
                defaultValue = "true",
                strictBoolean = true)
                boolean dryRun,
            @Param(
                value = "conflict_policy",
                source = ParamSource.BODY,
                defaultValue = "error",
                description = "error, keep, or replace")
                String conflictPolicy,
            @Param(
                value = "replace_user_definitions",
                source = ParamSource.BODY,
                defaultValue = "false",
                strictBoolean = true)
                boolean replaceUserDefinitions,
            @Param(
                value = "create_memory_blocks",
                source = ParamSource.BODY,
                defaultValue = "false",
                strictBoolean = true)
                boolean createMemoryBlocks,
            @Param(
                value = "program",
                defaultValue = "",
                description = "Target program name")
                String programName) {
        try {
            String policy = normalizePolicy(conflictPolicy);
            SymbolProfileParser.SymbolProfile profile =
                parser.parse(profileValue);
            Program program = requireProgram(programName);
            if (dryRun) {
                Plan plan = threading.executeRead(
                    () -> {
                        revalidateProgram(programName, program);
                        return plan(
                            program,
                            profile,
                            policy,
                            replaceUserDefinitions,
                            createMemoryBlocks);
                    });
                rejectUnresolved(plan, policy);
                return Response.ok(result(program, plan, false, true));
            }
            return threading.executeWrite(
                program,
                "Apply symbol profile " + profile.id(),
                () -> {
                    revalidateProgram(programName, program);
                    Plan plan = plan(
                        program,
                        profile,
                        policy,
                        replaceUserDefinitions,
                        createMemoryBlocks);
                    rejectUnresolved(plan, policy);
                    monitor.checkCancelled();
                    apply(program, plan);
                    return Response.ok(result(program, plan, true, false));
                });
        }
        catch (Exception error) {
            return Response.err(
                "Failed to apply symbol profile: " + message(error));
        }
    }

    private Plan plan(
            Program program,
            SymbolProfileParser.SymbolProfile profile,
            String policy,
            boolean replaceUserDefinitions,
            boolean createMemoryBlocks) throws Exception {
        validateResolvedRequestIdentities(program, profile);
        List<String> conflicts = new ArrayList<>();
        List<String> warnings = new ArrayList<>(schemaWarnings(profile));
        List<String> replacements = new ArrayList<>();
        List<NamespacePlan> namespaces =
            planNamespaces(program, profile, conflicts);
        List<SymbolPlan> symbols = planSymbols(
            program,
            profile,
            policy,
            replaceUserDefinitions,
            conflicts,
            replacements);
        List<EquatePlan> equates = planEquates(
            program,
            profile,
            policy,
            replaceUserDefinitions,
            conflicts,
            replacements);
        List<CommentPlan> comments = planComments(
            program,
            profile,
            policy,
            replaceUserDefinitions,
            conflicts,
            replacements);
        List<BlockPlan> blocks = planBlocks(
            program,
            profile,
            policy,
            createMemoryBlocks,
            conflicts);
        if (!createMemoryBlocks && !profile.memoryBlocks().isEmpty()) {
            warnings.add(
                "memory_blocks were validated but creation is disabled");
        }
        return new Plan(
            profile,
            policy,
            replaceUserDefinitions,
            createMemoryBlocks,
            namespaces,
            symbols,
            equates,
            comments,
            blocks,
            List.copyOf(new LinkedHashSet<>(conflicts)),
            List.copyOf(new LinkedHashSet<>(warnings)),
            List.copyOf(new LinkedHashSet<>(replacements)));
    }

    private List<NamespacePlan> planNamespaces(
            Program program,
            SymbolProfileParser.SymbolProfile profile,
            List<String> conflicts) {
        Map<String, NamespacePlan> plans = new LinkedHashMap<>();
        Set<String> requestedLabels = new LinkedHashSet<>();
        for (SymbolProfileParser.ProfileSymbol symbol : profile.symbols()) {
            requestedLabels.add(symbol.qualifiedName());
            String path = "";
            for (String component : namespaceComponents(symbol.namespace())) {
                path = path.isEmpty() ? component : path + "::" + component;
                plans.putIfAbsent(
                    path,
                    inspectNamespace(program, path, conflicts));
            }
        }
        for (String path : plans.keySet()) {
            if (requestedLabels.contains(path)) {
                conflicts.add(
                    "requested namespace conflicts with requested label: "
                        + path);
            }
        }
        return List.copyOf(plans.values());
    }

    private NamespacePlan inspectNamespace(
            Program program, String path, List<String> conflicts) {
        Namespace parent = program.getGlobalNamespace();
        String traversed = "";
        for (String component : namespaceComponents(path)) {
            traversed = traversed.isEmpty()
                ? component : traversed + "::" + component;
            Namespace existing =
                program.getSymbolTable().getNamespace(component, parent);
            if (existing != null) {
                parent = existing;
                continue;
            }
            List<Symbol> colliding =
                program.getSymbolTable().getSymbols(component, parent);
            if (!colliding.isEmpty()) {
                conflicts.add(
                    "namespace '" + traversed
                        + "' conflicts with an existing symbol");
                return new NamespacePlan(path, "conflict");
            }
            return new NamespacePlan(path, "create");
        }
        return new NamespacePlan(path, "idempotent");
    }

    private List<SymbolPlan> planSymbols(
            Program program,
            SymbolProfileParser.SymbolProfile profile,
            String policy,
            boolean replaceUserDefinitions,
            List<String> conflicts,
            List<String> replacements) {
        List<SymbolPlan> result = new ArrayList<>();
        SymbolTable table = program.getSymbolTable();
        for (SymbolProfileParser.ProfileSymbol requested : profile.symbols()) {
            Address address = resolveMappedAddress(
                program, requested.address(), "symbol address");
            List<Symbol> named = existingSymbols(
                program, requested.name(), requested.namespace());
            Symbol exact = named.stream()
                .filter(symbol -> symbol.getAddress().equals(address))
                .findFirst()
                .orElse(null);
            List<Symbol> elsewhere = named.stream()
                .filter(symbol -> !symbol.getAddress().equals(address))
                .toList();
            boolean entryExists = table.isExternalEntryPoint(address);

            String conflict = null;
            List<Symbol> replace = new ArrayList<>();
            if (exact != null && exact.getSymbolType() != SymbolType.LABEL) {
                conflict =
                    "symbol '" + requested.qualifiedName()
                        + "' exists with incompatible type "
                        + exact.getSymbolType();
            }
            if (!elsewhere.isEmpty()) {
                if (requested.kind()
                        == SymbolProfileParser.SymbolKind.ENTRY_POINT) {
                    conflict =
                        "entry point move is not implicit for '"
                            + requested.qualifiedName() + "'";
                }
                else if (elsewhere.stream().anyMatch(
                        symbol -> symbol.getSymbolType() != SymbolType.LABEL)) {
                    conflict =
                        "symbol '" + requested.qualifiedName()
                            + "' exists at another address with "
                            + "a non-label type";
                }
                else {
                    conflict =
                        "symbol '" + requested.qualifiedName()
                            + "' exists at another address";
                    replace.addAll(elsewhere);
                }
            }
            Symbol primary = table.getPrimarySymbol(address);
            if (requested.primary()
                    && primary != null
                    && primary != exact) {
                conflict =
                    "different primary symbol already exists at "
                        + qualified(address);
                if (primary.getSymbolType() == SymbolType.LABEL) {
                    replace.add(primary);
                }
            }

            String action;
            if (conflict == null) {
                boolean exactComplete =
                    exact != null
                        && (!requested.primary() || exact.isPrimary())
                        && (requested.kind()
                                != SymbolProfileParser.SymbolKind.ENTRY_POINT
                            || entryExists);
                action = exactComplete ? "idempotent"
                    : exact == null ? "create" : "update";
            }
            else {
                action = conflictAction(
                    policy,
                    replaceUserDefinitions,
                    conflict,
                    replace,
                    conflicts,
                    replacements);
                if ("replace".equals(action)
                        && (requested.kind()
                            == SymbolProfileParser.SymbolKind.ENTRY_POINT
                            && !elsewhere.isEmpty())) {
                    action = "conflict";
                }
            }
            result.add(new SymbolPlan(
                requested,
                address,
                List.copyOf(replace),
                action,
                conflict));
        }
        return List.copyOf(result);
    }

    private List<EquatePlan> planEquates(
            Program program,
            SymbolProfileParser.SymbolProfile profile,
            String policy,
            boolean replaceUserDefinitions,
            List<String> conflicts,
            List<String> replacements) {
        List<EquatePlan> result = new ArrayList<>();
        EquateTable table = program.getEquateTable();
        for (SymbolProfileParser.ProfileEquate requested : profile.equates()) {
            Equate existing = table.getEquate(requested.name());
            String definitionConflict =
                existing != null && existing.getValue() != requested.value()
                    ? "equate '" + requested.name()
                        + "' already has value " + existing.getValue()
                    : null;
            String definitionAction;
            if (definitionConflict == null) {
                definitionAction =
                    existing == null ? "create" : "idempotent";
            }
            else if (CONFLICT_KEEP.equals(policy)) {
                conflicts.add(definitionConflict);
                definitionAction = "keep";
            }
            else if (CONFLICT_REPLACE.equals(policy)) {
                if (!replaceUserDefinitions) {
                    conflicts.add(
                        definitionConflict
                            + "; replace_user_definitions=true is required");
                    definitionAction = "conflict";
                }
                else {
                    definitionAction = "replace";
                    replacements.add("equate:" + requested.name());
                }
            }
            else {
                conflicts.add(definitionConflict);
                definitionAction = "conflict";
            }

            List<ApplicationPlan> applications = new ArrayList<>();
            for (SymbolProfileParser.EquateApplication application
                    : requested.applications()) {
                ApplicationSite site =
                    resolveApplication(program, requested, application);
                if ("keep".equals(definitionAction)
                        || "conflict".equals(definitionAction)) {
                    String conflict =
                        "equate application at "
                            + qualified(site.address()) + " operand "
                            + site.operandIndex()
                            + scalarSuffix(site)
                            + " was not applied because parent "
                            + definitionConflict;
                    conflicts.add(conflict);
                    applications.add(new ApplicationPlan(
                        site,
                        List.of(),
                        definitionAction,
                        conflict));
                    continue;
                }
                List<Equate> atSite = equatesAtSite(
                    table, site);
                Equate same = atSite.stream()
                    .filter(equate ->
                        equate.getName().equals(requested.name())
                            && equate.getValue() == requested.value())
                    .findFirst()
                    .orElse(null);
                List<Equate> different = atSite.stream()
                    .filter(equate -> equate != same)
                    .toList();
                String conflict = different.isEmpty()
                    ? null
                    : "equate application at "
                        + qualified(site.address()) + " operand "
                        + site.operandIndex()
                        + scalarSuffix(site)
                        + " already has "
                        + different.stream()
                            .map(Equate::getName)
                            .sorted()
                            .toList();
                String action;
                if (conflict == null) {
                    action = same == null ? "create" : "idempotent";
                }
                else if (CONFLICT_KEEP.equals(policy)) {
                    conflicts.add(conflict);
                    action = "keep";
                }
                else if (CONFLICT_REPLACE.equals(policy)) {
                    if (!replaceUserDefinitions) {
                        conflicts.add(
                            conflict
                                + "; replace_user_definitions=true is required");
                        action = "conflict";
                    }
                    else {
                        action = "replace";
                        replacements.add(
                            "equate_application:"
                                + qualified(site.address()) + ":"
                                + site.operandIndex() + scalarSuffix(site));
                    }
                }
                else {
                    conflicts.add(conflict);
                    action = "conflict";
                }
                applications.add(new ApplicationPlan(
                    site,
                    List.copyOf(different),
                    action,
                    conflict));
            }
            result.add(new EquatePlan(
                requested,
                definitionAction,
                definitionConflict,
                List.copyOf(applications)));
        }
        return List.copyOf(result);
    }

    private List<CommentPlan> planComments(
            Program program,
            SymbolProfileParser.SymbolProfile profile,
            String policy,
            boolean replaceUserDefinitions,
            List<String> conflicts,
            List<String> replacements) {
        List<CommentPlan> result = new ArrayList<>();
        for (SymbolProfileParser.ProfileComment requested
                : profile.comments()) {
            AddressCommentCore.ResolvedAddress target =
                commentCore.resolveAddress(program, requested.address());
            CommentType type = commentType(requested.type());
            AddressCommentCore.Plan corePlan = commentCore.plan(
                program,
                target,
                type,
                requested.text(),
                AddressCommentCore.WriteMode.REPLACE);
            String conflict =
                corePlan.previous() != null
                    && !corePlan.previous().equals(requested.text())
                        ? "comment " + requested.type().wireName()
                            + " at " + qualified(corePlan.address())
                            + " already has different text"
                        : null;
            String action;
            if (conflict == null) {
                action = corePlan.changed() ? "create" : "idempotent";
            }
            else if (CONFLICT_KEEP.equals(policy)) {
                conflicts.add(conflict);
                action = "keep";
            }
            else if (CONFLICT_REPLACE.equals(policy)) {
                if (!replaceUserDefinitions) {
                    conflicts.add(
                        conflict
                            + "; replace_user_definitions=true is required");
                    action = "conflict";
                }
                else {
                    action = "replace";
                    replacements.add(
                        "comment:" + qualified(corePlan.address())
                            + ":" + requested.type().wireName());
                }
            }
            else {
                conflicts.add(conflict);
                action = "conflict";
            }
            result.add(new CommentPlan(
                requested, corePlan, action, conflict));
        }
        return List.copyOf(result);
    }

    private List<BlockPlan> planBlocks(
            Program program,
            SymbolProfileParser.SymbolProfile profile,
            String policy,
            boolean createMemoryBlocks,
            List<String> conflicts) throws Exception {
        List<BlockPlan> result = new ArrayList<>();
        List<RequestedRange> requestedRanges = new ArrayList<>();
        for (SymbolProfileParser.ProfileMemoryBlock requested
                : profile.memoryBlocks()) {
            validateBlockRange(program, requested);
            if (!createMemoryBlocks) {
                result.add(new BlockPlan(
                    requested, null,
                    "disabled", null));
                continue;
            }
            MemoryBlock existing =
                program.getMemory().getBlock(requested.name());
            if (existing != null
                    && blockMatches(program, existing, requested)) {
                result.add(new BlockPlan(
                    requested, null,
                    "idempotent", null));
                continue;
            }

            MemoryBlockCore.CreateRequest request =
                blockRequest(requested);
            MemoryBlockCore.CreatePlan createPlan = null;
            String conflict = null;
            if (existing != null) {
                conflict =
                    "memory block name '" + requested.name()
                        + "' is already used by a different block";
            }
            else {
                try {
                    createPlan = blockCore.planCreate(program, request);
                    if (!requested.overlay()) {
                        Address end = checkedEnd(
                            createPlan.start(), createPlan.length());
                        for (RequestedRange earlier : requestedRanges) {
                            if (earlier.start().getAddressSpace().equals(
                                    createPlan.start().getAddressSpace())
                                    && overlaps(
                                        createPlan.start(),
                                        end,
                                        earlier.start(),
                                        earlier.end())) {
                                conflict =
                                    "requested memory block '"
                                        + requested.name()
                                        + "' overlaps requested block '"
                                        + earlier.name() + "'";
                                break;
                            }
                        }
                        requestedRanges.add(new RequestedRange(
                            requested.name(),
                            createPlan.start(),
                            end));
                    }
                }
                catch (Exception error) {
                    conflict = message(error);
                }
            }

            String action;
            if (conflict == null) {
                action = createMemoryBlocks ? "create" : "disabled";
            }
            else if (CONFLICT_KEEP.equals(policy)) {
                conflicts.add(conflict);
                action = "keep";
            }
            else {
                // Block replacement and overlap resolution are intentionally
                // never implicit, including under replace.
                conflicts.add(conflict);
                action = "conflict";
            }
            result.add(new BlockPlan(
                requested, createPlan, action, conflict));
        }
        return List.copyOf(result);
    }

    private static void validateBlockRange(
            Program program,
            SymbolProfileParser.ProfileMemoryBlock requested) {
        Address start =
            ServiceUtils.parseAddress(program, requested.start());
        if (start == null) {
            String detail = ServiceUtils.getLastParseError();
            throw new IllegalArgumentException(
                "invalid memory block start '" + requested.start()
                    + "': "
                    + (detail == null ? "address could not be resolved"
                        : detail));
        }
        checkedEnd(start, requested.length());
    }

    private void apply(Program program, Plan plan) throws Exception {
        createNamespaces(program, plan.namespaces());
        SymbolTable symbols = program.getSymbolTable();
        for (SymbolPlan symbolPlan : plan.symbols()) {
            monitor.checkCancelled();
            if (skipped(symbolPlan.action())) {
                continue;
            }
            for (Symbol old : symbolPlan.replace()) {
                if (!old.delete()) {
                    throw new IllegalStateException(
                        "failed to replace symbol " + old.getName(true));
                }
            }
            Namespace namespace = resolveNamespace(
                program, symbolPlan.requested().namespace(), false);
            if (namespace == null) {
                throw new IllegalStateException(
                    "planned namespace was not created: "
                        + symbolPlan.requested().namespace());
            }
            Symbol symbol = symbols.getSymbol(
                symbolPlan.requested().name(),
                symbolPlan.address(),
                namespace);
            if (symbol == null) {
                symbol = symbols.createLabel(
                    symbolPlan.address(),
                    symbolPlan.requested().name(),
                    namespace,
                    SourceType.IMPORTED);
            }
            if (symbolPlan.requested().primary() && !symbol.isPrimary()) {
                if (!symbol.setPrimary()) {
                    throw new IllegalStateException(
                        "failed to make symbol primary: "
                            + symbolPlan.requested().qualifiedName());
                }
            }
            if (symbolPlan.requested().kind()
                    == SymbolProfileParser.SymbolKind.ENTRY_POINT
                    && !symbols.isExternalEntryPoint(
                        symbolPlan.address())) {
                symbols.addExternalEntryPoint(symbolPlan.address());
            }
        }

        EquateTable equates = program.getEquateTable();
        for (EquatePlan equatePlan : plan.equates()) {
            monitor.checkCancelled();
            if ("keep".equals(equatePlan.action())
                    || "conflict".equals(equatePlan.action())) {
                continue;
            }
            if ("replace".equals(equatePlan.action())) {
                if (!equates.removeEquate(
                        equatePlan.requested().name())) {
                    throw new IllegalStateException(
                        "failed to replace equate "
                            + equatePlan.requested().name());
                }
            }
            Equate equate = equates.getEquate(
                equatePlan.requested().name());
            if (equate == null) {
                equate = equates.createEquate(
                    equatePlan.requested().name(),
                    equatePlan.requested().value());
            }
            for (ApplicationPlan application : equatePlan.applications()) {
                monitor.checkCancelled();
                if (skipped(application.action())) {
                    continue;
                }
                if ("replace".equals(application.action())) {
                    for (Equate old : application.replace()) {
                        removeApplicationReference(
                            old, application.site());
                    }
                }
                addApplicationReference(equate, application.site());
            }
        }

        for (CommentPlan comment : plan.comments()) {
            monitor.checkCancelled();
            if (!skipped(comment.action())) {
                commentCore.apply(program, comment.corePlan());
            }
        }

        for (BlockPlan block : plan.blocks()) {
            monitor.checkCancelled();
            if ("create".equals(block.action())) {
                blockCore.applyCreate(program, block.createPlan(), monitor);
            }
        }
    }

    private static void createNamespaces(
            Program program, List<NamespacePlan> plans) throws Exception {
        for (NamespacePlan plan : plans) {
            if (!"create".equals(plan.action())) {
                continue;
            }
            Namespace parent = program.getGlobalNamespace();
            for (String component : namespaceComponents(plan.path())) {
                Namespace existing =
                    program.getSymbolTable().getNamespace(component, parent);
                if (existing == null) {
                    existing = program.getSymbolTable().createNameSpace(
                        parent, component, SourceType.IMPORTED);
                }
                parent = existing;
            }
        }
    }

    private static void addApplicationReference(
            Equate equate, ApplicationSite site) {
        if (site.dynamicHash() == 0) {
            equate.addReference(site.address(), site.operandIndex());
        }
        else {
            equate.addReference(site.dynamicHash(), site.address());
        }
    }

    private static void removeApplicationReference(
            Equate equate, ApplicationSite site) {
        if (site.dynamicHash() == 0) {
            equate.removeReference(site.address(), site.operandIndex());
        }
        else {
            equate.removeReference(site.dynamicHash(), site.address());
        }
    }

    private ApplicationSite resolveApplication(
            Program program,
            SymbolProfileParser.ProfileEquate equate,
            SymbolProfileParser.EquateApplication application) {
        Address address = resolveMappedAddress(
            program, application.address(), "equate application address");
        Instruction instruction =
            program.getListing().getInstructionAt(address);
        if (instruction == null) {
            throw new IllegalArgumentException(
                "equate application address is not an instruction: "
                    + qualified(address));
        }
        if (application.operandIndex() >= instruction.getNumOperands()) {
            throw new IllegalArgumentException(
                "operand_index " + application.operandIndex()
                    + " is outside instruction operand range at "
                    + qualified(address));
        }
        List<Scalar> scalars = Arrays.stream(
                instruction.getOpObjects(application.operandIndex()))
            .filter(Scalar.class::isInstance)
            .map(Scalar.class::cast)
            .filter(scalar ->
                scalar.getValue() == equate.value()
                    || scalar.getUnsignedValue() == equate.value()
                    || scalar.getSignedValue() == equate.value())
            .toList();
        if (scalars.isEmpty()) {
            throw new IllegalArgumentException(
                "equate value " + equate.value()
                    + " is not a scalar in operand "
                    + application.operandIndex() + " at "
                    + qualified(address));
        }
        if (application.scalarIndex() == null) {
            if (scalars.size() > 1) {
                throw new IllegalArgumentException(
                    "operand contains multiple matching scalars at "
                        + qualified(address)
                        + "; scalar_index is required");
            }
            return new ApplicationSite(
                address, application.operandIndex(), null, 0);
        }
        if (application.scalarIndex() >= scalars.size()) {
            throw new IllegalArgumentException(
                "scalar_index " + application.scalarIndex()
                    + " is outside matching scalar occurrences at "
                    + qualified(address));
        }
        long[] hashes =
            DynamicHash.calcConstantHash(instruction, equate.value());
        if (application.scalarIndex() >= hashes.length) {
            throw new IllegalArgumentException(
                "Ghidra cannot identify scalar occurrence "
                    + application.scalarIndex() + " at "
                    + qualified(address));
        }
        return new ApplicationSite(
            address,
            application.operandIndex(),
            application.scalarIndex(),
            hashes[application.scalarIndex()]);
    }

    private static List<Equate> equatesAtSite(
            EquateTable table, ApplicationSite site) {
        if (site.dynamicHash() == 0) {
            return table.getEquates(
                    site.address(), site.operandIndex()).stream()
                .sorted(Comparator.comparing(Equate::getName))
                .toList();
        }
        List<Equate> result = new ArrayList<>();
        for (Equate equate :
                table.getEquates(site.address(), site.operandIndex())) {
            for (EquateReference reference : equate.getReferences(
                    site.address())) {
                if (reference.getOpIndex() != site.operandIndex()) {
                    continue;
                }
                if (reference.getDynamicHashValue()
                        == site.dynamicHash()) {
                    result.add(equate);
                    break;
                }
            }
        }
        result.sort(Comparator.comparing(Equate::getName));
        return List.copyOf(result);
    }

    private static String conflictAction(
            String policy,
            boolean replaceUserDefinitions,
            String conflict,
            List<Symbol> replace,
            List<String> conflicts,
            List<String> replacements) {
        if (CONFLICT_KEEP.equals(policy)) {
            conflicts.add(conflict);
            return "keep";
        }
        if (!CONFLICT_REPLACE.equals(policy)) {
            conflicts.add(conflict);
            return "conflict";
        }
        if (replace.isEmpty()) {
            conflicts.add(conflict);
            return "conflict";
        }
        boolean protectedDefinition = replace.stream().anyMatch(
            SymbolProfileService::isProtected);
        if (protectedDefinition && !replaceUserDefinitions) {
            conflicts.add(
                conflict
                    + "; replace_user_definitions=true is required");
            return "conflict";
        }
        for (Symbol symbol : replace) {
            replacements.add(
                "symbol:" + symbol.getName(true)
                    + "@" + qualified(symbol.getAddress()));
        }
        return "replace";
    }

    private static boolean isProtected(Symbol symbol) {
        return symbol.getSource() == SourceType.USER_DEFINED
            || symbol.getSource() == SourceType.IMPORTED;
    }

    private static void rejectUnresolved(Plan plan, String policy) {
        boolean namespaceConflict = plan.namespaces().stream()
            .anyMatch(item -> "conflict".equals(item.action()));
        if (CONFLICT_KEEP.equals(policy)) {
            boolean hard = namespaceConflict
                || plan.symbols().stream()
                .anyMatch(item -> "conflict".equals(item.action()))
                || plan.equates().stream()
                    .anyMatch(item -> "conflict".equals(item.action()))
                || plan.equates().stream()
                    .flatMap(item -> item.applications().stream())
                    .anyMatch(item -> "conflict".equals(item.action()))
                || plan.comments().stream()
                    .anyMatch(item -> "conflict".equals(item.action()))
                || plan.blocks().stream()
                    .anyMatch(item -> "conflict".equals(item.action()));
            if (!hard) {
                return;
            }
        }
        if (namespaceConflict || !plan.conflicts().isEmpty()) {
            throw new IllegalArgumentException(
                String.join("; ", plan.conflicts()));
        }
    }

    private Program requireProgram(String programName) {
        ServiceUtils.ProgramOrError selected =
            ServiceUtils.getProgramOrError(programProvider, programName);
        if (selected.hasError()) {
            throw new IllegalArgumentException(
                selected.error().toJson());
        }
        return selected.program();
    }

    private void revalidateProgram(
            String programName, Program expected) {
        Program current = requireProgram(programName);
        if (current != expected) {
            throw new IllegalStateException(
                "target program changed before symbol-profile planning");
        }
    }

    private Address resolveMappedAddress(
            Program program, String text, String description) {
        try {
            return commentCore.resolveAddress(program, text).address();
        }
        catch (Exception error) {
            throw new IllegalArgumentException(
                "invalid " + description + ": " + message(error),
                error);
        }
    }

    private void validateResolvedRequestIdentities(
            Program program,
            SymbolProfileParser.SymbolProfile profile) {
        Map<Address, String> primaries = new LinkedHashMap<>();
        for (SymbolProfileParser.ProfileSymbol symbol : profile.symbols()) {
            Address address = resolveMappedAddress(
                program, symbol.address(), "symbol address");
            if (symbol.primary()) {
                String prior = primaries.putIfAbsent(
                    address, symbol.qualifiedName());
                if (prior != null
                        && !prior.equals(symbol.qualifiedName())) {
                    throw new IllegalArgumentException(
                        "different requested primary symbols at "
                            + qualified(address) + ": "
                            + prior + " and " + symbol.qualifiedName());
                }
            }
        }

        Set<String> comments = new LinkedHashSet<>();
        for (SymbolProfileParser.ProfileComment comment
                : profile.comments()) {
            Address address = resolveMappedAddress(
                program, comment.address(), "comment address");
            String identity =
                qualified(address) + ":" + comment.type().wireName();
            if (!comments.add(identity)) {
                throw new IllegalArgumentException(
                    "duplicate resolved comment identity '"
                        + identity + "'");
            }
        }

        Set<ApplicationIdentity> applications =
            new LinkedHashSet<>();
        for (SymbolProfileParser.ProfileEquate equate
                : profile.equates()) {
            for (SymbolProfileParser.EquateApplication application
                    : equate.applications()) {
                ApplicationSite site =
                    resolveApplication(program, equate, application);
                ApplicationIdentity identity =
                    new ApplicationIdentity(
                        site.address(),
                        site.operandIndex(),
                        site.dynamicHash());
                if (!applications.add(identity)) {
                    throw new IllegalArgumentException(
                        "duplicate resolved equate application identity at "
                            + qualified(site.address())
                            + " operand " + site.operandIndex()
                            + scalarSuffix(site));
                }
            }
        }
    }

    private static Namespace resolveNamespace(
            Program program, String path, boolean create) {
        Namespace current = program.getGlobalNamespace();
        for (String component : namespaceComponents(path)) {
            Namespace next =
                program.getSymbolTable().getNamespace(component, current);
            if (next == null) {
                if (!create) {
                    return null;
                }
                try {
                    next = program.getSymbolTable().createNameSpace(
                        current, component, SourceType.IMPORTED);
                }
                catch (Exception error) {
                    throw new IllegalArgumentException(
                        "cannot create namespace " + path, error);
                }
            }
            current = next;
        }
        return current;
    }

    private static List<Symbol> existingSymbols(
            Program program, String name, String namespacePath) {
        Namespace namespace =
            resolveNamespace(program, namespacePath, false);
        if (namespace == null) {
            return List.of();
        }
        return List.copyOf(
            program.getSymbolTable().getSymbols(name, namespace));
    }

    private static List<String> namespaceComponents(String path) {
        if (path == null || path.isEmpty()) {
            return List.of();
        }
        return List.of(path.split("::", -1));
    }

    private static String normalizePolicy(String policy) {
        String normalized =
            policy == null ? CONFLICT_ERROR
                : policy.trim().toLowerCase(Locale.ROOT);
        if (!Set.of(
                CONFLICT_ERROR,
                CONFLICT_KEEP,
                CONFLICT_REPLACE).contains(normalized)) {
            throw new IllegalArgumentException(
                "conflict_policy must be error, keep, or replace");
        }
        return normalized;
    }

    private static MemoryBlockCore.CreateRequest blockRequest(
            SymbolProfileParser.ProfileMemoryBlock requested) {
        MemoryBlockCore.SourceData source =
            new MemoryBlockCore.SourceData(
                requested.length(),
                null,
                requested.fill(),
                requested.fill() == null
                    ? "uninitialized"
                    : String.format(
                        Locale.ROOT,
                        "fill:%02X",
                        requested.fill()));
        return new MemoryBlockCore.CreateRequest(
            requested.name(),
            requested.start(),
            source,
            requested.overlay(),
            requested.read(),
            requested.write(),
            requested.execute(),
            false,
            requested.comment());
    }

    private static boolean blockMatches(
            Program program,
            MemoryBlock block,
            SymbolProfileParser.ProfileMemoryBlock requested)
            throws Exception {
        Address requestedStart =
            ServiceUtils.parseAddress(
                program, requested.start());
        if (requestedStart == null) {
            return false;
        }
        boolean overlay =
            block.getStart().getAddressSpace().isOverlaySpace();
        boolean addressSpaceMatches =
            (overlay
                ? block.getStart().getPhysicalAddress().getAddressSpace()
                : block.getStart().getAddressSpace())
                == requestedStart.getAddressSpace();
        String comment =
            block.getComment() == null ? "" : block.getComment();
        boolean geometryMatches =
            addressSpaceMatches
                && block.getStart().getOffset()
                    == requestedStart.getOffset()
                && block.getSize() == requested.length()
                && overlay == requested.overlay();
        if (!geometryMatches
                || block.isInitialized()
                    != (requested.fill() != null)
                || block.isRead() != requested.read()
                || block.isWrite() != requested.write()
                || block.isExecute() != requested.execute()
                || block.isVolatile()
                || !comment.equals(requested.comment())) {
            return false;
        }
        if (requested.fill() != null) {
            Address cursor = block.getStart();
            for (long index = 0; index < block.getSize(); index++) {
                if ((block.getByte(cursor) & 0xff)
                        != requested.fill()) {
                    return false;
                }
                cursor = cursor.next();
            }
        }
        return true;
    }

    private static Address checkedEnd(Address start, long length) {
        try {
            return start.addNoWrap(Math.subtractExact(length, 1));
        }
        catch (AddressOverflowException | ArithmeticException error) {
            throw new IllegalArgumentException(
                "memory range overflows its address space", error);
        }
    }

    private static boolean overlaps(
            Address firstStart,
            Address firstEnd,
            Address secondStart,
            Address secondEnd) {
        return firstStart.compareTo(secondEnd) <= 0
            && firstEnd.compareTo(secondStart) >= 0;
    }

    private static CommentType commentType(
            SymbolProfileParser.CommentType type) {
        return switch (type) {
            case PLATE -> CommentType.PLATE;
            case PRE -> CommentType.PRE;
            case POST -> CommentType.POST;
            case EOL -> CommentType.EOL;
            case REPEATABLE -> CommentType.REPEATABLE;
        };
    }

    private static JsonObject invalidValidation(Exception error) {
        JsonObject result = new JsonObject();
        result.addProperty("valid", false);
        result.addProperty("program_checks_performed", false);
        result.add("profile", JsonNull.INSTANCE);
        result.add("counts", emptyCounts());
        result.add("warnings", new JsonArray());
        JsonArray conflicts = new JsonArray();
        conflicts.add(message(error));
        result.add("conflicts", conflicts);
        return result;
    }

    private static JsonObject validationResult(
            SymbolProfileParser.SymbolProfile profile,
            boolean programChecks,
            List<String> conflicts,
            List<String> warnings) {
        JsonObject result = new JsonObject();
        result.addProperty("valid", conflicts.isEmpty());
        result.addProperty("program_checks_performed", programChecks);
        result.add("profile", profileIdentity(profile));
        result.add("counts", counts(profile));
        result.add("warnings", strings(warnings));
        result.add("conflicts", strings(conflicts));
        return result;
    }

    private static JsonObject result(
            Program program,
            Plan plan,
            boolean committed,
            boolean dryRun) {
        JsonObject result = new JsonObject();
        result.add("profile", profileIdentity(plan.profile()));
        result.addProperty("program", program.getName());
        result.addProperty("dry_run", dryRun);
        result.addProperty("committed", committed);
        result.addProperty("conflict_policy", plan.policy());
        result.addProperty(
            "replace_user_definitions",
            plan.replaceUserDefinitions());
        result.addProperty(
            "create_memory_blocks",
            plan.createMemoryBlocks());
        result.add("counts", counts(plan.profile()));
        result.add("symbols", symbolJson(plan.symbols()));
        result.add("equates", equateJson(plan.equates()));
        result.add("comments", commentJson(plan.comments()));
        result.add("memory_blocks", blockJson(plan.blocks()));
        result.add(
            "kept_conflicts",
            strings(keptConflicts(plan)));
        result.add(
            "replaced_definitions",
            strings(plan.replacements()));
        result.add("idempotent", strings(idempotent(plan)));
        result.add("warnings", strings(plan.warnings()));
        return result;
    }

    private static JsonObject profileIdentity(
            SymbolProfileParser.SymbolProfile profile) {
        JsonObject result = new JsonObject();
        result.addProperty("schema_version", profile.schemaVersion());
        result.addProperty("id", profile.id());
        result.addProperty("version", profile.version());
        result.addProperty("description", profile.description());
        return result;
    }

    private static JsonObject counts(
            SymbolProfileParser.SymbolProfile profile) {
        JsonObject result = emptyCounts();
        result.addProperty("symbols", profile.symbols().size());
        result.addProperty("equates", profile.equates().size());
        result.addProperty(
            "equate_applications",
            profile.equates().stream()
                .mapToInt(item -> item.applications().size())
                .sum());
        result.addProperty("comments", profile.comments().size());
        result.addProperty(
            "memory_blocks", profile.memoryBlocks().size());
        return result;
    }

    private static JsonObject emptyCounts() {
        JsonObject result = new JsonObject();
        result.addProperty("symbols", 0);
        result.addProperty("equates", 0);
        result.addProperty("equate_applications", 0);
        result.addProperty("comments", 0);
        result.addProperty("memory_blocks", 0);
        return result;
    }

    private static JsonArray symbolJson(List<SymbolPlan> plans) {
        JsonArray result = new JsonArray();
        for (SymbolPlan plan : plans) {
            JsonObject item = new JsonObject();
            item.addProperty("address", qualified(plan.address()));
            item.addProperty("name", plan.requested().name());
            item.addProperty(
                "namespace", plan.requested().namespace());
            item.addProperty(
                "qualified_name", plan.requested().qualifiedName());
            item.addProperty(
                "kind",
                plan.requested().kind() ==
                    SymbolProfileParser.SymbolKind.ENTRY_POINT
                        ? "entry_point" : "label");
            item.addProperty("primary", plan.requested().primary());
            item.addProperty(
                "source_note", plan.requested().sourceNote());
            item.addProperty("action", plan.action());
            addNullable(item, "conflict", plan.conflict());
            result.add(item);
        }
        return result;
    }

    private static JsonArray equateJson(List<EquatePlan> plans) {
        JsonArray result = new JsonArray();
        for (EquatePlan plan : plans) {
            JsonObject item = new JsonObject();
            item.addProperty("name", plan.requested().name());
            item.addProperty("value", plan.requested().value());
            item.addProperty("description", plan.requested().description());
            item.addProperty("action", plan.action());
            addNullable(item, "conflict", plan.conflict());
            JsonArray applications = new JsonArray();
            for (ApplicationPlan application : plan.applications()) {
                JsonObject app = new JsonObject();
                app.addProperty(
                    "address",
                    qualified(application.site().address()));
                app.addProperty(
                    "operand_index",
                    application.site().operandIndex());
                if (application.site().scalarIndex() == null) {
                    app.add("scalar_index", JsonNull.INSTANCE);
                }
                else {
                    app.addProperty(
                        "scalar_index",
                        application.site().scalarIndex());
                }
                app.addProperty("action", application.action());
                addNullable(
                    app, "conflict", application.conflict());
                applications.add(app);
            }
            item.add("applications", applications);
            result.add(item);
        }
        return result;
    }

    private static JsonArray commentJson(List<CommentPlan> plans) {
        JsonArray result = new JsonArray();
        for (CommentPlan plan : plans) {
            JsonObject item = new JsonObject();
            item.addProperty(
                "address", qualified(plan.corePlan().address()));
            item.addProperty(
                "type", plan.requested().type().wireName());
            item.addProperty("text", plan.requested().text());
            item.addProperty("action", plan.action());
            addNullable(item, "conflict", plan.conflict());
            result.add(item);
        }
        return result;
    }

    private static JsonArray blockJson(List<BlockPlan> plans) {
        JsonArray result = new JsonArray();
        for (BlockPlan plan : plans) {
            JsonObject item = new JsonObject();
            item.addProperty("name", plan.requested().name());
            item.addProperty("start", plan.requested().start());
            item.addProperty("length", plan.requested().length());
            if (plan.requested().fill() == null) {
                item.add("fill", JsonNull.INSTANCE);
            }
            else {
                item.addProperty("fill", plan.requested().fill());
            }
            item.addProperty("overlay", plan.requested().overlay());
            item.addProperty("read", plan.requested().read());
            item.addProperty("write", plan.requested().write());
            item.addProperty("execute", plan.requested().execute());
            item.addProperty("comment", plan.requested().comment());
            item.addProperty("action", plan.action());
            addNullable(item, "conflict", plan.conflict());
            result.add(item);
        }
        return result;
    }

    private static List<String> keptConflicts(Plan plan) {
        List<String> result = new ArrayList<>();
        for (SymbolPlan item : plan.symbols()) {
            addKept(result, item.action(), item.conflict());
        }
        for (EquatePlan item : plan.equates()) {
            addKept(result, item.action(), item.conflict());
            for (ApplicationPlan application : item.applications()) {
                addKept(
                    result,
                    application.action(),
                    application.conflict());
            }
        }
        for (CommentPlan item : plan.comments()) {
            addKept(result, item.action(), item.conflict());
        }
        for (BlockPlan item : plan.blocks()) {
            addKept(result, item.action(), item.conflict());
        }
        return List.copyOf(result);
    }

    private static void addKept(
            List<String> result, String action, String conflict) {
        if ("keep".equals(action) && conflict != null) {
            result.add(conflict);
        }
    }

    private static List<String> idempotent(Plan plan) {
        List<String> result = new ArrayList<>();
        for (SymbolPlan item : plan.symbols()) {
            if ("idempotent".equals(item.action())) {
                result.add(
                    "symbol:" + item.requested().qualifiedName());
            }
        }
        for (EquatePlan item : plan.equates()) {
            if ("idempotent".equals(item.action())) {
                result.add("equate:" + item.requested().name());
            }
            for (ApplicationPlan application : item.applications()) {
                if ("idempotent".equals(application.action())) {
                    result.add(
                        "equate_application:"
                            + qualified(application.site().address())
                            + ":" + application.site().operandIndex()
                            + scalarSuffix(application.site()));
                }
            }
        }
        for (CommentPlan item : plan.comments()) {
            if ("idempotent".equals(item.action())) {
                result.add(
                    "comment:" + qualified(item.corePlan().address())
                        + ":" + item.requested().type().wireName());
            }
        }
        for (BlockPlan item : plan.blocks()) {
            if ("idempotent".equals(item.action())) {
                result.add(
                    "memory_block:" + item.requested().name());
            }
        }
        return List.copyOf(result);
    }

    private static List<String> schemaWarnings(
            SymbolProfileParser.SymbolProfile profile) {
        List<String> result = new ArrayList<>();
        for (SymbolProfileParser.ProfileEquate equate : profile.equates()) {
            if (!equate.description().isEmpty()) {
                result.add(
                    "equate description for '" + equate.name()
                        + "' is retained as profile metadata; "
                        + "Ghidra equates have no description field");
            }
        }
        return List.copyOf(result);
    }

    private static JsonArray strings(List<String> values) {
        JsonArray result = new JsonArray();
        values.forEach(result::add);
        return result;
    }

    private static void addNullable(
            JsonObject object, String name, String value) {
        object.add(
            name,
            value == null
                ? JsonNull.INSTANCE
                : new JsonPrimitive(value));
    }

    private static boolean skipped(String action) {
        return Set.of(
            "keep", "conflict", "disabled", "idempotent")
            .contains(action);
    }

    private static String scalarSuffix(ApplicationSite site) {
        return site.scalarIndex() == null
            ? "" : ":scalar:" + site.scalarIndex();
    }

    private static String qualified(Address address) {
        return address.getAddressSpace().getName()
            + ":" + address.toString(false);
    }

    private static String message(Throwable error) {
        String message = error.getMessage();
        return message == null || message.isBlank()
            ? error.toString() : message;
    }

    private record Plan(
        SymbolProfileParser.SymbolProfile profile,
        String policy,
        boolean replaceUserDefinitions,
        boolean createMemoryBlocks,
        List<NamespacePlan> namespaces,
        List<SymbolPlan> symbols,
        List<EquatePlan> equates,
        List<CommentPlan> comments,
        List<BlockPlan> blocks,
        List<String> conflicts,
        List<String> warnings,
        List<String> replacements) {
    }

    private record NamespacePlan(String path, String action) {
    }

    private record SymbolPlan(
        SymbolProfileParser.ProfileSymbol requested,
        Address address,
        List<Symbol> replace,
        String action,
        String conflict) {
    }

    private record EquatePlan(
        SymbolProfileParser.ProfileEquate requested,
        String action,
        String conflict,
        List<ApplicationPlan> applications) {
    }

    private record ApplicationPlan(
        ApplicationSite site,
        List<Equate> replace,
        String action,
        String conflict) {
    }

    private record ApplicationSite(
        Address address,
        int operandIndex,
        Integer scalarIndex,
        long dynamicHash) {
    }

    private record ApplicationIdentity(
        Address address, int operandIndex, long dynamicHash) {
    }

    private record CommentPlan(
        SymbolProfileParser.ProfileComment requested,
        AddressCommentCore.Plan corePlan,
        String action,
        String conflict) {
    }

    private record BlockPlan(
        SymbolProfileParser.ProfileMemoryBlock requested,
        MemoryBlockCore.CreatePlan createPlan,
        String action,
        String conflict) {
    }

    private record RequestedRange(
        String name, Address start, Address end) {
    }
}
