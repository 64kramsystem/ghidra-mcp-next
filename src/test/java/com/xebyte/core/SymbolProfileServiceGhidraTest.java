package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.xebyte.headless.DirectThreadingStrategy;
import com.xebyte.headless.HeadlessProgramProvider;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitorAdapter;
import java.io.File;
import java.util.concurrent.Callable;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class SymbolProfileServiceGhidraTest {
    private ProgramBuilder builder;
    private ProgramDB program;
    private SymbolProfileService service;

    @BeforeClass
    public static void initializeGhidraOrSkip() throws Exception {
        String installDir = System.getProperty("ghidra.test.install.dir");
        assumeTrue(installDir != null && !installDir.isBlank());
        if (!Application.isInitialized()) {
            ApplicationConfiguration configuration =
                new ApplicationConfiguration();
            configuration.setInitializeLogging(false);
            Application.initializeApplication(
                new GhidraApplicationLayout(new File(installDir)),
                configuration);
        }
    }

    @Before
    public void setUp() throws Exception {
        builder = new ProgramBuilder(
            "symbol-profile-6502",
            "6502:LE:16:default",
            "default",
            this);
        program = builder.getProgram();
        builder.createMemory("ram", "0x1000", 0x100);
        builder.setBytes("0x1000", "a9 80 60");
        builder.disassemble("0x1000", 3);
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        service = new SymbolProfileService(
            provider, new DirectThreadingStrategy());
    }

    @After
    public void tearDown() {
        if (builder != null) {
            builder.dispose();
        }
    }

    @Test
    public void schemaOnlyValidationDoesNotResolveProgramAddresses() {
        JsonObject result = ok(service.validateSymbolProfile(
            profileWithAddress("missing:ffff"), null));

        assertTrue(result.get("valid").getAsBoolean());
        assertFalse(
            result.get("program_checks_performed").getAsBoolean());
        assertEquals(1,
            result.getAsJsonObject("counts").get("symbols").getAsInt());
    }

    @Test
    public void programValidationReportsUnmappedAddressesWithoutMutation() {
        JsonObject result = ok(service.validateSymbolProfile(
            profileWithAddress("0xffff"),
            program.getName()));

        assertFalse(result.get("valid").getAsBoolean());
        assertTrue(
            result.get("program_checks_performed").getAsBoolean());
        assertFalse(result.getAsJsonArray("conflicts").isEmpty());
        assertEquals(0, program.getSymbolTable().getNumSymbols());
    }

    @Test
    public void dryRunAndCommitApplyEveryProfileObjectAtomically()
            throws Exception {
        Object profile = completeProfile();

        JsonObject preview = ok(service.applySymbolProfile(
            profile, true, "error", false, true, program.getName()));
        assertFalse(preview.get("committed").getAsBoolean());
        assertNull(program.getSymbolTable().getGlobalSymbol(
            "START", builder.addr("0x1000")));
        assertNull(program.getMemory().getBlock("profile-data"));

        JsonObject committed = ok(service.applySymbolProfile(
            profile, false, "error", false, true, program.getName()));
        assertTrue(committed.get("committed").getAsBoolean());
        Namespace machine = program.getSymbolTable().getNamespace(
            "Machine", program.getGlobalNamespace());
        assertNotNull(machine);
        Namespace rom = program.getSymbolTable().getNamespace(
            "ROM", machine);
        assertNotNull(rom);
        assertNotNull(program.getSymbolTable().getSymbol(
            "START", builder.addr("0x1000"), rom));
        assertTrue(program.getSymbolTable().isExternalEntryPoint(
            builder.addr("0x1002")));
        assertEquals(
            "entry",
            program.getListing().getComment(
                CommentType.PLATE, builder.addr("0x1000")));
        Equate equate = program.getEquateTable().getEquate(
            builder.addr("0x1000"), 0, 0x80);
        assertNotNull(equate);
        assertEquals("HIGH_BIT", equate.getName());
        assertEquals(
            (byte) 0xaa,
            program.getMemory().getByte(builder.addr("0x3000")));

        JsonObject repeated = ok(service.applySymbolProfile(
            profile, false, "error", false, true, program.getName()));
        assertTrue(repeated.get("committed").getAsBoolean());
        assertFalse(repeated.getAsJsonArray("idempotent").isEmpty());
    }

    @Test
    public void userDefinedReplacementRequiresSecondAuthorization()
            throws Exception {
        int transaction = program.startTransaction("seed user label");
        try {
            Namespace machine = program.getSymbolTable().createNameSpace(
                program.getGlobalNamespace(),
                "Machine",
                SourceType.USER_DEFINED);
            Namespace rom = program.getSymbolTable().createNameSpace(
                machine, "ROM", SourceType.USER_DEFINED);
            program.getSymbolTable().createLabel(
                builder.addr("0x1010"),
                "START",
                rom,
                SourceType.USER_DEFINED);
        }
        finally {
            program.endTransaction(transaction, true);
        }

        Response refused = service.applySymbolProfile(
            profileWithNamespacedStart(),
            false,
            "replace",
            false,
            false,
            program.getName());
        assertTrue(refused.toJson(), refused instanceof Response.Err);
        assertTrue(refused.toJson().contains("replace_user_definitions"));
        assertNotNull(program.getSymbolTable().getSymbol(
            "START",
            builder.addr("0x1010"),
            program.getSymbolTable().getNamespace(
                "ROM",
                program.getSymbolTable().getNamespace(
                    "Machine", program.getGlobalNamespace()))));

        JsonObject replaced = ok(service.applySymbolProfile(
            profileWithNamespacedStart(),
            false,
            "replace",
            true,
            false,
            program.getName()));
        assertFalse(
            replaced.getAsJsonArray("replaced_definitions").isEmpty());
    }

    @Test
    public void keepRecordsConflictsAndPreservesExistingDefinitions()
            throws Exception {
        builder.createComment("0x1000", "keep me", CommentType.PLATE);

        JsonObject result = ok(service.applySymbolProfile(
            commentProfile("replace me"),
            false,
            "keep",
            false,
            false,
            program.getName()));

        assertEquals(
            "keep me",
            program.getListing().getComment(
                CommentType.PLATE, builder.addr("0x1000")));
        assertEquals(1, result.getAsJsonArray("kept_conflicts").size());
    }

    @Test
    public void completePreflightRejectsLateFailureBeforeAnyMutation() {
        Object profile = JsonParser.parseString("""
            {"schema_version":1,"id":"preflight","version":"1",
             "comments":[
               {"address":"0x1000","type":"plate","text":"must rollback"}],
             "symbols":[
               {"address":"0xffff","name":"UNMAPPED"}]}
            """);

        Response response = service.applySymbolProfile(
            profile, false, "error", false, false, program.getName());

        assertTrue(response.toJson(), response instanceof Response.Err);
        assertNull(program.getListing().getComment(
            CommentType.PLATE, builder.addr("0x1000")));
        assertNull(program.getSymbolTable().getGlobalSymbol(
            "UNMAPPED", builder.addr("0xffff")));
    }

    @Test
    public void cancellationAfterFirstMutationRollsBackWholeTransaction() {
        FailingMonitor failingMonitor = new FailingMonitor(3);
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        SymbolProfileService cancelService = new SymbolProfileService(
            provider,
            new DirectThreadingStrategy(),
            new SymbolProfileParser(),
            new AddressCommentCore(),
            new MemoryBlockCore(),
            failingMonitor);
        Object profile = JsonParser.parseString("""
            {"schema_version":1,"id":"rollback","version":"1",
             "symbols":[
               {"address":"0x1000","name":"FIRST",
                "namespace":"Rollback"},
               {"address":"0x1001","name":"SECOND",
                "namespace":"Rollback"}]}
            """);

        Response response = cancelService.applySymbolProfile(
            profile, false, "error", false, false, program.getName());

        assertTrue(response.toJson(), response instanceof Response.Err);
        assertNull(program.getSymbolTable().getNamespace(
            "Rollback", program.getGlobalNamespace()));
        assertNull(program.getSymbolTable().getGlobalSymbol(
            "FIRST", builder.addr("0x1000")));
        assertNull(program.getSymbolTable().getGlobalSymbol(
            "SECOND", builder.addr("0x1001")));
    }

    @Test
    public void entryPointMoveIsNeverImplicitEvenWithReplaceAuthority()
            throws Exception {
        int transaction = program.startTransaction("seed entry point");
        try {
            program.getSymbolTable().createLabel(
                builder.addr("0x1010"),
                "START",
                SourceType.USER_DEFINED);
            program.getSymbolTable().addExternalEntryPoint(
                builder.addr("0x1010"));
        }
        finally {
            program.endTransaction(transaction, true);
        }
        Object profile = JsonParser.parseString("""
            {"schema_version":1,"id":"entry-move","version":"1",
             "symbols":[{
               "address":"0x1000","name":"START",
               "kind":"entry_point"}]}
            """);

        Response response = service.applySymbolProfile(
            profile, false, "replace", true, false, program.getName());

        assertTrue(response.toJson(), response instanceof Response.Err);
        assertTrue(response.toJson().contains("move"));
        assertTrue(program.getSymbolTable().isExternalEntryPoint(
            builder.addr("0x1010")));
        assertFalse(program.getSymbolTable().isExternalEntryPoint(
            builder.addr("0x1000")));
    }

    @Test
    public void overlappingBlockReplacementIsNeverImplicit() {
        Object profile = JsonParser.parseString("""
            {"schema_version":1,"id":"overlap","version":"1",
             "memory_blocks":[{
               "name":"overlap",
               "start":"0x1080",
               "length":16,
               "fill":0}]}
            """);

        Response response = service.applySymbolProfile(
            profile, false, "replace", true, true, program.getName());

        assertTrue(response.toJson(), response instanceof Response.Err);
        assertTrue(response.toJson().contains("overlap"));
        assertNull(program.getMemory().getBlock("overlap"));
    }

    @Test
    public void optionalBlocksAreValidatedButNotCreatedByDefault() {
        Object profile = JsonParser.parseString("""
            {"schema_version":1,"id":"blocks-disabled","version":"1",
             "memory_blocks":[{
               "name":"optional",
               "start":"0x3000",
               "length":16,
               "fill":0}]}
            """);

        JsonObject result = ok(service.applySymbolProfile(
            profile, false, "error", false, false, program.getName()));

        assertTrue(result.get("committed").getAsBoolean());
        assertEquals(
            "disabled",
            result.getAsJsonArray("memory_blocks")
                .get(0).getAsJsonObject()
                .get("action").getAsString());
        assertNull(program.getMemory().getBlock("optional"));
    }

    @Test
    public void disabledC64TemplateDoesNotConflictWithFullRam()
            throws Exception {
        builder.dispose();
        builder = new ProgramBuilder(
            "symbol-profile-c64",
            "6502:LE:16:default",
            "default",
            this);
        program = builder.getProgram();
        builder.createMemory("full-ram", "0x0000", 0x10000);
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        service = new SymbolProfileService(
            provider, new DirectThreadingStrategy());
        Object profile = JsonParser.parseString("""
            {"schema_version":1,"id":"c64-shaped","version":"1",
             "symbols":[
               {"address":"0xd011","name":"VIC_CONTROL_1"},
               {"address":"0xffd5","name":"KERNAL_LOAD"}],
             "memory_blocks":[{
               "name":"vic-register-template",
               "start":"0xd000",
               "length":1024,
               "fill":0}]}
            """);

        JsonObject applied = ok(service.applySymbolProfile(
            profile, false, "error", false, false, program.getName()));

        assertTrue(applied.get("committed").getAsBoolean());
        assertEquals(
            "disabled",
            applied.getAsJsonArray("memory_blocks")
                .get(0).getAsJsonObject()
                .get("action").getAsString());
        assertNotNull(program.getSymbolTable().getGlobalSymbol(
            "VIC_CONTROL_1", builder.addr("0xd011")));
        assertNotNull(program.getSymbolTable().getGlobalSymbol(
            "KERNAL_LOAD", builder.addr("0xffd5")));
        assertNull(program.getMemory().getBlock(
            "vic-register-template"));

        JsonObject validated = ok(service.validateSymbolProfile(
            profile, program.getName()));
        assertFalse(validated.get("valid").getAsBoolean());
        assertTrue(validated.toString().contains("overlap"));

        Response enabled = service.applySymbolProfile(
            profile, false, "error", false, true, program.getName());
        assertTrue(enabled.toJson(), enabled instanceof Response.Err);
        assertTrue(enabled.toJson().contains("overlap"));
        assertNull(program.getMemory().getBlock(
            "vic-register-template"));
    }

    @Test
    public void ordinaryBlockIdentityIncludesItsAddressSpace()
            throws Exception {
        MemoryBlock other =
            builder.createMemory("same-name", "OTHER:1000", 0x10);
        int transaction =
            program.startTransaction("normalize OTHER block");
        try {
            other.setPermissions(true, false, false);
            other.setVolatile(false);
            other.setComment("");
        }
        finally {
            program.endTransaction(transaction, true);
        }
        Object profile = JsonParser.parseString("""
            {"schema_version":1,"id":"space-identity","version":"1",
             "memory_blocks":[{
               "name":"same-name",
               "start":"0x1000",
               "length":16,
               "fill":0}]}
            """);

        Response response = service.applySymbolProfile(
            profile, false, "error", false, true, program.getName());

        assertTrue(response.toJson(), response instanceof Response.Err);
        assertTrue(response.toJson().contains(
            "already used by a different block"));
        assertEquals(
            "OTHER",
            program.getMemory().getBlock("same-name")
                .getStart().getAddressSpace().getName());
    }

    @Test
    public void keptEquateDefinitionKeepsEveryChildApplication()
            throws Exception {
        int transaction = program.startTransaction("seed parent equate");
        try {
            program.getEquateTable().createEquate("MASK", 1);
        }
        finally {
            program.endTransaction(transaction, true);
        }
        Object profile = JsonParser.parseString("""
            {"schema_version":1,"id":"keep-parent-equate","version":"1",
             "equates":[{
               "name":"MASK",
               "value":128,
               "applications":[{
                 "address":"0x1000",
                 "operand_index":0,
                 "scalar_index":0}]}]}
            """);

        JsonObject result = ok(service.applySymbolProfile(
            profile, false, "keep", false, false, program.getName()));

        JsonObject equate =
            result.getAsJsonArray("equates").get(0).getAsJsonObject();
        JsonObject application =
            equate.getAsJsonArray("applications")
                .get(0).getAsJsonObject();
        assertEquals("keep", equate.get("action").getAsString());
        assertEquals("keep", application.get("action").getAsString());
        assertNotNull(application.get("conflict"));
        assertEquals(
            1, program.getEquateTable().getEquate("MASK").getValue());
        assertNull(program.getEquateTable().getEquate(
            builder.addr("0x1000"), 0, 0x80));
    }

    @Test
    public void invalidEquateOccurrenceFailsBeforeCreatingDefinition() {
        Object profile = JsonParser.parseString("""
            {"schema_version":1,"id":"bad-equate","version":"1",
             "equates":[{
               "name":"NOT_PRESENT",
               "value":127,
               "applications":[{
                 "address":"0x1000",
                 "operand_index":0,
                 "scalar_index":0}]}]}
            """);

        Response response = service.applySymbolProfile(
            profile, false, "error", false, false, program.getName());

        assertTrue(response.toJson(), response instanceof Response.Err);
        assertNull(program.getEquateTable().getEquate("NOT_PRESENT"));
    }

    @Test
    public void namespaceCollisionsAreHardConflictsUnderKeep()
            throws Exception {
        int transaction = program.startTransaction("seed namespace collision");
        try {
            program.getSymbolTable().createLabel(
                builder.addr("0x1010"),
                "Machine",
                SourceType.USER_DEFINED);
        }
        finally {
            program.endTransaction(transaction, true);
        }
        Object profile = JsonParser.parseString("""
            {"schema_version":1,"id":"namespace-conflict","version":"1",
             "symbols":[{
               "address":"0x1000","name":"START",
               "namespace":"Machine::ROM"}]}
            """);

        Response response = service.applySymbolProfile(
            profile, false, "keep", false, false, program.getName());

        assertTrue(response.toJson(), response instanceof Response.Err);
        assertTrue(response.toJson().contains("namespace"));
        assertNull(program.getSymbolTable().getNamespace(
            "Machine", program.getGlobalNamespace()));
        assertNull(program.getSymbolTable().getGlobalSymbol(
            "START", builder.addr("0x1000")));
    }

    @Test
    public void resolvedDuplicateCommentsAreRejectedBeforeMutation() {
        Object profile = JsonParser.parseString("""
            {"schema_version":1,"id":"resolved-duplicates","version":"1",
             "comments":[
               {"address":"0x1000","type":"plate","text":"first"},
               {"address":"00001000","type":"plate","text":"second"}]}
            """);

        Response response = service.applySymbolProfile(
            profile, false, "keep", false, false, program.getName());

        assertTrue(response.toJson(), response instanceof Response.Err);
        assertTrue(response.toJson().contains("duplicate resolved comment"));
        assertNull(program.getListing().getComment(
            CommentType.PLATE, builder.addr("0x1000")));
    }

    @Test
    public void differentRequestedPrimariesAtOneAddressAreRejected() {
        Object profile = JsonParser.parseString("""
            {"schema_version":1,"id":"primary-collision","version":"1",
             "symbols":[
               {"address":"0x1000","name":"ONE","primary":true},
               {"address":"00001000","name":"TWO","primary":true}]}
            """);

        Response response = service.applySymbolProfile(
            profile, false, "keep", false, false, program.getName());

        assertTrue(response.toJson(), response instanceof Response.Err);
        assertTrue(response.toJson().contains("primary"));
        assertNull(program.getSymbolTable().getGlobalSymbol(
            "ONE", builder.addr("0x1000")));
        assertNull(program.getSymbolTable().getGlobalSymbol(
            "TWO", builder.addr("0x1000")));
    }

    @Test
    public void unqualifiedOverlayAddressesAreRejectedAsAmbiguous()
            throws Exception {
        builder.createMemory("bank-base", "0x2000", 0x20);
        builder.createOverlayMemory("bank", "0x2000", 0x20);
        Object ambiguous = JsonParser.parseString("""
            {"schema_version":1,"id":"ambiguous","version":"1",
             "symbols":[{"address":"0x2000","name":"AMBIGUOUS"}]}
            """);

        Response refused = service.applySymbolProfile(
            ambiguous, false, "error", false, false, program.getName());

        assertTrue(refused.toJson(), refused instanceof Response.Err);
        assertTrue(refused.toJson().toLowerCase().contains("ambiguous"));

        Object qualified = JsonParser.parseString("""
            {"schema_version":1,"id":"qualified","version":"1",
             "symbols":[{"address":"bank:2000","name":"BANK_START"}]}
            """);
        JsonObject applied = ok(service.applySymbolProfile(
            qualified, false, "error", false, false, program.getName()));
        assertTrue(applied.get("committed").getAsBoolean());
        assertNotNull(program.getSymbolTable().getGlobalSymbol(
            "BANK_START", builder.addr("bank::2000")));
    }

    @Test
    public void targetProgramIsRevalidatedInsideWriteSerialization() {
        SwitchableProvider provider = new SwitchableProvider(program);
        SymbolProfileService switchingService =
            new SymbolProfileService(
                provider,
                new SwitchingProgramStrategy(provider));
        Object profile = JsonParser.parseString("""
            {"schema_version":1,"id":"program-switch","version":"1",
             "symbols":[{"address":"0x1000","name":"MUST_NOT_APPLY"}]}
            """);

        Response response = switchingService.applySymbolProfile(
            profile, false, "error", false, false, "");

        assertTrue(response.toJson(), response instanceof Response.Err);
        assertTrue(response.toJson().contains("program"));
        assertNull(program.getSymbolTable().getGlobalSymbol(
            "MUST_NOT_APPLY", builder.addr("0x1000")));
    }

    @Test
    public void analysisLabelsCanBeReplacedWithoutUserAuthorization()
            throws Exception {
        int transaction = program.startTransaction("seed analysis label");
        try {
            program.getSymbolTable().createLabel(
                builder.addr("0x1010"),
                "ANALYZED",
                SourceType.ANALYSIS);
        }
        finally {
            program.endTransaction(transaction, true);
        }
        Object profile = JsonParser.parseString("""
            {"schema_version":1,"id":"analysis-replace","version":"1",
             "symbols":[{
               "address":"0x1000","name":"ANALYZED"}]}
            """);

        JsonObject result = ok(service.applySymbolProfile(
            profile, false, "replace", false, false, program.getName()));

        assertEquals(
            1, result.getAsJsonArray("replaced_definitions").size());
        assertNull(program.getSymbolTable().getGlobalSymbol(
            "ANALYZED", builder.addr("0x1010")));
        assertNotNull(program.getSymbolTable().getGlobalSymbol(
            "ANALYZED", builder.addr("0x1000")));
    }

    @Test
    public void equateApplicationReplacementRequiresAuthorization()
            throws Exception {
        int transaction = program.startTransaction("seed equate");
        try {
            Equate old = program.getEquateTable().createEquate(
                "OLD_MASK", 0x80);
            old.addReference(builder.addr("0x1000"), 0);
        }
        finally {
            program.endTransaction(transaction, true);
        }
        Object profile = JsonParser.parseString("""
            {"schema_version":1,"id":"equate-replace","version":"1",
             "equates":[{
               "name":"NEW_MASK",
               "value":128,
               "applications":[{
                 "address":"0x1000",
                 "operand_index":0}]}]}
            """);

        Response refused = service.applySymbolProfile(
            profile, false, "replace", false, false, program.getName());
        assertTrue(refused.toJson(), refused instanceof Response.Err);
        assertTrue(refused.toJson().contains(
            "replace_user_definitions"));
        assertEquals(
            "OLD_MASK",
            program.getEquateTable()
                .getEquate(builder.addr("0x1000"), 0, 0x80)
                .getName());
        assertNull(program.getEquateTable().getEquate("NEW_MASK"));

        JsonObject result = ok(service.applySymbolProfile(
            profile, false, "replace", true, false, program.getName()));
        assertFalse(
            result.getAsJsonArray("replaced_definitions").isEmpty());
        assertEquals(
            "NEW_MASK",
            program.getEquateTable()
                .getEquate(builder.addr("0x1000"), 0, 0x80)
                .getName());
        assertNotNull(program.getEquateTable().getEquate("OLD_MASK"));
    }

    @Test
    public void repeatedPreviewsAreByteForByteDeterministic() {
        Response first = service.applySymbolProfile(
            completeProfile(), true, "error", false, true,
            program.getName());
        Response second = service.applySymbolProfile(
            completeProfile(), true, "error", false, true,
            program.getName());

        assertTrue(first.toJson(), first instanceof Response.Ok);
        assertEquals(first.toJson(), second.toJson());
    }

    @Test
    public void validationReturnsStructuredSchemaErrors() {
        JsonObject result = ok(service.validateSymbolProfile(
            JsonParser.parseString("""
                {"schema_version":1,"id":"x","version":"1",
                 "unknown":true}
                """),
            null));

        assertFalse(result.get("valid").getAsBoolean());
        assertFalse(result.get("program_checks_performed").getAsBoolean());
        assertFalse(result.getAsJsonArray("conflicts").isEmpty());
        assertTrue(result.get("profile").isJsonNull());
    }

    private static Object profileWithAddress(String address) {
        return JsonParser.parseString("""
            {"schema_version":1,"id":"test","version":"1",
             "symbols":[{"address":"%s","name":"START"}]}
            """.formatted(address));
    }

    private static Object profileWithNamespacedStart() {
        return JsonParser.parseString("""
            {"schema_version":1,"id":"test","version":"1",
             "symbols":[{"address":"0x1000","name":"START",
               "namespace":"Machine::ROM","primary":true}]}
            """);
    }

    private static Object commentProfile(String text) {
        return JsonParser.parseString("""
            {"schema_version":1,"id":"test","version":"1",
             "comments":[{"address":"0x1000","type":"plate","text":"%s"}]}
            """.formatted(text));
    }

    private static Object completeProfile() {
        return JsonParser.parseString("""
            {
              "schema_version":1,
              "id":"test.complete",
              "version":"1",
              "symbols":[
                {"address":"0x1000","name":"START",
                 "namespace":"Machine::ROM","primary":true},
                {"address":"0x1002","name":"RETURN",
                 "namespace":"Machine::ROM","kind":"entry_point"}
              ],
              "equates":[{
                "name":"HIGH_BIT",
                "value":128,
                "applications":[{
                  "address":"0x1000",
                  "operand_index":0,
                  "scalar_index":0
                }]
              }],
              "comments":[{
                "address":"0x1000",
                "type":"plate",
                "text":"entry"
              }],
              "memory_blocks":[{
                "name":"profile-data",
                "start":"0x3000",
                "length":16,
                "fill":170,
                "read":true,
                "write":true
              }]
            }
            """);
    }

    private static JsonObject ok(Response response) {
        assertTrue(response.toJson(), response instanceof Response.Ok);
        return JsonParser.parseString(response.toJson()).getAsJsonObject();
    }

    private static final class FailingMonitor
            extends TaskMonitorAdapter {
        private final int failureCheck;
        private int checks;

        FailingMonitor(int failureCheck) {
            this.failureCheck = failureCheck;
        }

        @Override
        public void checkCancelled() throws CancelledException {
            checks++;
            if (checks >= failureCheck) {
                throw new CancelledException("injected cancellation");
            }
        }
    }

    private static final class SwitchingProgramStrategy
            implements ThreadingStrategy {
        private final SwitchableProvider provider;
        private final DirectThreadingStrategy delegate =
            new DirectThreadingStrategy();

        SwitchingProgramStrategy(SwitchableProvider provider) {
            this.provider = provider;
        }

        public <T> T executeRead(Callable<T> action)
                throws Exception {
            provider.clear();
            return delegate.executeRead(action);
        }

        public <T> T executeWrite(
                ghidra.program.model.listing.Program target,
                String description,
                Callable<T> action) throws Exception {
            provider.clear();
            return delegate.executeWrite(target, description, action);
        }

        public boolean isHeadless() {
            return true;
        }
    }

    private static final class SwitchableProvider
            implements ProgramProvider {
        private Program current;

        SwitchableProvider(Program program) {
            current = program;
        }

        public Program getCurrentProgram() {
            return current;
        }

        public Program getProgram(String name) {
            if (current == null) {
                return null;
            }
            return name == null || name.isBlank()
                || current.getName().equals(name)
                    ? current : null;
        }

        public Program[] getAllOpenPrograms() {
            return current == null
                ? new Program[0] : new Program[] { current };
        }

        public void setCurrentProgram(Program program) {
            current = program;
        }

        void clear() {
            current = null;
        }
    }
}
