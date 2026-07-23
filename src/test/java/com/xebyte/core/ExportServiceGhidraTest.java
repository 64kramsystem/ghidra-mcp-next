package com.xebyte.core;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import com.xebyte.headless.HeadlessProgramProvider;

import ghidra.GhidraApplicationLayout;
import ghidra.app.util.exporter.AsciiExporter;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.util.task.TaskMonitor;

public class ExportServiceGhidraTest {

    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();

    private ProgramBuilder builder;
    private ProgramDB program;
    private HeadlessProgramProvider provider;
    private SecurityConfig security;

    @BeforeClass
    public static void initializeGhidra() throws Exception {
        String installDir = System.getenv("GHIDRA_INSTALL_DIR");
        assumeTrue("GHIDRA_INSTALL_DIR is required for real Ghidra tests",
            installDir != null && !installDir.isBlank());
        if (!Application.isInitialized()) {
            ApplicationConfiguration configuration = new ApplicationConfiguration();
            configuration.setInitializeLogging(false);
            Application.initializeApplication(new GhidraApplicationLayout(new File(installDir)),
                configuration);
        }
    }

    @Before
    public void setUp() throws Exception {
        builder = new ProgramBuilder("ascii-export-fixture", ProgramBuilder._X64, "gcc", this);
        program = builder.getProgram();
        builder.createMemory(".text", "0x1000", 0x40);
        builder.setBytes("0x1000", "55 48 89 e5 b8 01 00 00 00 5d c3");
        builder.disassemble("0x1000", 0xb);
        builder.createFunction("0x1000");

        provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        security = mock(SecurityConfig.class);
        when(security.resolveWithinFileRoot(anyString())).thenAnswer(invocation ->
            new File(invocation.getArgument(0, String.class)).getCanonicalFile().toPath());
    }

    @After
    public void tearDown() {
        if (builder != null) {
            builder.dispose();
        }
    }

    @Test
    public void wholeAndBoundedBytesEqualDirectAsciiExporter() throws Exception {
        Path directory = temporaryFolder.newFolder("equality").toPath();
        ExportService service = new ExportService(provider, security);

        Path whole = directory.resolve("whole.asm");
        Response wholeResponse = service.exportAsciiListing(
            whole.toString(), null, null, false, "");
        assertTrue(wholeResponse.toJson(), wholeResponse instanceof Response.Ok);
        assertArrayEquals(directExport(directory.resolve("direct-whole.asm"),
            program.getMemory()), Files.readAllBytes(whole));

        Path bounded = directory.resolve("bounded.asm");
        AddressSet set = new AddressSet(builder.addr("0x1000"), builder.addr("0x100a"));
        Response boundedResponse = service.exportAsciiListing(
            bounded.toString(), "0x1000", "0x100a", false, "");
        assertTrue(boundedResponse.toJson(), boundedResponse instanceof Response.Ok);
        assertArrayEquals(directExport(directory.resolve("direct-bounded.asm"), set),
            Files.readAllBytes(bounded));
    }

    @Test
    public void nativeExporterReportsAddressRestrictionCapability() {
        ExportService.AsciiExportRunner runner = new ExportService.AsciiExportRunner();
        assertEquals(new AsciiExporter().supportsAddressRestrictedExport(),
            runner.supportsAddressRestrictedExport());
    }

    private byte[] directExport(Path destination, AddressSetView set) throws Exception {
        AsciiExporter exporter = new AsciiExporter();
        assertTrue(exporter.export(destination.toFile(), program, set, TaskMonitor.DUMMY));
        return Files.readAllBytes(destination);
    }
}
