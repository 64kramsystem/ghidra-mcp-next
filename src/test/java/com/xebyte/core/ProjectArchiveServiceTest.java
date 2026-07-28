package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import com.xebyte.headless.DirectThreadingStrategy;

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectLocator;

public class ProjectArchiveServiceTest {

    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();

    private Project project;
    private ProjectLocator locator;
    private SecurityConfig security;

    @Before
    public void setUp() throws Exception {
        project = mock(Project.class);
        locator = mock(ProjectLocator.class);
        security = mock(SecurityConfig.class);

        when(project.getName()).thenReturn("fixture");
        when(project.getProjectLocator()).thenReturn(locator);
        when(project.getOpenData()).thenReturn(List.of());
        when(security.resolveWithinFileRoot(anyString())).thenAnswer(invocation ->
            new File(invocation.getArgument(0, String.class)).getCanonicalFile().toPath());
    }

    @Test
    public void rejectsRelativePathBeforeResolvingOrWriting() {
        AtomicBoolean writerCalled = new AtomicBoolean();
        ProjectArchiveService service = service((ignoredProject, ignoredDestination, monitor) ->
            writerCalled.set(true));

        Response response = service.exportProjectArchive("fixture.gar");

        assertErrorContains(response, "must be absolute");
        verify(security, never()).resolveWithinFileRoot(anyString());
        assertFalse(writerCalled.get());
    }

    @Test
    public void rejectsMissingActiveProject() throws Exception {
        Path destination = temporaryFolder.getRoot().toPath().resolve("fixture.gar");
        AtomicBoolean writerCalled = new AtomicBoolean();
        ProjectArchiveService service = new ProjectArchiveService(
            () -> null, new DirectThreadingStrategy(), security,
            (ignoredProject, ignoredDestination, monitor) -> writerCalled.set(true));

        Response response = service.exportProjectArchive(destination.toString());

        assertErrorContains(response, "no active project");
        assertFalse(writerCalled.get());
    }

    @Test
    public void savesAndAtomicallyReplacesDestinationWithVerifiedGar() throws Exception {
        Path destination = temporaryFolder.getRoot().toPath().resolve("fixture.gar");
        Files.writeString(destination, "old");
        DomainFile changed = mock(DomainFile.class);
        when(changed.getProjectLocator()).thenReturn(locator);
        when(changed.isChanged()).thenReturn(true);
        when(changed.canSave()).thenReturn(true);
        when(project.getOpenData()).thenReturn(List.of(changed));

        Response response = service(ProjectArchiveServiceTest::writeGar)
            .exportProjectArchive(destination.toString());

        assertTrue(response.toJson(), response instanceof Response.Ok);
        verify(changed).save(any());
        verify(project).save();
        assertTrue(Files.size(destination) > 0);
        assertNoTemporaryFiles(destination.getParent());

        @SuppressWarnings("unchecked")
        Map<String, Object> result =
            (Map<String, Object>) ((Response.Ok) response).data();
        assertEquals("fixture", result.get("project"));
        assertEquals(destination.toFile().getCanonicalPath(), result.get("path"));
        assertEquals("GAR", result.get("content_type"));
        assertEquals(Files.size(destination), result.get("size_bytes"));
    }

    @Test
    public void writerFailurePreservesExistingDestination() throws Exception {
        Path destination = temporaryFolder.getRoot().toPath().resolve("fixture.gar");
        Files.writeString(destination, "old");

        Response response = service((ignoredProject, temporary, monitor) -> {
            Files.writeString(temporary.toPath(), "partial");
            throw new IllegalStateException("simulated failure");
        }).exportProjectArchive(destination.toString());

        assertErrorContains(response, "simulated failure");
        assertEquals("old", Files.readString(destination));
        assertNoTemporaryFiles(destination.getParent());
    }

    @Test
    public void invalidArchivePreservesExistingDestination() throws Exception {
        Path destination = temporaryFolder.getRoot().toPath().resolve("fixture.gar");
        Files.writeString(destination, "old");

        Response response = service((ignoredProject, temporary, monitor) ->
            Files.writeString(temporary.toPath(), "not a GAR"))
            .exportProjectArchive(destination.toString());

        assertErrorContains(response, "GAR export failed");
        assertEquals("old", Files.readString(destination));
        assertNoTemporaryFiles(destination.getParent());
    }

    private ProjectArchiveService service(ProjectArchiveService.ArchiveWriter writer) {
        return new ProjectArchiveService(
            () -> project, new DirectThreadingStrategy(), security, writer);
    }

    private static void writeGar(Project project, File destination,
            ghidra.util.task.TaskMonitor monitor) throws Exception {
        try (JarOutputStream jar = new JarOutputStream(
                Files.newOutputStream(destination.toPath()))) {
            jar.putNextEntry(new JarEntry("JAR_FORMAT"));
            jar.closeEntry();
            jar.putNextEntry(new JarEntry(project.getName() + ".gpr"));
            jar.closeEntry();
        }
    }

    private static void assertErrorContains(Response response, String expected) {
        assertTrue(response.toJson(), response instanceof Response.Err);
        assertTrue(response.toJson(), response.toJson().contains(expected));
    }

    private static void assertNoTemporaryFiles(Path directory) throws Exception {
        try (var files = Files.list(directory)) {
            assertFalse(files.anyMatch(path ->
                path.getFileName().toString().contains(".tmp-")));
        }
    }
}
