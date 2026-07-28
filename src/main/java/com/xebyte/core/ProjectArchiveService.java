/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.xebyte.core;

import ghidra.app.plugin.core.archive.HeadlessArchiveBridge;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectLocator;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.function.Supplier;
import java.util.jar.JarFile;

/** Exports the active project with Ghidra's native GAR writer. */
@McpToolGroup(value = "export", description = "Native program and project export")
public final class ProjectArchiveService {

    @FunctionalInterface
    interface ArchiveWriter {
        void write(Project project, File destination, TaskMonitor monitor) throws Exception;
    }

    private final Supplier<Project> projectSupplier;
    private final ThreadingStrategy threading;
    private final SecurityConfig security;
    private final ArchiveWriter archiveWriter;

    public ProjectArchiveService(Supplier<Project> projectSupplier,
            ThreadingStrategy threading) {
        this(projectSupplier, threading, SecurityConfig.getInstance(),
            HeadlessArchiveBridge::archive);
    }

    ProjectArchiveService(Supplier<Project> projectSupplier,
            ThreadingStrategy threading, SecurityConfig security,
            ArchiveWriter archiveWriter) {
        this.projectSupplier = projectSupplier;
        this.threading = threading;
        this.security = security;
        this.archiveWriter = archiveWriter;
    }

    @McpTool(path = "/export_project_archive", method = "POST",
        description = "Save and export the active Ghidra project as a native GAR archive",
        category = "export", supportsDryRun = false)
    public Response exportProjectArchive(
            @Param(value = "output_path", source = ParamSource.BODY,
                description = "Absolute destination path ending in .gar")
                String outputPath) {
        if (outputPath == null || outputPath.isBlank()) {
            return Response.err("output_path required");
        }

        Path requested;
        try {
            requested = Path.of(outputPath);
        }
        catch (InvalidPathException e) {
            return Response.err("invalid output_path: " + outputPath);
        }
        if (!requested.isAbsolute()) {
            return Response.err("output_path must be absolute");
        }
        if (!outputPath.toLowerCase(Locale.ROOT)
                .endsWith(HeadlessArchiveBridge.ARCHIVE_EXTENSION)) {
            return Response.err("output_path must end in "
                + HeadlessArchiveBridge.ARCHIVE_EXTENSION);
        }

        Path destination = security.resolveWithinFileRoot(outputPath);
        if (destination == null) {
            return Response.err(
                "output_path is outside GHIDRA_MCP_FILE_ROOT: " + outputPath);
        }
        Path parent = destination.getParent();
        if (parent == null || !Files.isDirectory(parent)) {
            return Response.err(
                "destination parent directory does not exist: " + parent);
        }
        if (Files.isDirectory(destination)) {
            return Response.err("destination is a directory: " + destination);
        }

        Project project = projectSupplier.get();
        if (project == null || project.isClosed()) {
            return Response.err("no active project");
        }

        Path temporary = ExportService.siblingTemporaryPath(destination);
        boolean published = false;
        try {
            saveChangedFiles(project);
            archiveWriter.write(project, temporary.toFile(), TaskMonitor.DUMMY);
            verifyGar(temporary, project.getName());
            long size = Files.size(temporary);
            ExportService.publish(temporary, destination, true);
            published = true;

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("project", project.getName());
            result.put("path", destination.toString());
            result.put("size_bytes", size);
            result.put("content_type", "GAR");
            return Response.ok(result);
        }
        catch (Exception e) {
            Msg.error(this, "GAR export failed for project '" + project.getName() + "'", e);
            String message = e.getMessage() != null ? e.getMessage() : e.toString();
            return Response.err("GAR export failed: " + message);
        }
        finally {
            if (!published) {
                try {
                    Files.deleteIfExists(temporary);
                }
                catch (IOException ignored) {
                    // Best-effort cleanup after a failed export.
                }
            }
        }
    }

    private void saveChangedFiles(Project project) throws Exception {
        ProjectLocator activeLocator = project.getProjectLocator();
        for (DomainFile file : project.getOpenData()) {
            if (file == null || !activeLocator.equals(file.getProjectLocator())
                    || !file.isChanged()) {
                continue;
            }
            if (!file.canSave()) {
                throw new IOException(
                    "changed project file cannot be saved: " + file.getPathname());
            }
            threading.executeRead(() -> {
                file.save(TaskMonitor.DUMMY);
                return null;
            });
        }
        threading.executeRead(() -> {
            project.save();
            return null;
        });
    }

    private static void verifyGar(Path archive, String projectName)
            throws IOException {
        if (!Files.isRegularFile(archive)) {
            throw new IOException("native archive writer produced no file");
        }
        try (JarFile jar = new JarFile(archive.toFile())) {
            if (jar.getJarEntry("JAR_FORMAT") == null
                    || jar.getJarEntry(projectName + ".gpr") == null) {
                throw new IOException("native archive writer produced an invalid GAR");
            }
        }
    }
}
