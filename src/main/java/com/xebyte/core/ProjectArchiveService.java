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

import ghidra.app.plugin.core.archive.ProjectArchiveBridge;
import ghidra.framework.data.DefaultProjectData;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectLocator;
import ghidra.util.Msg;
import ghidra.util.PropertyFile;
import ghidra.util.SystemUtilities;
import ghidra.util.task.TaskMonitor;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.function.Supplier;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/** Exports the active project with Ghidra's native GAR writer. */
public final class ProjectArchiveService {

    private static final String PROJECT_EXTENSION = ".gpr";
    private static final String PROJECT_PROPERTIES = "project";
    private static final String PROJECT_STATE = "projectState";

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
            ProjectArchiveBridge::archive);
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
        description = "Save and export the active Ghidra project as a native GAR archive")
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
                .endsWith(ProjectArchiveBridge.ARCHIVE_EXTENSION)) {
            return Response.err("output_path must end in "
                + ProjectArchiveBridge.ARCHIVE_EXTENSION);
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

    @McpTool(path = "/restore_project_archive", method = "POST",
        description = "Restore a native GAR archive into a fresh local Ghidra project")
    public Response restoreProjectArchive(
            @Param(value = "archive_path", source = ParamSource.BODY,
                description = "Absolute path to an existing .gar archive")
                String archivePath,
            @Param(value = "parent_dir", source = ParamSource.BODY,
                description = "Existing local directory that will contain the project")
                String parentDir,
            @Param(value = "name", source = ParamSource.BODY,
                description = "Name for the restored project")
                String name) {
        if (archivePath == null || archivePath.isBlank()
                || parentDir == null || parentDir.isBlank()
                || name == null || name.isBlank()) {
            return Response.err("archive_path, parent_dir, and name are required");
        }

        Path archive;
        Path parent;
        try {
            archive = Path.of(archivePath);
            parent = Path.of(parentDir);
        }
        catch (InvalidPathException e) {
            return Response.err("invalid archive_path or parent_dir");
        }
        if (!archive.isAbsolute() || !parent.isAbsolute()) {
            return Response.err("archive_path and parent_dir must be absolute");
        }
        if (!archivePath.toLowerCase(Locale.ROOT)
                .endsWith(ProjectArchiveBridge.ARCHIVE_EXTENSION)) {
            return Response.err("archive_path must end in "
                + ProjectArchiveBridge.ARCHIVE_EXTENSION);
        }

        archive = security.resolveWithinFileRoot(archivePath);
        parent = security.resolveWithinFileRoot(parentDir);
        if (archive == null || parent == null) {
            return Response.err("archive_path and parent_dir must be within GHIDRA_MCP_FILE_ROOT");
        }
        if (!Files.isRegularFile(archive)) {
            return Response.err("archive does not exist: " + archive);
        }
        if (!Files.isDirectory(parent)) {
            return Response.err("parent directory does not exist: " + parent);
        }

        ProjectLocator locator;
        try {
            locator = new ProjectLocator(parent.toString(), name);
        }
        catch (IllegalArgumentException e) {
            return Response.err("invalid project name: " + e.getMessage());
        }
        String projectName = locator.getName();
        Path marker = locator.getMarkerFile().toPath();
        Path projectDir = locator.getProjectDir().toPath();
        if (Files.exists(marker, LinkOption.NOFOLLOW_LINKS)
                || Files.exists(projectDir, LinkOption.NOFOLLOW_LINKS)) {
            return Response.err("project destination already exists: " + marker);
        }

        Path temporary = null;
        boolean moved = false;
        try {
            temporary = Files.createTempDirectory(parent, "." + projectName + "-restore-");
            extractGar(archive, temporary);
            Files.move(temporary, projectDir);
            moved = true;
            PropertyFile properties =
                new PropertyFile(projectDir.toFile(), PROJECT_PROPERTIES);
            properties.putString(DefaultProjectData.OWNER, SystemUtilities.getUserName());
            properties.writeState();
            Files.createFile(marker);

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("project", projectName);
            result.put("path", marker.toString());
            result.put("archive_path", archive.toString());
            return Response.ok(result);
        }
        catch (Exception e) {
            deleteTree(moved ? projectDir : temporary);
            Msg.error(this, "GAR restore failed for project '" + projectName + "'", e);
            String message = e.getMessage() != null ? e.getMessage() : e.toString();
            return Response.err("GAR restore failed: " + message);
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

    private static void extractGar(Path archive, Path destination) throws IOException {
        try (JarFile jar = new JarFile(archive.toFile())) {
            if (jar.getJarEntry("JAR_FORMAT") == null) {
                throw new IOException("archive is missing JAR_FORMAT");
            }
            var entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                Path relative = Path.of(entry.getName()).normalize();
                if (relative.isAbsolute() || relative.startsWith("..")) {
                    throw new IOException("unsafe archive entry: " + entry.getName());
                }
                if (skipRestoreEntry(relative)) {
                    continue;
                }
                Path target = destination.resolve(relative).normalize();
                if (!target.startsWith(destination)) {
                    throw new IOException("unsafe archive entry: " + entry.getName());
                }
                Files.createDirectories(target.getParent());
                try (var input = jar.getInputStream(entry)) {
                    Files.copy(input, target, StandardCopyOption.REPLACE_EXISTING);
                }
            }
        }
    }

    private static boolean skipRestoreEntry(Path relative) {
        if (relative.getNameCount() == 0) {
            return true;
        }
        String root = relative.getName(0).toString();
        String filename = relative.getFileName().toString();
        return root.equalsIgnoreCase("JAR_FORMAT")
            || root.equalsIgnoreCase(PROJECT_PROPERTIES + PropertyFile.PROPERTY_EXT)
            || root.equalsIgnoreCase(PROJECT_STATE)
            || root.equalsIgnoreCase("save")
            || root.equalsIgnoreCase("groups")
            || filename.equalsIgnoreCase(".properties")
            || filename.toLowerCase(Locale.ROOT).endsWith(PROJECT_EXTENSION);
    }

    private static void deleteTree(Path root) {
        if (root == null || !Files.exists(root)) {
            return;
        }
        try (var paths = Files.walk(root)) {
            paths.sorted(Comparator.reverseOrder()).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                }
                catch (IOException ignored) {
                    // Best-effort cleanup after a failed restore.
                }
            });
        }
        catch (IOException ignored) {
            // Best-effort cleanup after a failed restore.
        }
    }
}
