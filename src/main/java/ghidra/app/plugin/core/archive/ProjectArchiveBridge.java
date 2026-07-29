package ghidra.app.plugin.core.archive;

import ghidra.framework.model.Project;
import ghidra.util.task.TaskMonitor;

import java.io.File;

/** Package-local bridge to Ghidra's native project archive task. */
public final class ProjectArchiveBridge {

    public static final String ARCHIVE_EXTENSION =
        ArchivePlugin.ARCHIVE_EXTENSION;

    private ProjectArchiveBridge() {
    }

    public static void archive(
            Project project, File destination, TaskMonitor monitor)
            throws Exception {
        new ArchiveTask(project, destination).run(monitor);
    }
}
