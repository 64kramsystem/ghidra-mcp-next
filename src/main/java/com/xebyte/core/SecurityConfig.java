package com.xebyte.core;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SecureDirectoryStream;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * Read-once, thread-safe snapshot of security-relevant environment variables.
 *
 * v5.4.1 introduces three opt-in hardening switches. All are off by default
 * so existing localhost-only deployments see no behavior change.
 *
 * <ul>
 *   <li>{@code GHIDRA_MCP_AUTH_TOKEN} — if set, every HTTP request must
 *       carry a matching {@code Authorization: Bearer &lt;token&gt;} header.
 *       Read-only health endpoints ({@code /mcp/health}, {@code /check_connection})
 *       are always exempt. Constant-time comparison is used to resist timing
 *       attacks. When unset, no authentication is enforced (pre-v5.4.1
 *       behavior).
 *   <li>{@code GHIDRA_MCP_ALLOW_SCRIPTS} — set to {@code "1"}, {@code "true"},
 *       or {@code "yes"} (case-insensitive) to allow {@code /run_script} and
 *       {@code /run_script_inline}. These endpoints execute arbitrary Java
 *       code against the Ghidra process and are off by default in v5.4.1+.
 *       Without an explicit opt-in they return 403. Scripts endpoints were
 *       always-on before v5.4.1; the flip to default-off is a deliberate
 *       breaking change in the security release.
 *   <li>{@code GHIDRA_MCP_FILE_ROOT} — if set to a directory path, endpoints that take a
 *       real <em>filesystem</em> path canonicalize the input (via
 *       {@link #resolveWithinFileRoot(String)}) and require that the resolved path fall
 *       under this root, preventing path traversal. This applies to {@code /import_file}
 *       (and the headless import path). When unset, paths are accepted as-is (pre-v5.4.1
 *       behavior).
 *       <p>Note: {@code /delete_file} and {@code /open_project} operate on Ghidra
 *       <em>project domain</em> paths (e.g. {@code /Vanilla/1.00/D2Common.dll}), not
 *       filesystem paths, so file-root canonicalization does not apply to them; their
 *       analogous containment guard is project-folder scope
 *       ({@link #isPathInProjectScope(String)}), which is enforced only when a project
 *       scope is configured.</li>
 *   <li>{@code GHIDRA_MCP_ALLOW_UNSECURED_FILE_READ} — set to {@code "1"}, {@code "true"},
 *       or {@code "yes"} (case-insensitive) to permit bounded file reads on filesystem
 *       providers that offer no {@link SecureDirectoryStream}, which on macOS means all of
 *       them. Without it those reads fail closed, so every endpoint taking
 *       {@code file_path} bytes is unusable there. The fallback narrows the substitution
 *       window rather than closing it — see
 *       {@link #readFileRangeWithoutSecureTraversal} — which is why it is opt-in.</li>
 * </ul>
 *
 * Also enforces a bind-hardening rule at headless startup:
 * {@link #requireAuthForNonLoopbackBind(String)} refuses to start the
 * server on a non-loopback address unless a token is configured.
 */
public final class SecurityConfig {

    private static final SecurityConfig INSTANCE = new SecurityConfig();

    private final byte[] tokenBytes;     // null if auth disabled
    private final boolean scriptsAllowed;
    private final String fileRoot;       // null if disabled
    private final Path fileRootCanonical;
    private final String projectFolderScope; // null = no enforcement (default)
    private final boolean unsecuredFileReadAllowed;

    private SecurityConfig() {
        this(System.getenv("GHIDRA_MCP_AUTH_TOKEN"),
            System.getenv("GHIDRA_MCP_ALLOW_SCRIPTS"),
            System.getenv("GHIDRA_MCP_FILE_ROOT"),
            System.getenv("GHIDRA_MCP_PROJECT_FOLDER"),
            System.getenv("GHIDRA_MCP_ALLOW_UNSECURED_FILE_READ"));
    }

    private SecurityConfig(String rawToken, String rawScripts, String rawRoot,
            String rawScope, String rawUnsecuredRead) {
        this.unsecuredFileReadAllowed = rawUnsecuredRead != null
                && (rawUnsecuredRead.equalsIgnoreCase("1")
                    || rawUnsecuredRead.equalsIgnoreCase("true")
                    || rawUnsecuredRead.equalsIgnoreCase("yes"));

        this.tokenBytes = (rawToken != null && !rawToken.isEmpty())
                ? rawToken.getBytes(StandardCharsets.UTF_8)
                : null;

        this.scriptsAllowed = rawScripts != null
                && (rawScripts.equalsIgnoreCase("1")
                    || rawScripts.equalsIgnoreCase("true")
                    || rawScripts.equalsIgnoreCase("yes"));

        if (rawRoot != null && !rawRoot.isEmpty()) {
            this.fileRoot = rawRoot;
            Path p;
            try {
                p = new File(rawRoot).getCanonicalFile().toPath();
            } catch (IOException e) {
                p = Paths.get(rawRoot).toAbsolutePath().normalize();
            }
            this.fileRootCanonical = p;
        } else {
            this.fileRoot = null;
            this.fileRootCanonical = null;
        }

        // Project-folder scope guard. When set, FrontEndProgramProvider
        // refuses to return Programs whose DomainFile path falls outside
        // this prefix. Default unset = no enforcement (back-compat for all
        // general users — only opt-in via env var changes behavior).
        // Trailing slash normalized so collision-safe `path == prefix or
        // startsWith(prefix + "/")` matching works.
        if (rawScope != null) {
            String trimmed = rawScope.trim();
            // Strip trailing slash unless the value is just "/"
            if (trimmed.length() > 1 && trimmed.endsWith("/")) {
                trimmed = trimmed.substring(0, trimmed.length() - 1);
            }
            this.projectFolderScope = trimmed.isEmpty() ? null : trimmed;
        } else {
            this.projectFolderScope = null;
        }
    }

    /**
     * Build an isolated configuration with a real file-root policy for tests.
     * Package-private so production callers continue to use the environment snapshot.
     *
     * <p>The unsecured-read fallback is enabled here so the suite exercises the same read path
     * on providers with and without {@link SecureDirectoryStream}. Production keeps that
     * fallback behind an explicit environment opt-in.
     */
    static SecurityConfig forFileRootTesting(Path fileRoot) {
        if (fileRoot == null) {
            throw new IllegalArgumentException("fileRoot is required");
        }
        return new SecurityConfig(null, null, fileRoot.toString(), null, "1");
    }

    public static SecurityConfig getInstance() {
        return INSTANCE;
    }

    /** True when {@code GHIDRA_MCP_AUTH_TOKEN} is set. */
    public boolean isAuthEnabled() {
        return tokenBytes != null;
    }

    /**
     * Extract the bearer token from an {@code Authorization} header value
     * and compare it constant-time against the configured token.
     *
     * @param authHeader the full header value (e.g. {@code "Bearer abc123"});
     *                   may be {@code null}
     * @return true if auth is disabled, or if the token matches
     */
    public boolean matchesBearerAuth(String authHeader) {
        if (tokenBytes == null) return true;  // auth disabled
        if (authHeader == null) return false;
        // Accept "Bearer <token>" with any amount of whitespace
        String prefix = "Bearer ";
        if (authHeader.length() < prefix.length()
                || !authHeader.regionMatches(true, 0, prefix, 0, prefix.length())) {
            return false;
        }
        byte[] presented = authHeader.substring(prefix.length()).trim()
                .getBytes(StandardCharsets.UTF_8);
        return constantTimeEquals(tokenBytes, presented);
    }

    /** True when {@code GHIDRA_MCP_ALLOW_SCRIPTS} opts in. */
    public boolean areScriptsAllowed() {
        return scriptsAllowed;
    }

    /** True when {@code GHIDRA_MCP_PROJECT_FOLDER} is set (any value). */
    public boolean hasProjectFolderScope() {
        return projectFolderScope != null;
    }

    /**
     * Return the configured project-folder scope prefix (e.g.
     * {@code "/Mods/PD2-S12"}), or {@code null} when unset (default).
     * Trailing slash already normalized at construction.
     */
    public String getProjectFolderScope() {
        return projectFolderScope;
    }

    /**
     * Test whether {@code domainFilePath} falls under the configured project
     * folder scope. Always returns {@code true} when no scope is configured
     * (default — preserves general-user behavior).
     *
     * Uses the {@code path == prefix || path.startsWith(prefix + "/")} idiom
     * to prevent prefix-collision attacks (e.g. {@code /Mods/PD2-S12-OTHER}
     * does NOT match scope {@code /Mods/PD2-S12}).
     *
     * @param domainFilePath the project-relative path of a Ghidra DomainFile
     *                       (e.g. {@code "/Mods/PD2-S12/Bnclient.dll"});
     *                       null returns true (unscoped equivalent)
     */
    public boolean isPathInProjectScope(String domainFilePath) {
        if (projectFolderScope == null) return true;
        if (domainFilePath == null) return true;
        if (domainFilePath.equals(projectFolderScope)) return true;
        return domainFilePath.startsWith(projectFolderScope + "/");
    }

    /** True when {@code GHIDRA_MCP_FILE_ROOT} is set. */
    public boolean hasFileRoot() {
        return fileRoot != null;
    }

    public String getFileRoot() {
        return fileRoot;
    }

    /**
     * Canonicalize {@code userPath} and verify it falls under
     * {@link #getFileRoot()}. When no file root is configured this returns the
     * path as-is (pre-v5.4.1 behavior). Returns {@code null} when a root is
     * configured and the path escapes it.
     */
    public Path resolveWithinFileRoot(String userPath) {
        if (userPath == null) return null;
        Path requested;
        try {
            requested = new File(userPath).getCanonicalFile().toPath();
        } catch (IOException e) {
            requested = Paths.get(userPath).toAbsolutePath().normalize();
        }
        if (fileRootCanonical == null) {
            return requested;  // no allow-list configured
        }
        return requested.startsWith(fileRootCanonical) ? requested : null;
    }

    /**
     * Read one bounded file range through directory handles anchored at the
     * filesystem root. Every path component is opened with
     * {@link LinkOption#NOFOLLOW_LINKS}, so replacing an approved file,
     * parent, or configured root with a symlink cannot escape the allow-list.
     *
     * <p>Providers without {@link SecureDirectoryStream} — which includes every filesystem on
     * macOS, where the JDK offers no secure variant at all — fail closed unless
     * {@code GHIDRA_MCP_ALLOW_UNSECURED_FILE_READ} is set, in which case
     * {@link #readFileRangeWithoutSecureTraversal} handles the read under a weaker guarantee.
     */
    byte[] readFileRangeWithinRoot(
            Path authorizedPath, long offset, int length)
            throws IOException {
        if (fileRootCanonical == null) {
            throw new IOException("GHIDRA_MCP_FILE_ROOT is not configured");
        }
        if (authorizedPath == null) {
            throw new IOException("file path was not authorized");
        }
        Path requested = authorizedPath.toAbsolutePath().normalize();
        if (!requested.startsWith(fileRootCanonical)) {
            throw new IOException(
                "file path is outside GHIDRA_MCP_FILE_ROOT");
        }
        if (requested.equals(fileRootCanonical)
                || requested.getFileName() == null) {
            throw new IOException("file_path must name a regular file");
        }

        Path anchor = fileRootCanonical.getRoot();
        if (anchor == null) {
            throw new IOException(
                "GHIDRA_MCP_FILE_ROOT must be an absolute path");
        }
        List<Path> directories = new ArrayList<>();
        for (Path component : anchor.relativize(fileRootCanonical)) {
            directories.add(component);
        }
        Path relative = fileRootCanonical.relativize(requested);
        Path parent = relative.getParent();
        if (parent != null) {
            for (Path component : parent) {
                directories.add(component);
            }
        }

        List<SecureDirectoryStream<Path>> opened = new ArrayList<>();
        Throwable primaryFailure = null;
        try {
            DirectoryStream<Path> rootStream =
                java.nio.file.Files.newDirectoryStream(anchor);
            if (!(rootStream instanceof SecureDirectoryStream<?>)) {
                rootStream.close();
                if (!unsecuredFileReadAllowed) {
                    throw new IOException(
                        "filesystem provider does not support secure file-root traversal; "
                            + "set GHIDRA_MCP_ALLOW_UNSECURED_FILE_READ=1 to permit the "
                            + "canonicalizing fallback, which is not race-free");
                }
                return readFileRangeWithoutSecureTraversal(
                    authorizedPath, offset, length);
            }
            @SuppressWarnings("unchecked")
            SecureDirectoryStream<Path> current =
                (SecureDirectoryStream<Path>) rootStream;
            opened.add(current);
            for (Path component : directories) {
                current = current.newDirectoryStream(
                    component, LinkOption.NOFOLLOW_LINKS);
                opened.add(current);
            }

            Path fileName = requested.getFileName();
            BasicFileAttributeView view = current.getFileAttributeView(
                fileName,
                BasicFileAttributeView.class,
                LinkOption.NOFOLLOW_LINKS);
            if (view == null) {
                throw new IOException(
                    "filesystem provider cannot inspect file_path securely");
            }
            BasicFileAttributes attributes = view.readAttributes();
            if (!attributes.isRegularFile()) {
                throw new IOException(
                    "file_path must be a regular readable file: "
                        + requested);
            }

            Set<OpenOption> options = Set.of(
                StandardOpenOption.READ,
                LinkOption.NOFOLLOW_LINKS);
            try (SeekableByteChannel channel =
                    current.newByteChannel(fileName, options)) {
                return readSlice(channel, offset, length);
            }
        }
        catch (IOException | RuntimeException | Error error) {
            primaryFailure = error;
            throw error;
        }
        finally {
            Collections.reverse(opened);
            IOException closeFailure = null;
            for (SecureDirectoryStream<Path> stream : opened) {
                try {
                    stream.close();
                }
                catch (IOException error) {
                    if (closeFailure == null) {
                        closeFailure = error;
                    }
                    else {
                        closeFailure.addSuppressed(error);
                    }
                }
            }
            if (closeFailure != null) {
                if (primaryFailure != null) {
                    primaryFailure.addSuppressed(closeFailure);
                }
                else {
                    throw closeFailure;
                }
            }
        }
    }

    /**
     * Read one bounded file range without per-component directory handles, for providers that
     * offer no {@link SecureDirectoryStream}.
     *
     * <p><strong>This is weaker than {@link #readFileRangeWithinRoot} and cannot be made as
     * strong with standard Java.</strong> The secure path holds an open handle on every path
     * component, so no component can be substituted once it has been verified. Here the path is
     * verified by name: canonicalization resolves every symlink and the result must fall inside
     * the configured root, the file is opened with {@link LinkOption#NOFOLLOW_LINKS} so the last
     * component cannot itself be a link, and both the canonical path and the file's identity are
     * re-checked after the open so a substitution made during the call is detected. A
     * substitution that lands between the final check and the kernel's own resolution is still
     * possible: the window is narrowed, not closed. That is why reaching this method requires
     * {@code GHIDRA_MCP_ALLOW_UNSECURED_FILE_READ}.
     */
    byte[] readFileRangeWithoutSecureTraversal(
            Path authorizedPath, long offset, int length)
            throws IOException {
        if (fileRootCanonical == null) {
            throw new IOException("GHIDRA_MCP_FILE_ROOT is not configured");
        }
        if (authorizedPath == null) {
            throw new IOException("file path was not authorized");
        }
        Path resolved = canonicalWithinRoot(authorizedPath);
        BasicFileAttributes before = java.nio.file.Files.readAttributes(
            resolved, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!before.isRegularFile()) {
            throw new IOException(
                "file_path must be a regular readable file: " + resolved);
        }

        Set<OpenOption> options = Set.of(
            StandardOpenOption.READ,
            LinkOption.NOFOLLOW_LINKS);
        try (SeekableByteChannel channel =
                java.nio.file.Files.newByteChannel(resolved, options)) {
            // Re-verify after opening: a swap performed during the call above would otherwise
            // leave this holding a handle on a file outside the root.
            if (!resolved.equals(canonicalWithinRoot(authorizedPath))) {
                throw new IOException(
                    "file path changed while opening; refusing the read");
            }
            BasicFileAttributes after = java.nio.file.Files.readAttributes(
                resolved, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (before.fileKey() != null
                    && !before.fileKey().equals(after.fileKey())) {
                throw new IOException(
                    "file was replaced while opening; refusing the read");
            }
            return readSlice(channel, offset, length);
        }
    }

    /**
     * Canonicalize {@code requested} — resolving every symlink in it — and require the result to
     * name a file inside the configured root.
     */
    private Path canonicalWithinRoot(Path requested) throws IOException {
        Path canonical = requested.toFile().getCanonicalFile().toPath();
        if (!canonical.startsWith(fileRootCanonical)) {
            throw new IOException("file path is outside GHIDRA_MCP_FILE_ROOT");
        }
        if (canonical.equals(fileRootCanonical) || canonical.getFileName() == null) {
            throw new IOException("file_path must name a regular file");
        }
        return canonical;
    }

    /** Reads exactly {@code length} bytes at {@code offset}, against the channel's own size. */
    private static byte[] readSlice(
            SeekableByteChannel channel, long offset, int length)
            throws IOException {
        long size = channel.size();
        if (offset > size || length > size - offset) {
            throw new IOException(
                "file_offset plus source_length exceeds file size");
        }
        byte[] result = new byte[length];
        channel.position(offset);
        ByteBuffer buffer = ByteBuffer.wrap(result);
        while (buffer.hasRemaining()) {
            int count = channel.read(buffer);
            if (count < 0) {
                break;
            }
        }
        if (buffer.hasRemaining()) {
            throw new IOException(
                "file changed while reading; requested range no longer fits");
        }
        return result;
    }

    /**
     * Validate a bind address at server startup. When auth is NOT configured,
     * only loopback is permitted. Returns an error message to throw, or
     * {@code null} if the bind is acceptable.
     */
    public String requireAuthForNonLoopbackBind(String bindAddress) {
        if (bindAddress == null) return null;
        if (isAuthEnabled()) return null;
        if ("127.0.0.1".equals(bindAddress) || "localhost".equalsIgnoreCase(bindAddress)
                || "::1".equals(bindAddress)) {
            return null;
        }
        return "Refusing to bind " + bindAddress
                + " without GHIDRA_MCP_AUTH_TOKEN. Set the env var to a"
                + " strong shared secret before binding to a non-loopback address.";
    }

    /**
     * Timing-safe byte array comparison. Always iterates the longer of the
     * two arrays to avoid leaking length via timing. Returns false if arrays
     * differ in length.
     */
    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null) return false;
        int diff = a.length ^ b.length;
        int max = Math.max(a.length, b.length);
        for (int i = 0; i < max; i++) {
            byte ab = i < a.length ? a[i] : 0;
            byte bb = i < b.length ? b[i] : 0;
            diff |= (ab ^ bb);
        }
        return diff == 0;
    }
}
