package com.xebyte.offline;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.junit.Test;

import com.xebyte.core.JsonHelper;

/**
 * Proves that the advertised 64 MiB native-array limit is practical without
 * materializing a list/tree/text copy in the Java endpoint transport.
 */
public class NativeByteStreamingHeapTest {

    private static final int LIMIT = 67_108_864;

    @Test
    public void nativeArrayAtLimitBindsUnder192MiBHeap() throws Exception {
        String java = Path.of(
            System.getProperty("java.home"), "bin", "java").toString();
        Process process = new ProcessBuilder(
            java,
            "-Xmx192m",
            "-cp",
            System.getProperty("java.class.path"),
            NativeByteStreamingHeapTest.class.getName(),
            "probe")
            .redirectErrorStream(true)
            .start();
        boolean finished = process.waitFor(120, TimeUnit.SECONDS);
        if (!finished) {
            process.destroyForcibly();
            process.waitFor();
        }
        byte[] output = process.getInputStream().readNBytes(65_536);

        assertTrue("streaming probe timed out", finished);
        assertEquals(
            new String(output, StandardCharsets.UTF_8),
            0,
            process.exitValue());
    }

    public static void main(String[] args) {
        if (args.length != 1 || !"probe".equals(args[0])) {
            throw new IllegalArgumentException("probe argument required");
        }
        Map<String, Object> body = JsonHelper.parseBody(
            new ZeroByteArrayBody(LIMIT),
            Map.of("bytes", LIMIT));
        byte[] bytes = (byte[]) body.get("bytes");
        if (bytes.length != LIMIT
                || bytes[0] != 0
                || bytes[bytes.length - 1] != 0) {
            throw new AssertionError("streamed byte payload mismatch");
        }
    }

    /** Generates {"bytes":[0,0,...]} without prebuilding the JSON text. */
    private static final class ZeroByteArrayBody extends InputStream {
        private static final byte[] PREFIX =
            "{\"bytes\":[".getBytes(StandardCharsets.US_ASCII);
        private static final byte[] SUFFIX =
            "]}".getBytes(StandardCharsets.US_ASCII);

        private final int count;
        private int prefixIndex;
        private int itemIndex;
        private boolean comma;
        private int suffixIndex;

        ZeroByteArrayBody(int count) {
            this.count = count;
        }

        @Override
        public int read() {
            if (prefixIndex < PREFIX.length) {
                return PREFIX[prefixIndex++] & 0xff;
            }
            if (itemIndex < count) {
                if (itemIndex > 0 && !comma) {
                    comma = true;
                    return ',';
                }
                comma = false;
                itemIndex++;
                return '0';
            }
            if (suffixIndex < SUFFIX.length) {
                return SUFFIX[suffixIndex++] & 0xff;
            }
            return -1;
        }

        @Override
        public int read(byte[] buffer, int offset, int length) {
            if (length == 0) {
                return 0;
            }
            int written = 0;
            while (written < length) {
                int value = read();
                if (value < 0) {
                    break;
                }
                buffer[offset + written++] = (byte) value;
            }
            return written == 0 ? -1 : written;
        }
    }
}
