package ghidra_string_sniper;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.apache.commons.io.IOUtils;

public class PythonRunner {
	public static File getTempFileFromResource(Class yourClass, String resourcePath) throws IOException {
		InputStream in = yourClass.getResourceAsStream(resourcePath);
		File tempFile = File.createTempFile("ghidra-resource-", "-" + Paths.get(resourcePath).getFileName());
		tempFile.deleteOnExit();
		try(OutputStream outputStream = new FileOutputStream(tempFile)){
			IOUtils.copy(in, outputStream);
		}

		return tempFile;
	}

    public static RunResult runSystemPython(Class myClass, String scriptResource, List<String> args, long timeoutSeconds) throws IOException, InterruptedException {
        String os = System.getProperty("os.name").toLowerCase();
        String pythonCmd = os.contains("win") ? "python" : "python3";
        List<String> cmd = new ArrayList<>();
        cmd.add(pythonCmd);
        cmd.add(getTempFileFromResource(myClass, scriptResource).getPath());
        if (args != null) cmd.addAll(args);

        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true); // merge stderr -> stdout

        Process p;
        try {
            p = pb.start();
        } catch (IOException ioe) {
            // Try fallback to "python" if "python3" not found
            if (!pythonCmd.equals("python")) {
                cmd.set(0, "python");
                p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
            } else {
                throw ioe;
            }
        }

        // read all output (stdout+stderr)
        StringBuilder out = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                out.append(line).append(System.lineSeparator());
            }
        }

        if (timeoutSeconds > 0) {
            boolean exited = p.waitFor(timeoutSeconds, TimeUnit.SECONDS);
            if (!exited) {
                p.destroyForcibly();
                return null;
            }
        } else {
            p.waitFor();
        }

        int code = p.exitValue();
        return new RunResult(code, out.toString());
    }

    public static class RunResult {
        public final int exitCode;
        public final String stdout;
        public RunResult(int exitCode, String stdout) {
            this.exitCode = exitCode;
            this.stdout = stdout;
        }
    }
}
