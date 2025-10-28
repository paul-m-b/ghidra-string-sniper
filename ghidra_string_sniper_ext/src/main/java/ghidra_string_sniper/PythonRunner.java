package ghidra_string_sniper;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class PythonRunner {
	public static Path getTempDirFromResourceDir(Class yourClass, String resourceDir) throws IOException {
		// TODO - calculate files inside of resourceDir
		String[] files = {
			"TOKEN",
			"string_prioritize.py",
			"requirements.txt",
			"llm_interact.py",
			"function_match.py",
			"cfg/strprioritize_response.json",
			"cfg/strprioritize_system.txt"
		};

		// ensure resourceDir ends with a slash so concatenation is safe
		if (!resourceDir.endsWith("/")) {
			resourceDir = resourceDir + "/";
		}

		Path tempDirectory = Files.createTempDirectory("ghidra-sniper-python-script-");

		for (String name : files) {
			// Resolve file path inside the temp directory, creating parent directories if needed
			Path dest = tempDirectory.resolve(name);
			File destFile = dest.toFile();
			File parent = destFile.getParentFile();
			if (parent != null && !parent.exists()) {
				if (!parent.mkdirs()) {
					throw new IOException("Failed to create parent directories for " + dest);
				}
			}

			// Load resource from classpath
			try (InputStream in = yourClass.getResourceAsStream(resourceDir + name)) {
				if (in == null) {
					throw new FileNotFoundException("Resource not found: " + resourceDir + name);
				}
				// Copy to destination (overwrites if somehow present)
				Files.copy(in, dest, StandardCopyOption.REPLACE_EXISTING);
			}
		}

		return tempDirectory;
	}

    public static RunResult runSystemPython(Class myClass, String scriptDir, String scriptName, List<String> args, long timeoutSeconds) throws IOException, InterruptedException {
		// copy python scripts from directory to temp dir
		Path tempDir = getTempDirFromResourceDir(myClass, scriptDir);

		// build command to run
        String os = System.getProperty("os.name").toLowerCase();
        String pythonCmd = os.contains("win") ? "python" : "python3";
        List<String> cmd = new ArrayList<>();
        cmd.add(pythonCmd);
        cmd.add(tempDir.resolve(scriptName).toString());
        if (args != null) cmd.addAll(args);

        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true); // merge stderr -> stdout
		pb.directory(new File(tempDir.toString()));

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
