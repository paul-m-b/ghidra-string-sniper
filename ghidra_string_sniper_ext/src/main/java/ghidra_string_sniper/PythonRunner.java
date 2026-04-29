package ghidra_string_sniper;

import ghidra.framework.Application;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;

import generic.jar.ResourceFile;

public class PythonRunner {
    /**
     * Copies a resource directory from the Ghidra module data into a temporary
     * directory on the filesystem. Returns the path to the temporary directory.
     */
	public static Path getTempDirFromResourceDir(String resourceDir) throws IOException {
		if (!resourceDir.endsWith("/")) resourceDir += "/";
		ResourceFile base = Application.getModuleDataSubDirectory(resourceDir);
		if (base == null || !base.exists()) throw new FileNotFoundException("Resource dir not found: " + resourceDir);

		Path temp = Files.createTempDirectory("ghidra-sniper-python-script-");
		copyRecursive(base.getFile(false), temp);
		return temp;
	}

	/**
     * Recursively copies files from a source directory to a destination path.
     */
	private static void copyRecursive(File src, Path dest) throws IOException {
		if (src.isDirectory()) {
			for (File f : Objects.requireNonNull(src.listFiles()))
				copyRecursive(f, dest.resolve(src.toPath().relativize(f.toPath()).toString()));
		} else {
			Files.createDirectories(dest.getParent());
			Files.copy(src.toPath(), dest, StandardCopyOption.REPLACE_EXISTING);
		}
	}
    /**
     * Executes a Python script located in a resource directory, using the system Python interpreter.
     */
	public static RunResult runSystemPython(String scriptDir, String scriptName, List<String> args, long timeoutSec)
		throws IOException, InterruptedException {

		Path tempDir = getTempDirFromResourceDir(scriptDir);
		List<String> cmd = new ArrayList<>();
		cmd.add(System.getProperty("os.name").toLowerCase().contains("win") ? "python" : "python3");
		cmd.add(tempDir.resolve(scriptName).toString());
		if (args != null) cmd.addAll(args);

		ProcessBuilder pb = new ProcessBuilder(cmd).redirectErrorStream(true).directory(tempDir.toFile());
		Process p = pb.start();

		StringBuilder out = new StringBuilder();
		try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
			r.lines().forEach(l -> out.append(l).append(System.lineSeparator()));
		}

		if (timeoutSec > 0 && !p.waitFor(timeoutSec, TimeUnit.SECONDS)) { p.destroyForcibly(); return null; }
		p.waitFor();

		return new RunResult(p.exitValue(), out.toString());
	}
    /**
     * Simple data container for the result of running a Python script.
     */
	public static class RunResult {
		public final int exitCode;
		public final String stdout;
		public RunResult(int exitCode, String stdout) { this.exitCode = exitCode; this.stdout = stdout; }
	}
}
