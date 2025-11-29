package ghidra_string_sniper;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;


public class PythonRunner {

	public static RunResult runSystemPython(Path dir, String scriptName, List<String> args, long timeoutSec)
		throws IOException, InterruptedException {

		List<String> cmd = new ArrayList<>();
		cmd.add(System.getProperty("os.name").toLowerCase().contains("win") ? "python" : "python3");
		cmd.add(dir.resolve(scriptName).toString());
		if (args != null) cmd.addAll(args);

		ProcessBuilder pb = new ProcessBuilder(cmd).redirectErrorStream(true).directory(dir.toFile());
		Process p = pb.start();

		StringBuilder out = new StringBuilder();
		try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
			r.lines().forEach(l -> out.append(l).append(System.lineSeparator()));
		}

		if (timeoutSec > 0 && !p.waitFor(timeoutSec, TimeUnit.SECONDS)) { p.destroyForcibly(); return null; }
		p.waitFor();

		return new RunResult(p.exitValue(), out.toString());
	}

	public static class RunResult {
		public final int exitCode;
		public final String stdout;
		public RunResult(int exitCode, String stdout) { this.exitCode = exitCode; this.stdout = stdout; }
	}
}
