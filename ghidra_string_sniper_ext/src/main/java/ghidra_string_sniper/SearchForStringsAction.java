package ghidra_string_sniper;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import resources.Icons;

public class SearchForStringsAction extends DockingAction {

    public SearchForStringsAction(StringSniperComponentProvider provider, String owner) {
        super("Search For Strings", owner);
        setToolBarData(new ToolBarData(Icons.REFRESH_ICON));
    }

    @Override
    public void actionPerformed(ActionContext context) {
        ComponentProvider cp = context.getComponentProvider();
        if (!(cp instanceof StringSniperComponentProvider)) {
            return;
        }

        StringSniperComponentProvider sscp = (StringSniperComponentProvider) cp;
        Program program = sscp.getProgram();
        if (program == null) {
            Msg.showError(this, null, "No Program", "No program is currently open.");
            return;
        }

        Path projectDir = sscp.getProjectDir();
        if (projectDir == null) {
            Msg.showError(this, null, "No Project", "No project is currently open.");
            return;
        }

        String programId = program.getDomainFile() != null
                ? program.getDomainFile().getPathname()
                : program.getName();

        Path gssRoot = projectDir.resolve("gss_runs");
        String binaryId = buildBinaryId(programId);
        Path outputDir = gssRoot.resolve(binaryId);
        Path tokenPath = projectDir.resolve("gss_token.txt");

        String tokenValue = null;
        if (Files.exists(tokenPath)) {
            try {
                tokenValue = Files.readString(tokenPath, StandardCharsets.UTF_8).trim();
            } catch (IOException e) {
                Msg.showError(this, null, "Token Read Error", "Failed to read stored API key: " + e.getMessage());
                return;
            }
        }
        if (tokenValue == null || tokenValue.isBlank()) {
            tokenValue = JOptionPane.showInputDialog(
                    "Enter your Openrouter API key here:", "EnterValue"
            );
            if (tokenValue == null || tokenValue.trim().isEmpty()) {
                Msg.showWarn(this, null, "Missing API Key", "API key is required to run the pipeline.");
                return;
            }
            try {
                Files.createDirectories(projectDir);
                Files.writeString(tokenPath, tokenValue.trim(), StandardCharsets.UTF_8);
            } catch (IOException e) {
                Msg.showError(this, null, "Token Write Error", "Failed to save API key: " + e.getMessage());
                return;
            }
        }

        final Program programFinal = program;
        final StringSniperComponentProvider sscpFinal = sscp;
        final String keyPath = tokenPath.toString();
        final Path outputDirFinal = outputDir;

        Task task = new Task("Ghidra String Sniper Pipeline", true, true, true) {
            @Override
            public void run(TaskMonitor monitor) {
                try {
                    monitor.initialize(100);
                    monitor.setProgress(0);
                    monitor.setMessage("Preparing output...");
                    if (Files.exists(outputDirFinal)) {
                        deleteDirectory(outputDirFinal);
                    }
                    Files.createDirectories(outputDirFinal);
                    monitor.setProgress(5);

                    monitor.setMessage("Exporting strings...");
                    Map<String, Address> addressMap = exportStringsRaw(programFinal, outputDirFinal);
                    monitor.setProgress(15);

                    monitor.setMessage("Ranking strings (LLM)...");
                    List<String> rankArgs = new ArrayList<>();
                    rankArgs.add("--strings");
                    rankArgs.add(outputDirFinal.resolve("strings_raw.json").toString());
                    rankArgs.add("--out");
                    rankArgs.add(outputDirFinal.toString());
                    if (keyPath != null && !keyPath.isBlank()) {
                        rankArgs.add("--token");
                        rankArgs.add(keyPath);
                    }
                    PythonRunner.RunResult rankResult = PythonRunner.runSystemPython(
                            "python",
                            "extension_interface/rank_strings.py",
                            rankArgs,
                            0
                    );
                    if (rankResult == null) {
                        throw new IOException("Python ranking timed out or failed to start.");
                    }
                    if (rankResult.exitCode != 0) {
                        throw new IOException("Python ranking failed:\n" + rankResult.stdout);
                    }
                    monitor.setProgress(35);

                    File resultsFile = outputDirFinal.resolve("results.json").toFile();
                    if (!resultsFile.exists()) {
                        throw new IOException("results.json not found: " + resultsFile.getAbsolutePath());
                    }

                    JsonObject resultsRoot =
                            JsonParser.parseString(Files.readString(resultsFile.toPath())).getAsJsonObject();

                    monitor.setMessage("Decompiling referenced functions...");
                    writeDecomps(programFinal, addressMap, resultsRoot, outputDirFinal, monitor, 35, 40);
                    monitor.setProgress(75);

                    monitor.setMessage("Sourcegraph + function match...");
                    List<String> analyzeArgs = new ArrayList<>();
                    analyzeArgs.add("--out");
                    analyzeArgs.add(outputDirFinal.toString());
                    if (keyPath != null && !keyPath.isBlank()) {
                        analyzeArgs.add("--token");
                        analyzeArgs.add(keyPath);
                    }
                    PythonRunner.RunResult analyzeResult = PythonRunner.runSystemPython(
                            "python",
                            "extension_interface/analyze_strings.py",
                            analyzeArgs,
                            0
                    );
                    if (analyzeResult == null) {
                        throw new IOException("Python analysis timed out or failed to start.");
                    }
                    if (analyzeResult.exitCode != 0) {
                        throw new IOException("Python analysis failed:\n" + analyzeResult.stdout);
                    }
                    monitor.setProgress(90);

                    File matchesFile = outputDirFinal.resolve("MATCHES.json").toFile();
                    if (!matchesFile.exists()) {
                        throw new IOException("MATCHES.json not found: " + matchesFile.getAbsolutePath());
                    }

                    JsonObject matchesRoot =
                            JsonParser.parseString(Files.readString(matchesFile.toPath())).getAsJsonObject();

                    List<StringData> newData = new ArrayList<>();
                    for (String extractedValue : resultsRoot.keySet()) {
                        JsonObject rObj = resultsRoot.getAsJsonObject(extractedValue);

                        int resultsScore = rObj.get("confidence").getAsInt();
                        float entropy = rObj.get("entropy").getAsFloat();
                        String hash = rObj.get("hash").getAsString();

                        Float matchScore = null;
                        if (matchesRoot.has(hash)) {
                            JsonArray arr = matchesRoot.getAsJsonArray(hash);
                            if (arr.size() > 1) {
                                matchScore = arr.get(1).getAsFloat();
                            }
                        }

                        newData.add(new StringData(
                                extractedValue,
                                hash,
                                matchScore,
                                resultsScore,
                                entropy
                        ));
                    }
                    monitor.setProgress(100);

                    SwingUtilities.invokeLater(() -> {
                        sscpFinal.setLastOutputDir(outputDirFinal);
                        sscpFinal.clearStrings();
                        sscpFinal.clearResults();
                        for (StringData sd : newData) {
                            sscpFinal.addString(sd);
                        }
                        sscpFinal.applyDefaultSort();
                    });
                } catch (Exception e) {
                    SwingUtilities.invokeLater(() ->
                            Msg.showError(SearchForStringsAction.this, null, "Pipeline Error", e.getMessage(), e)
                    );
                }
            }
        };

        sscpFinal.clearStrings();
        sscpFinal.clearResults();
        new TaskLauncher(task, sscpFinal.getComponent());
    }

    @Override
    public boolean isEnabledForContext(ActionContext context) {
        return context != null && context.getComponentProvider() instanceof StringSniperComponentProvider;
    }

    private static Map<String, Address> exportStringsRaw(Program program, Path outputDir) throws IOException {
        Map<String, Address> addressMap = new HashMap<>();
        JsonObject root = new JsonObject();
        root.addProperty("program", program.getName());
        root.addProperty("language", program.getLanguageID().toString());
        JsonArray strings = new JsonArray();

        for (Data d : program.getListing().getDefinedData(true)) {
            if (!d.hasStringValue()) {
                continue;
            }
            String value = null;
            try {
                StringDataInstance sdi = StringDataInstance.getStringDataInstance(d);
                if (sdi != null) {
                    value = sdi.getStringValue();
                }
            } catch (Exception ignored) {
            }
            if (value == null) {
                Object v = d.getValue();
                if (v != null) {
                    value = v.toString();
                }
            }
            if (value == null || value.isEmpty()) {
                continue;
            }

            JsonObject entry = new JsonObject();
            entry.addProperty("value", value);
            entry.addProperty("address", d.getAddress().toString());
            strings.add(entry);

            addressMap.putIfAbsent(value, d.getAddress());
        }

        root.add("strings", strings);
        Path outPath = outputDir.resolve("strings_raw.json");
        Files.writeString(outPath, root.toString(), StandardCharsets.UTF_8);
        return addressMap;
    }

    private static void writeDecomps(Program program,
                                     Map<String, Address> addressMap,
                                     JsonObject resultsRoot,
                                     Path outputDir,
                                     TaskMonitor monitor,
                                     int baseProgress,
                                     int progressSpan) throws IOException, CancelledException {
        Path decompRoot = outputDir.resolve("GSS_decomps");
        Files.createDirectories(decompRoot);

        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(program);
        try {
            int total = Math.max(resultsRoot.size(), 1);
            int done = 0;
            for (String strValue : resultsRoot.keySet()) {
                monitor.checkCancelled();
                done++;
                int progress = baseProgress + (int) Math.round((progressSpan * (double) done) / total);
                if (progress > 99) {
                    progress = 99;
                }
                monitor.setProgress(progress);
                Address addr = addressMap.get(strValue);
                if (addr == null) {
                    continue;
                }
                JsonObject rObj = resultsRoot.getAsJsonObject(strValue);
                String hash = rObj.get("hash").getAsString();

                String decomp = decompileFunctionsReferencing(program, addr, ifc, monitor);
                if (decomp.isEmpty()) {
                    continue;
                }
                Path outDir = decompRoot.resolve(hash);
                Files.createDirectories(outDir);
                Files.writeString(outDir.resolve("decomp.txt"), decomp, StandardCharsets.UTF_8);
            }
        } finally {
            ifc.dispose();
        }
    }

    private static String decompileFunctionsReferencing(Program program,
                                                        Address target,
                                                        DecompInterface ifc,
                                                        TaskMonitor monitor) throws CancelledException {
        ReferenceManager rm = program.getReferenceManager();
        ReferenceIterator it = rm.getReferencesTo(target);

        Set<Address> seen = new HashSet<>();
        List<Function> funcs = new ArrayList<>();

        while (it.hasNext()) {
            monitor.checkCancelled();
            Reference ref = it.next();
            Address from = ref.getFromAddress();

            Function f = program.getFunctionManager().getFunctionContaining(from);
            if (f == null) {
                f = searchForFunctionByRefs(program, from, 0, 4, monitor);
            }
            if (f == null) {
                continue;
            }
            Address entry = f.getEntryPoint();
            if (seen.add(entry)) {
                funcs.add(f);
            }
        }

        if (funcs.isEmpty()) {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        for (Function f : funcs) {
            monitor.checkCancelled();
            DecompileResults res = ifc.decompileFunction(f, 30, monitor);
            if (res != null && res.decompileCompleted()) {
                sb.append(res.getDecompiledFunction().getC()).append("\n\n");
            }
        }
        return sb.toString();
    }

    private static Function searchForFunctionByRefs(Program program,
                                                    Address addr,
                                                    int depth,
                                                    int maxDepth,
                                                    TaskMonitor monitor) throws CancelledException {
        if (depth >= maxDepth) {
            return null;
        }
        ReferenceIterator it = program.getReferenceManager().getReferencesTo(addr);
        while (it.hasNext()) {
            monitor.checkCancelled();
            Address from = it.next().getFromAddress();
            Function f = program.getFunctionManager().getFunctionContaining(from);
            if (f != null) {
                return f;
            }
            f = searchForFunctionByRefs(program, from, depth + 1, maxDepth, monitor);
            if (f != null) {
                return f;
            }
        }
        return null;
    }

    private static void deleteDirectory(Path path) throws IOException {
        if (!Files.exists(path)) {
            return;
        }
        try (Stream<Path> walk = Files.walk(path)) {
            walk.sorted((a, b) -> b.compareTo(a)).forEach(p -> {
                try {
                    Files.deleteIfExists(p);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            });
        } catch (RuntimeException e) {
            if (e.getCause() instanceof IOException) {
                throw (IOException) e.getCause();
            }
            throw e;
        }
    }

    private static String buildBinaryId(String value) {
        String baseName = Paths.get(value).getFileName().toString();
        String hash = hashString(value);
        return baseName + "_" + hash.substring(0, 8);
    }

    private static String hashString(String value) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("MD5 not available", e);
        }
    }
}
