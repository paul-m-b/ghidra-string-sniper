package ghidra_string_sniper;

import java.awt.Component;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import javax.swing.JOptionPane;
import javax.swing.BoxLayout;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.SwingUtilities;
import javax.swing.JTextArea;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.PluginTool;
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
    private static final float INTERESTING_REPO_MATCH_THRESHOLD = 7.4f;
    private static final int INTERESTING_REPO_CONF_THRESHOLD = 6;
    private static final int INTERESTING_REPO_MIN_MATCHES = 4;
    private static final String INTERESTING_REPOS_DIR = "Interesting_repos";

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
                AtomicReference<BufferedWriter> logWriterRef = new AtomicReference<>();
                PluginTool tool = sscpFinal.getPluginTool();
                final ConsoleService consoleService =
                        tool != null ? tool.getService(ConsoleService.class) : null;
                try {
                    monitor.initialize(100);
                    monitor.setProgress(0);
                    monitor.setMessage("Preparing output...");
                    if (Files.exists(outputDirFinal)) {
                        deleteDirectory(outputDirFinal);
                    }
                    Files.createDirectories(outputDirFinal);
                    Path logPath = outputDirFinal.resolve("pipeline.log");
                    logWriterRef.set(Files.newBufferedWriter(
                            logPath,
                            StandardCharsets.UTF_8,
                            StandardOpenOption.CREATE,
                            StandardOpenOption.APPEND
                    ));
                    logLine(logWriterRef.get(), consoleService, "Pipeline start: " + programFinal.getName());
                    logLine(logWriterRef.get(), consoleService, "Output directory: " + outputDirFinal);
                    monitor.setProgress(5);

                    monitor.setMessage("Exporting strings...");
                    logLine(logWriterRef.get(), consoleService, "Exporting strings...");
                    Map<String, Address> addressMap = exportStringsRaw(programFinal, outputDirFinal);
                    logLine(logWriterRef.get(), consoleService, "Exported strings: " + addressMap.size());
                    monitor.setProgress(15);

                    monitor.setMessage("Ranking strings (LLM)...");
                    logLine(logWriterRef.get(), consoleService, "Ranking strings (LLM)...");
                    List<String> rankArgs = new ArrayList<>();
                    rankArgs.add("--strings");
                    rankArgs.add(outputDirFinal.resolve("strings_raw.json").toString());
                    rankArgs.add("--out");
                    rankArgs.add(outputDirFinal.toString());
                    if (keyPath != null && !keyPath.isBlank()) {
                        rankArgs.add("--token");
                        rankArgs.add(keyPath);
                    }
                    Consumer<String> pythonLog = line -> logLine(logWriterRef.get(), consoleService, "[PY] " + line);
                    PythonRunner.RunResult rankResult = PythonRunner.runSystemPython(
                            "python",
                            "extension_interface/rank_strings.py",
                            rankArgs,
                            0,
                            pythonLog
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
                    logLine(logWriterRef.get(), consoleService, "results.json: " + resultsFile.getAbsolutePath());

                    JsonObject resultsRoot =
                            JsonParser.parseString(Files.readString(resultsFile.toPath())).getAsJsonObject();

                    monitor.setMessage("Decompiling referenced functions...");
                    logLine(logWriterRef.get(), consoleService, "Decompiling referenced functions...");
                    writeDecomps(programFinal, addressMap, resultsRoot, outputDirFinal, monitor, 35, 40);
                    monitor.setProgress(75);

                    monitor.setMessage("Sourcegraph + function match...");
                    logLine(logWriterRef.get(), consoleService, "Sourcegraph + function match...");
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
                            0,
                            pythonLog
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
                    logLine(logWriterRef.get(), consoleService, "MATCHES.json: " + matchesFile.getAbsolutePath());

                    JsonObject matchesRoot =
                            JsonParser.parseString(Files.readString(matchesFile.toPath())).getAsJsonObject();

                    List<StringData> newData = new ArrayList<>();
                    Map<String, RepoAggregate> repoAggregates = new HashMap<>();
                    for (String extractedValue : resultsRoot.keySet()) {
                        JsonObject rObj = resultsRoot.getAsJsonObject(extractedValue);

                        int resultsScore = rObj.get("confidence").getAsInt();
                        float entropy = rObj.get("entropy").getAsFloat();
                        String hash = rObj.get("hash").getAsString();

                        Float matchScore = null;
                        String matchPath = null;
                        if (matchesRoot.has(hash)) {
                            JsonArray arr = matchesRoot.getAsJsonArray(hash);
                            if (arr.size() > 1) {
                                matchScore = arr.get(1).getAsFloat();
                            }
                            if (arr.size() > 0 && !arr.get(0).isJsonNull()) {
                                matchPath = arr.get(0).getAsString();
                            }
                        }

                        StringData sd = new StringData(
                                extractedValue,
                                hash,
                                matchScore,
                                resultsScore,
                                entropy
                        );
                        sd.matchPath = matchPath;
                        newData.add(sd);

                        if (matchScore != null &&
                                matchScore >= INTERESTING_REPO_MATCH_THRESHOLD &&
                                resultsScore >= INTERESTING_REPO_CONF_THRESHOLD &&
                                matchPath != null &&
                                !matchPath.isBlank()) {
                            RepoMatchMeta repoMatchMeta = readRepoMatchMeta(matchPath);
                            if (repoMatchMeta != null) {
                                RepoAggregate agg = repoAggregates.computeIfAbsent(
                                        repoMatchMeta.repoKey,
                                        key -> new RepoAggregate(
                                                repoMatchMeta.repoDisplayName,
                                                repoMatchMeta.repoUrl,
                                                repoMatchMeta.cloneUrl
                                        )
                                );
                                agg.addHit(hash, matchScore, resultsScore, extractedValue);
                                if ((agg.repoUrl == null || agg.repoUrl.isBlank()) &&
                                        repoMatchMeta.repoUrl != null && !repoMatchMeta.repoUrl.isBlank()) {
                                    agg.repoUrl = repoMatchMeta.repoUrl;
                                }
                                if ((agg.cloneUrl == null || agg.cloneUrl.isBlank()) &&
                                        repoMatchMeta.cloneUrl != null && !repoMatchMeta.cloneUrl.isBlank()) {
                                    agg.cloneUrl = repoMatchMeta.cloneUrl;
                                }
                            }
                        }
                    }

                    Map<String, RepoAggregate> interestingRepos = selectInterestingRepos(repoAggregates);
                    Map<String, CloneExecutionResult> cloneResults = cloneInterestingRepos(
                            outputDirFinal,
                            interestingRepos,
                            logWriterRef.get(),
                            consoleService
                    );
                    Path summaryPath = writeInterestingReposSummary(outputDirFinal, interestingRepos, cloneResults);
                    InterestingReposAlert interestingReposAlert =
                            buildInterestingReposAlert(interestingRepos, cloneResults, summaryPath);
                    List<StringSniperComponentProvider.RepoData> repoTabRows =
                            buildRepoTabData(interestingRepos, cloneResults);

                    logLine(
                            logWriterRef.get(),
                            consoleService,
                            "Interesting repo summary: " + summaryPath + " (" + interestingRepos.size() + " repo(s))"
                    );
                    monitor.setProgress(100);

                    SwingUtilities.invokeLater(() -> {
                        sscpFinal.setLastOutputDir(outputDirFinal);
                        sscpFinal.clearStrings();
                        sscpFinal.clearResults();
                        for (StringData sd : newData) {
                            sscpFinal.addString(sd);
                        }
                        sscpFinal.applyDefaultSort();
                        sscpFinal.setInterestingRepos(repoTabRows);
                        showInterestingReposAlert(sscpFinal.getComponent(), interestingReposAlert);
                    });
                    logLine(logWriterRef.get(), consoleService, "Pipeline completed.");
                } catch (Exception e) {
                    logLine(logWriterRef.get(), consoleService, "Pipeline error: " + e.getMessage());
                    SwingUtilities.invokeLater(() ->
                            Msg.showError(SearchForStringsAction.this, null, "Pipeline Error", e.getMessage(), e)
                    );
                } finally {
                    BufferedWriter logWriter = logWriterRef.get();
                    if (logWriter != null) {
                        try {
                            logWriter.flush();
                            logWriter.close();
                        } catch (IOException ignored) {
                        }
                    }
                }
            }
        };

        sscpFinal.clearStrings();
        sscpFinal.clearResults();
        sscpFinal.clearRepos();
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

    private static RepoMatchMeta readRepoMatchMeta(String matchPath) {
        Path matchFile;
        try {
            matchFile = Path.of(matchPath);
        } catch (RuntimeException e) {
            return null;
        }
        if (!Files.exists(matchFile)) {
            return null;
        }

        String repo = null;
        String repoUrl = null;
        try (BufferedReader reader = Files.newBufferedReader(matchFile, StandardCharsets.UTF_8)) {
            String line;
            int linesRead = 0;
            while ((line = reader.readLine()) != null && linesRead < 50) {
                linesRead++;
                if (line.startsWith("repo: ")) {
                    repo = line.substring("repo: ".length()).trim();
                } else if (line.startsWith("repo_url: ")) {
                    repoUrl = line.substring("repo_url: ".length()).trim();
                }
                if (repo != null && !repo.isBlank() && repoUrl != null && !repoUrl.isBlank()) {
                    break;
                }
            }
        } catch (IOException e) {
            return null;
        }

        String repoPath = extractRepoPath(repo, repoUrl);
        if (repoPath == null || repoPath.isBlank()) {
            return null;
        }

        String normalizedUrl = normalizeSourcegraphUrl(repoUrl);
        if (normalizedUrl == null || normalizedUrl.isBlank()) {
            normalizedUrl = "https://sourcegraph.com/" + repoPath;
        }
        String repoKey;
        if (repo != null && !repo.isBlank()) {
            repoKey = stripGitSuffix(repo.trim());
            if (repoKey.startsWith("/")) {
                repoKey = repoKey.substring(1);
            }
        } else {
            repoKey = repoPath;
        }
        String cloneUrl = "https://" + repoPath + ".git";
        String repoDisplayName = repoKey;
        return new RepoMatchMeta(repoKey, repoDisplayName, normalizedUrl, cloneUrl);
    }

    private static Map<String, RepoAggregate> selectInterestingRepos(Map<String, RepoAggregate> repoAggregates) {
        List<Map.Entry<String, RepoAggregate>> entries = new ArrayList<>(repoAggregates.entrySet());
        entries.sort((a, b) -> {
            RepoAggregate left = a.getValue();
            RepoAggregate right = b.getValue();
            int byCount = Integer.compare(right.count, left.count);
            if (byCount != 0) {
                return byCount;
            }
            int byScore = Double.compare(right.averageMatchScore(), left.averageMatchScore());
            if (byScore != 0) {
                return byScore;
            }
            return a.getKey().compareTo(b.getKey());
        });

        Map<String, RepoAggregate> selected = new LinkedHashMap<>();
        for (Map.Entry<String, RepoAggregate> entry : entries) {
            RepoAggregate aggregate = entry.getValue();
            if (aggregate.count < INTERESTING_REPO_MIN_MATCHES) {
                continue;
            }
            if (aggregate.strongHits() < INTERESTING_REPO_MIN_MATCHES) {
                continue;
            }
            selected.put(entry.getKey(), aggregate);
        }
        return selected;
    }

    private static Map<String, CloneExecutionResult> cloneInterestingRepos(Path outputDir,
                                                                           Map<String, RepoAggregate> interestingRepos,
                                                                           BufferedWriter writer,
                                                                           ConsoleService consoleService) throws IOException {
        Map<String, CloneExecutionResult> cloneResults = new LinkedHashMap<>();
        Path reposDir = outputDir.resolve(INTERESTING_REPOS_DIR);
        Files.createDirectories(reposDir);

        for (Map.Entry<String, RepoAggregate> entry : interestingRepos.entrySet()) {
            String repoKey = entry.getKey();
            RepoAggregate aggregate = entry.getValue();

            String folderName = sanitizeRepoFolderName(repoKey);
            Path targetDir = reposDir.resolve(folderName);

            CloneExecutionResult result;
            if (Files.isDirectory(targetDir)) {
                result = new CloneExecutionResult(
                        "already_present",
                        targetDir.toString(),
                        aggregate.cloneUrl,
                        ""
                );
            } else if (aggregate.cloneUrl == null || aggregate.cloneUrl.isBlank()) {
                result = new CloneExecutionResult(
                        "missing_clone_url",
                        targetDir.toString(),
                        "",
                        ""
                );
            } else {
                result = cloneRepository(aggregate.cloneUrl, targetDir, outputDir);
            }
            cloneResults.put(repoKey, result);
            logLine(
                    writer,
                    consoleService,
                    "Interesting repo " + repoKey + " -> " + result.status + " (" + result.targetDir + ")"
            );
        }
        return cloneResults;
    }

    private static Path writeInterestingReposSummary(Path outputDir,
                                                     Map<String, RepoAggregate> interestingRepos,
                                                     Map<String, CloneExecutionResult> cloneResults) throws IOException {
        Path reposDir = outputDir.resolve(INTERESTING_REPOS_DIR);
        Files.createDirectories(reposDir);
        Path summaryPath = reposDir.resolve("interesting_repos.json");

        JsonObject root = new JsonObject();
        for (Map.Entry<String, RepoAggregate> entry : interestingRepos.entrySet()) {
            String repoKey = entry.getKey();
            RepoAggregate aggregate = entry.getValue();
            JsonObject repoObj = new JsonObject();
            repoObj.addProperty("match_count", aggregate.count);
            repoObj.addProperty("average_match_score", roundTo3(aggregate.averageMatchScore()));
            repoObj.addProperty("strong_hits", aggregate.strongHits());

            JsonArray confidences = new JsonArray();
            for (Integer confidence : aggregate.resultConfidences) {
                confidences.add(confidence);
            }
            repoObj.add("result_confidences", confidences);

            JsonArray hashes = new JsonArray();
            for (String hash : aggregate.hashes) {
                hashes.add(hash);
            }
            repoObj.add("hashes", hashes);

            JsonArray strings = new JsonArray();
            for (String value : aggregate.strings) {
                strings.add(value);
            }
            repoObj.add("strings", strings);

            if (aggregate.repoUrl == null || aggregate.repoUrl.isBlank()) {
                repoObj.add("repo_url", JsonNull.INSTANCE);
            } else {
                repoObj.addProperty("repo_url", aggregate.repoUrl);
            }

            if (aggregate.cloneUrl == null || aggregate.cloneUrl.isBlank()) {
                repoObj.add("clone_url", JsonNull.INSTANCE);
            } else {
                repoObj.addProperty("clone_url", aggregate.cloneUrl);
            }

            CloneExecutionResult cloneResult = cloneResults.get(repoKey);
            JsonObject cloneObj = new JsonObject();
            if (cloneResult == null) {
                cloneObj.addProperty("status", "missing_result");
                cloneObj.addProperty("target_dir", "");
                cloneObj.addProperty("clone_url", aggregate.cloneUrl == null ? "" : aggregate.cloneUrl);
            } else {
                cloneObj.addProperty("status", cloneResult.status);
                cloneObj.addProperty("target_dir", cloneResult.targetDir);
                cloneObj.addProperty("clone_url", cloneResult.cloneUrl == null ? "" : cloneResult.cloneUrl);
                if (cloneResult.stderr != null && !cloneResult.stderr.isBlank()) {
                    cloneObj.addProperty("stderr", cloneResult.stderr);
                }
            }
            repoObj.add("clone", cloneObj);
            root.add(repoKey, repoObj);
        }
        String json = new GsonBuilder().setPrettyPrinting().create().toJson(root);
        Files.writeString(summaryPath, json, StandardCharsets.UTF_8);
        return summaryPath;
    }

    private static InterestingReposAlert buildInterestingReposAlert(Map<String, RepoAggregate> interestingRepos,
                                                                    Map<String, CloneExecutionResult> cloneResults,
                                                                    Path summaryPath) {
        if (interestingRepos.isEmpty()) {
            return null;
        }

        int clonedCount = 0;
        int alreadyPresentCount = 0;
        int failedCount = 0;
        List<String> details = new ArrayList<>();

        for (Map.Entry<String, RepoAggregate> entry : interestingRepos.entrySet()) {
            String repoKey = entry.getKey();
            RepoAggregate aggregate = entry.getValue();
            CloneExecutionResult cloneResult = cloneResults.get(repoKey);
            String status = cloneResult == null ? "missing_result" : cloneResult.status;

            if ("cloned".equals(status)) {
                clonedCount++;
            } else if ("already_present".equals(status)) {
                alreadyPresentCount++;
            } else {
                failedCount++;
            }

            details.add(
                    repoKey + " (" + aggregate.count + " hits, avg " +
                            String.format("%.2f", aggregate.averageMatchScore()) + "): " + status
            );
        }

        return new InterestingReposAlert(
                summaryPath,
                interestingRepos.size(),
                clonedCount,
                alreadyPresentCount,
                failedCount,
                details
        );
    }

    private static List<StringSniperComponentProvider.RepoData> buildRepoTabData(
            Map<String, RepoAggregate> interestingRepos,
            Map<String, CloneExecutionResult> cloneResults) {
        List<StringSniperComponentProvider.RepoData> rows = new ArrayList<>();
        for (Map.Entry<String, RepoAggregate> entry : interestingRepos.entrySet()) {
            String repoKey = entry.getKey();
            RepoAggregate aggregate = entry.getValue();
            CloneExecutionResult cloneResult = cloneResults.get(repoKey);
            String cloneStatus = cloneResult == null ? "missing_result" : cloneResult.status;
            String targetDir = cloneResult == null ? "" : cloneResult.targetDir;

            rows.add(new StringSniperComponentProvider.RepoData(
                    repoKey,
                    toGitHubUrl(aggregate.cloneUrl),
                    cloneStatus,
                    targetDir,
                    aggregate.count,
                    aggregate.averageMatchScore(),
                    aggregate.strongHits(),
                    new ArrayList<>(aggregate.strings)
            ));
        }
        return rows;
    }

    private static String toGitHubUrl(String cloneUrl) {
        if (cloneUrl == null || cloneUrl.isBlank()) {
            return "";
        }
        String out = cloneUrl.trim();
        if (out.endsWith(".git")) {
            out = out.substring(0, out.length() - 4);
        }
        return out;
    }

    private static void showInterestingReposAlert(Component parent, InterestingReposAlert alert) {
        if (alert == null) {
            return;
        }

        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.add(new JLabel("Interesting repositories detected and processed."));
        panel.add(new JLabel("Total: " + alert.totalRepos +
                ", cloned: " + alert.clonedCount +
                ", already present: " + alert.alreadyPresentCount +
                ", failed: " + alert.failedCount));
        panel.add(new JLabel("Summary written to: " + alert.summaryPath));

        JTextArea details = new JTextArea(String.join(System.lineSeparator(), alert.details));
        details.setEditable(false);
        details.setLineWrap(true);
        details.setWrapStyleWord(true);
        JScrollPane detailsScroll = new JScrollPane(details);
        detailsScroll.setPreferredSize(new java.awt.Dimension(760, 220));
        panel.add(detailsScroll);

        JOptionPane.showMessageDialog(parent, panel, "Interesting Repositories", JOptionPane.INFORMATION_MESSAGE);
    }

    private static CloneExecutionResult cloneRepository(String cloneUrl, Path targetDir, Path workingDir) {
        List<String> cmd = List.of(
                "git",
                "clone",
                "--depth",
                "1",
                cloneUrl,
                targetDir.toString()
        );
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.directory(workingDir.toFile());
        pb.redirectErrorStream(true);

        StringBuilder output = new StringBuilder();
        try {
            Process process = pb.start();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append(System.lineSeparator());
                }
            }
            int exit = process.waitFor();
            if (exit == 0) {
                return new CloneExecutionResult("cloned", targetDir.toString(), cloneUrl, "");
            }
            return new CloneExecutionResult("clone_failed", targetDir.toString(), cloneUrl, output.toString().trim());
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            return new CloneExecutionResult("clone_failed", targetDir.toString(), cloneUrl, e.getMessage());
        }
    }

    private static String extractRepoPath(String repo, String repoUrl) {
        if (repo != null && !repo.isBlank()) {
            String cleaned = repo.trim();
            if (cleaned.startsWith("/")) {
                cleaned = cleaned.substring(1);
            }
            if (!cleaned.isBlank()) {
                return stripGitSuffix(cleaned);
            }
        }

        String normalized = normalizeSourcegraphUrl(repoUrl);
        if (normalized == null || normalized.isBlank()) {
            return null;
        }
        try {
            java.net.URI uri = java.net.URI.create(normalized);
            String path = uri.getPath();
            if (path == null || path.isBlank()) {
                return null;
            }
            if (path.startsWith("/")) {
                path = path.substring(1);
            }
            int blobIdx = path.indexOf("/-/");
            if (blobIdx > 0) {
                path = path.substring(0, blobIdx);
            }
            return stripGitSuffix(path);
        } catch (Exception e) {
            return null;
        }
    }

    private static String stripGitSuffix(String value) {
        if (value == null) {
            return "";
        }
        String out = value.trim();
        while (out.endsWith("/")) {
            out = out.substring(0, out.length() - 1);
        }
        if (out.endsWith(".git")) {
            out = out.substring(0, out.length() - 4);
        }
        return out;
    }

    private static String sanitizeRepoFolderName(String repoName) {
        if (repoName == null || repoName.isBlank()) {
            return "unknown_repo";
        }
        String folder = repoName.replace("/", "__").replace("\\", "__");
        return folder.replaceAll("[\\\\/:*?\"<>|]", "_");
    }

    private static double roundTo3(double value) {
        return Math.round(value * 1000.0) / 1000.0;
    }

    private static String normalizeSourcegraphUrl(String url) {
        if (url == null || url.isBlank()) {
            return null;
        }
        String trimmed = url.trim();
        if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
            return trimmed;
        }
        if (trimmed.startsWith("/")) {
            return "https://sourcegraph.com" + trimmed;
        }
        return trimmed;
    }

    private static final class RepoMatchMeta {
        final String repoKey;
        final String repoDisplayName;
        final String repoUrl;
        final String cloneUrl;

        RepoMatchMeta(String repoKey, String repoDisplayName, String repoUrl, String cloneUrl) {
            this.repoKey = repoKey;
            this.repoDisplayName = repoDisplayName;
            this.repoUrl = repoUrl;
            this.cloneUrl = cloneUrl;
        }
    }

    private static final class RepoAggregate {
        final String repoDisplayName;
        String repoUrl;
        String cloneUrl;
        int count;
        float scoreSum;
        final List<Integer> resultConfidences = new ArrayList<>();
        final List<String> hashes = new ArrayList<>();
        final Set<String> strings = new LinkedHashSet<>();

        RepoAggregate(String repoDisplayName, String repoUrl, String cloneUrl) {
            this.repoDisplayName = repoDisplayName;
            this.repoUrl = repoUrl;
            this.cloneUrl = cloneUrl;
            this.count = 0;
            this.scoreSum = 0.0f;
        }

        void addHit(String hash, float score, int resultConfidence, String stringValue) {
            count++;
            scoreSum += score;
            resultConfidences.add(resultConfidence);
            hashes.add(hash);
            if (stringValue != null && !stringValue.isBlank()) {
                strings.add(stringValue);
            }
        }

        float averageMatchScore() {
            if (count == 0) {
                return 0.0f;
            }
            return scoreSum / count;
        }

        int strongHits() {
            int hits = 0;
            for (Integer confidence : resultConfidences) {
                if (confidence != null && confidence >= INTERESTING_REPO_CONF_THRESHOLD) {
                    hits++;
                }
            }
            return hits;
        }
    }

    private static final class CloneExecutionResult {
        final String status;
        final String targetDir;
        final String cloneUrl;
        final String stderr;

        CloneExecutionResult(String status, String targetDir, String cloneUrl, String stderr) {
            this.status = status;
            this.targetDir = targetDir;
            this.cloneUrl = cloneUrl;
            this.stderr = stderr;
        }
    }

    private static final class InterestingReposAlert {
        final Path summaryPath;
        final int totalRepos;
        final int clonedCount;
        final int alreadyPresentCount;
        final int failedCount;
        final List<String> details;

        InterestingReposAlert(Path summaryPath,
                              int totalRepos,
                              int clonedCount,
                              int alreadyPresentCount,
                              int failedCount,
                              List<String> details) {
            this.summaryPath = summaryPath;
            this.totalRepos = totalRepos;
            this.clonedCount = clonedCount;
            this.alreadyPresentCount = alreadyPresentCount;
            this.failedCount = failedCount;
            this.details = details;
        }
    }

    private static void deleteDirectory(Path path) throws IOException {
        if (!Files.exists(path)) {
            return;
        }
        try (Stream<Path> walk = Files.walk(path)) {
            walk.sorted((a, b) -> b.compareTo(a)).forEach(p -> {
                try {
                    java.io.File f = p.toFile();
                    if (!f.canWrite()) {
                        f.setWritable(true);
                    }
                    try {
                        Files.setAttribute(p, "dos:readonly", false);
                    } catch (Exception ignored) {
                        // ignore non-Windows filesystems and unsupported attributes
                    }
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

    private static void logLine(BufferedWriter writer, ConsoleService consoleService, String message) {
        String ts = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
        String line = "[" + ts + "] " + message;
        Msg.info(SearchForStringsAction.class, line);
        if (consoleService != null) {
            consoleService.println("StringSniper> " + line);
        } else {
            System.out.println(line);
        }
        if (writer == null) {
            return;
        }
        try {
            writer.write(line);
            writer.newLine();
            writer.flush();
        } catch (IOException ignored) {
        }
    }
}
