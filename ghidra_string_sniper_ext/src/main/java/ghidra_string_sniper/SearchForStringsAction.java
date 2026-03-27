package ghidra_string_sniper;

import java.awt.Component;
import java.awt.Desktop;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.net.URI;
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
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import javax.swing.JOptionPane;
import javax.swing.BoxLayout;
import javax.swing.JEditorPane;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import javax.swing.event.HyperlinkEvent;

import com.google.gson.JsonArray;
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
    private static final float OPEN_SOURCE_ALERT_SCORE_THRESHOLD = 7.4f;
    private static final int OPEN_SOURCE_ALERT_MIN_STRINGS = 4;

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

                        if (matchScore != null && matchScore > OPEN_SOURCE_ALERT_SCORE_THRESHOLD &&
                                matchPath != null && !matchPath.isBlank()) {
                            RepoMatchMeta repoMatchMeta = readRepoMatchMeta(matchPath);
                            if (repoMatchMeta != null) {
                                RepoAggregate agg = repoAggregates.computeIfAbsent(
                                        repoMatchMeta.repoKey,
                                        key -> new RepoAggregate(repoMatchMeta.repoDisplayName, repoMatchMeta.repoUrl)
                                );
                                agg.addScore(matchScore);
                                if ((agg.repoUrl == null || agg.repoUrl.isBlank()) &&
                                        repoMatchMeta.repoUrl != null && !repoMatchMeta.repoUrl.isBlank()) {
                                    agg.repoUrl = repoMatchMeta.repoUrl;
                                }
                            }
                        }
                    }
                    OpenSourceAlertCandidate alertCandidate = pickOpenSourceAlertCandidate(repoAggregates);
                    monitor.setProgress(100);

                    SwingUtilities.invokeLater(() -> {
                        sscpFinal.setLastOutputDir(outputDirFinal);
                        sscpFinal.clearStrings();
                        sscpFinal.clearResults();
                        for (StringData sd : newData) {
                            sscpFinal.addString(sd);
                        }
                        sscpFinal.applyDefaultSort();
                        showOpenSourceAlert(sscpFinal.getComponent(), alertCandidate);
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

        String repoKey = null;
        if (repo != null && !repo.isBlank()) {
            repoKey = repo;
        } else if (repoUrl != null && !repoUrl.isBlank()) {
            repoKey = normalizeSourcegraphUrl(repoUrl);
        }
        if (repoKey == null || repoKey.isBlank()) {
            return null;
        }

        String normalizedUrl = normalizeSourcegraphUrl(repoUrl);
        if ((normalizedUrl == null || normalizedUrl.isBlank()) && repo != null && !repo.isBlank()) {
            normalizedUrl = "https://sourcegraph.com/" + repo;
        }
        String repoDisplayName = (repo != null && !repo.isBlank()) ? repo : repoKey;
        return new RepoMatchMeta(repoKey, repoDisplayName, normalizedUrl);
    }

    private static OpenSourceAlertCandidate pickOpenSourceAlertCandidate(Map<String, RepoAggregate> repoAggregates) {
        OpenSourceAlertCandidate best = null;
        for (RepoAggregate aggregate : repoAggregates.values()) {
            if (aggregate.count < OPEN_SOURCE_ALERT_MIN_STRINGS) {
                continue;
            }
            float avgScore = aggregate.scoreSum / aggregate.count;
            if (best == null ||
                    aggregate.count > best.count ||
                    (aggregate.count == best.count && avgScore > best.averageScore)) {
                best = new OpenSourceAlertCandidate(
                        aggregate.repoDisplayName,
                        aggregate.repoUrl,
                        aggregate.count,
                        avgScore
                );
            }
        }
        return best;
    }

    private static void showOpenSourceAlert(Component parent, OpenSourceAlertCandidate candidate) {
        if (candidate == null) {
            return;
        }
        String link = (candidate.repoUrl != null && !candidate.repoUrl.isBlank())
                ? candidate.repoUrl
                : candidate.repoDisplayName;
        String safeLink = escapeHtml(link);

        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.add(new JLabel("Likely open-source file detected."));
        panel.add(new JLabel(candidate.count + " strings scored above " +
                OPEN_SOURCE_ALERT_SCORE_THRESHOLD + " from the same repository."));
        panel.add(new JLabel("Repository: " + candidate.repoDisplayName));

        JEditorPane linkPane = new JEditorPane(
                "text/html",
                "<html>Repo link: <a href=\"" + safeLink + "\">" + safeLink + "</a></html>"
        );
        linkPane.setEditable(false);
        linkPane.setOpaque(false);
        linkPane.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
        linkPane.addHyperlinkListener(e -> {
            if (e.getEventType() != HyperlinkEvent.EventType.ACTIVATED) {
                return;
            }
            try {
                if (Desktop.isDesktopSupported()) {
                    Desktop.getDesktop().browse(new URI(e.getURL().toString()));
                }
            } catch (Exception ex) {
                Msg.showError(SearchForStringsAction.class, parent,
                        "Failed to open URL", ex.getMessage(), ex);
            }
        });
        panel.add(linkPane);

        JOptionPane.showMessageDialog(parent, panel, "Likely Open-Source Match", JOptionPane.INFORMATION_MESSAGE);
    }

    private static String escapeHtml(String value) {
        if (value == null) {
            return "";
        }
        return value
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;");
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

        RepoMatchMeta(String repoKey, String repoDisplayName, String repoUrl) {
            this.repoKey = repoKey;
            this.repoDisplayName = repoDisplayName;
            this.repoUrl = repoUrl;
        }
    }

    private static final class RepoAggregate {
        final String repoDisplayName;
        String repoUrl;
        int count;
        float scoreSum;

        RepoAggregate(String repoDisplayName, String repoUrl) {
            this.repoDisplayName = repoDisplayName;
            this.repoUrl = repoUrl;
            this.count = 0;
            this.scoreSum = 0.0f;
        }

        void addScore(float score) {
            count++;
            scoreSum += score;
        }
    }

    private static final class OpenSourceAlertCandidate {
        final String repoDisplayName;
        final String repoUrl;
        final int count;
        final float averageScore;

        OpenSourceAlertCandidate(String repoDisplayName, String repoUrl, int count, float averageScore) {
            this.repoDisplayName = repoDisplayName;
            this.repoUrl = repoUrl;
            this.count = count;
            this.averageScore = averageScore;
        }
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
