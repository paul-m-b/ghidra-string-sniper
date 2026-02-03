package ghidra_string_sniper;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;

import com.google.gson.JsonObject;
import com.google.gson.JsonArray;
import com.google.gson.JsonParser;

import resources.Icons;

public class SearchForStringsAction extends DockingAction {

    public SearchForStringsAction(StringSniperComponentProvider provider, String owner) {
        super("Search For Strings", owner);
        setToolBarData(new ToolBarData(Icons.REFRESH_ICON));
    }

    @Override
    public void actionPerformed(ActionContext context) {
        String tokenValue = JOptionPane.showInputDialog(
                "Enter your Openrouter API key here:", "EnterValue"
        );
        if (tokenValue == null || tokenValue.trim().isEmpty()) {
            Msg.showWarn(this, null, "Missing API Key", "API key is required to run the pipeline.");
            return;
        }

        try {
            File keyFile = File.createTempFile("SniperKey", ".txt");
            keyFile.deleteOnExit();
            try (FileWriter writer = new FileWriter(keyFile)) {
                writer.write(tokenValue);
            }
            System.setProperty("StringSniperKeyFile", keyFile.getAbsolutePath());
        } catch (IOException e) {
            Msg.showError(this, null, "Key File Error", "Failed to write API key: " + e.getMessage());
            return;
        }

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

        String binaryPath = program.getExecutablePath();
        if (binaryPath == null || binaryPath.trim().isEmpty()) {
            JFileChooser chooser = new JFileChooser();
            chooser.setDialogTitle("Select binary file");
            if (chooser.showOpenDialog(null) != JFileChooser.APPROVE_OPTION) {
                return;
            }
            binaryPath = chooser.getSelectedFile().getAbsolutePath();
        }
        if (binaryPath.startsWith("/") &&
                binaryPath.length() > 3 &&
                Character.isLetter(binaryPath.charAt(1)) &&
                binaryPath.charAt(2) == ':') {
            binaryPath = binaryPath.substring(1);
        }
        try {
            binaryPath = Paths.get(binaryPath).toAbsolutePath().toString();
        } catch (Exception e) {
            Msg.showError(this, null, "Invalid Path", "Binary path must be absolute. Got: " + binaryPath);
            return;
        }
        if (!Files.exists(Paths.get(binaryPath))) {
            JFileChooser chooser = new JFileChooser();
            chooser.setDialogTitle("Binary not found. Select binary file");
            if (chooser.showOpenDialog(null) != JFileChooser.APPROVE_OPTION) {
                Msg.showError(this, null, "File Not Found", "Binary path does not exist: " + binaryPath);
                return;
            }
            binaryPath = chooser.getSelectedFile().getAbsolutePath();
        }

        final String binaryPathFinal = binaryPath;
        final Program programFinal = program;
        final StringSniperComponentProvider sscpFinal = sscp;
        final String keyPath = System.getProperty("StringSniperKeyFile");

        Task task = new Task("Ghidra String Sniper Pipeline", true, true, true) {
            @Override
            public void run(TaskMonitor monitor) {
                try {
                    monitor.setMessage("Preparing pipeline...");
                    Path outputDir = Files.createTempDirectory("GSS_Run_");

                    monitor.setMessage("Checking pyghidra...");
                    PythonRunner.RunResult preflight = PythonRunner.runSystemPython(
                            "python",
                            "extension_interface/check_pyghidra.py",
                            new ArrayList<>(),
                            0
                    );
                    if (preflight == null || preflight.exitCode != 0) {
                        throw new IOException("pyghidra is required. Please install it in the Python environment used by Ghidra.");
                    }

                    List<String> args = new ArrayList<>();
                    args.add("--binary");
                    args.add(binaryPathFinal);
                    args.add("--out");
                    args.add(outputDir.toString());
                    if (keyPath != null && !keyPath.isBlank()) {
                        args.add("--token");
                        args.add(keyPath);
                    }
                    if (programFinal.getLanguageID() != null) {
                        args.add("--language");
                        args.add(programFinal.getLanguageID().toString());
                    }

                    monitor.setMessage("Running Python pipeline...");
                    PythonRunner.RunResult result = PythonRunner.runSystemPython(
                            "python",
                            "extension_interface/run_pipeline.py",
                            args,
                            0
                    );

                    if (result == null) {
                        throw new IOException("Python pipeline timed out or failed to start.");
                    }
                    if (result.exitCode != 0) {
                        throw new IOException("Python pipeline failed:\n" + result.stdout);
                    }

                    File resultsFile = outputDir.resolve("results.json").toFile();
                    File matchesFile = outputDir.resolve("MATCHES.json").toFile();

                    if (!resultsFile.exists()) {
                        throw new IOException("results.json not found: " + resultsFile.getAbsolutePath());
                    }
                    if (!matchesFile.exists()) {
                        throw new IOException("MATCHES.json not found: " + matchesFile.getAbsolutePath());
                    }

                    JsonObject resultsRoot =
                            JsonParser.parseString(Files.readString(resultsFile.toPath())).getAsJsonObject();
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

                    SwingUtilities.invokeLater(() -> {
                        sscpFinal.setLastOutputDir(outputDir);
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
}
