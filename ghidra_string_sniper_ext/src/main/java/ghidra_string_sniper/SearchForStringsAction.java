package ghidra_string_sniper;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.util.List;

import javax.swing.JOptionPane;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.util.Msg;

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

        // ---- API KEY code unchanged ----
        String tokenValue = JOptionPane.showInputDialog(
                "Enter your Openrouter API key here:", "EnterValue"
        );

        try {
            File keyFile = File.createTempFile("SniperKey", ".txt");
            keyFile.deleteOnExit();
            try (FileWriter writer = new FileWriter(keyFile)) {
                writer.write(tokenValue);
            }
            System.setProperty("StringSniperKeyFile", keyFile.getAbsolutePath());
        } catch (IOException e) {
            Msg.showError(this, null, "Key File Error", "Failed to write API key: " + e.getMessage());
        }

        ComponentProvider cp = context.getComponentProvider();
        if (!(cp instanceof StringSniperComponentProvider)) {
            return;
        }

        StringSniperComponentProvider sscp = (StringSniperComponentProvider) cp;
        sscp.clearStrings();

        try {
            String tmpDir = System.getProperty("java.io.tmpdir");

            // *** Get results.json ***
            File resultsDir = new File(tmpDir, "GSS_Results");
            File resultsFile = new File(resultsDir, "results.json");

            if (!resultsFile.exists()) {
                throw new IOException("results.json not found: " + resultsFile.getAbsolutePath());
            }

            String resultsText = Files.readString(resultsFile.toPath());
            JsonObject resultsRoot = JsonParser.parseString(resultsText).getAsJsonObject();


            // *** Get MATCHES.json (has confidence scores) ***
            File matchesDir = new File(tmpDir, "GSS_matches");
            File matchesFile = new File(matchesDir, "MATCHES.json");

            if (!matchesFile.exists()) {
                throw new IOException("MATCHES.json not found: " + matchesFile.getAbsolutePath());
            }

            String matchesText = Files.readString(matchesFile.toPath());
            JsonObject matchesRoot = JsonParser.parseString(matchesText).getAsJsonObject();


            // ==== MERGE PHASE ====
            for (String extractedValue : resultsRoot.keySet()) {

                JsonObject valObj = resultsRoot.getAsJsonObject(extractedValue);

                // hash from results.json
                String hash = valObj.has("hash") ? valObj.get("hash").getAsString() : null;

                if (hash == null) {
                    Msg.showWarn(this, null, "Missing Hash", "No hash for: " + extractedValue);
                    continue;
                }

                // get confidence from MATCHES.json
                float floatValue = 0.0f;

                if (matchesRoot.has(hash)) {
                    JsonArray arr = matchesRoot.getAsJsonArray(hash);
                    if (arr.size() > 1) {
                        floatValue = arr.get(1).getAsFloat();
                    }
                } else {
                    Msg.showWarn(this, null, "Missing Score", "No MATCHES.json entry for hash: " + hash);
                }

                // Add to the UI table
                sscp.addString(new StringData(extractedValue, hash, floatValue));
            }

            sscp.applyDefaultSort();

        } catch (Exception e) {
            Msg.showError(this, null, "Error loading data", e.toString());
        }
}

    @Override
    public boolean isEnabledForContext(ActionContext context) {
        return context != null && context.getComponentProvider() instanceof StringSniperComponentProvider;
    }
}
