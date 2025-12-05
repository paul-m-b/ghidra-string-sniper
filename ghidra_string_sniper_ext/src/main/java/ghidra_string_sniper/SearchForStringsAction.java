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

        // --- API KEY code unchanged ---
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

            // ------------------------------
            // LOAD results.json (entropy + resultsScore + hash)
            // ------------------------------
            File resultsDir = new File(tmpDir, "GSS_Results");
            File resultsFile = new File(resultsDir, "results.json");

            if (!resultsFile.exists()) {
                throw new IOException("results.json not found: " + resultsFile.getAbsolutePath());
            }

            JsonObject resultsRoot =
                    JsonParser.parseString(Files.readString(resultsFile.toPath())).getAsJsonObject();


            // ------------------------------
            // LOAD MATCHES.json (score)
            // ------------------------------
            File matchesDir = new File(tmpDir, "GSS_matches");
            File matchesFile = new File(matchesDir, "MATCHES.json");

            if (!matchesFile.exists()) {
                throw new IOException("MATCHES.json not found: " + matchesFile.getAbsolutePath());
            }

            JsonObject matchesRoot =
                    JsonParser.parseString(Files.readString(matchesFile.toPath())).getAsJsonObject();


            // ------------------------------
            // MERGE DATA AND ADD TO UI
            // ------------------------------
            for (String extractedValue : resultsRoot.keySet()) {

                JsonObject rObj = resultsRoot.getAsJsonObject(extractedValue);

                // Pull fields from results.json
                int resultsScore = rObj.get("confidence").getAsInt();
                float entropy = rObj.get("entropy").getAsFloat();
                String hash = rObj.get("hash").getAsString();

                // Try to get match confidence from MATCHES.json
                Float matchScore = null;

                if (matchesRoot.has(hash)) {
                    JsonArray arr = matchesRoot.getAsJsonArray(hash);
                    if (arr.size() > 1) {
                        matchScore = arr.get(1).getAsFloat();
                    }
                }

                // Build final record
                StringData sd = new StringData(
                        extractedValue,
                        hash,
                        matchScore,     // score (from MATCHES.json)
                        resultsScore,   // results.json confidence
                        entropy         // entropy
                );

                sscp.addString(sd);
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
