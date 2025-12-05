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

        // --- API key part unchanged ---
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
            File resultsDir = new File(tmpDir, "GSS_Results"); // matches SOURCEGRAPH_QUERY
            File jsonFile = new File(resultsDir, "results.json");

            if (!jsonFile.exists()) {
                throw new IOException("results.json not found: " + jsonFile.getAbsolutePath());
            }

            String jsonText = Files.readString(jsonFile.toPath());
            JsonObject root = JsonParser.parseString(jsonText).getAsJsonObject();

            for (String extractedValue : root.keySet()) {
                JsonObject valueObj = root.getAsJsonObject(extractedValue);
                String hash = valueObj.has("hash") ? valueObj.get("hash").getAsString() : "UNKNOWN";
                
                // Use floatValue placeholder (or modify if you store it in results.json)
                Float floatValue = 0.0f;

                // Insert into table
                sscp.addString(new StringData(extractedValue, hash, floatValue));
            }

            sscp.applyDefaultSort();

        } catch (Exception e) {
            Msg.showError(this, null, "Error loading results.json", e.toString());
        }
    }

    @Override
    public boolean isEnabledForContext(ActionContext context) {
        return context != null && context.getComponentProvider() instanceof StringSniperComponentProvider;
    }
}
