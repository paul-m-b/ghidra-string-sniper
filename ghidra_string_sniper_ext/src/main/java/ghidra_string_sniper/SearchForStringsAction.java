package ghidra_string_sniper;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.List;

import javax.swing.JOptionPane;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.services.ProgramManager;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import com.google.gson.JsonObject;
import com.google.gson.JsonArray;
import com.google.gson.JsonParser;

import generic.jar.ResourceFile;
import resources.Icons;

public class SearchForStringsAction extends DockingAction {

    public SearchForStringsAction(StringSniperComponentProvider provider, String owner) {
        super("Search For Strings", owner);
        setToolBarData(new ToolBarData(Icons.REFRESH_ICON));
    }

    @Override
    public void actionPerformed(ActionContext context) {

        //------------------------------------------------------------
        // Ask for API key + store in temp file
        //------------------------------------------------------------
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
        if (cp instanceof StringSniperComponentProvider) {

            StringSniperComponentProvider sscp = (StringSniperComponentProvider) cp;
            Program program = sscp.getTool().getService(ProgramManager.class).getCurrentProgram();
            sscp.clearStrings();

            //------------------------------------------------------------
            // LOAD JSON FROM TEMP OUTPUT LOCATION
            // GSS_matches/MATCHES.json is now written by Python into temp directory
            //------------------------------------------------------------
            try {
                String tmpDir = System.getProperty("java.io.tmpdir");
                File jsonFile = new File(tmpDir + "GSS_matches", "MATCHES.json");

                if (!jsonFile.exists()) {
                    throw new IOException("Temp MATCHES.json not found: " + jsonFile.getAbsolutePath());
                }

                String jsonText = Files.readString(jsonFile.toPath());
                JsonObject root = JsonParser.parseString(jsonText).getAsJsonObject();

                for (String key : root.keySet()) {
                    JsonArray arr = root.getAsJsonArray(key);

                    double score = arr.get(1).getAsDouble();

                    // Convert score → fake address
                    long fakeAddressValue = (long) (score * 1000);

                    Address fakeAddr = program.getAddressFactory()
                            .getDefaultAddressSpace()
                            .getAddress(fakeAddressValue);

                    sscp.addString(new StringData(key, fakeAddr));

                    //Want it to be String, string
                    //For String query and then hash?


                    
                }

            } catch (Exception e) {
                Msg.showError(this, null, "JSON Load Error", e.toString());
            }
        }

        //------------------------------------------------------------
        // RUN PYTHON SCRIPT (now outputs to temp dir)
        //------------------------------------------------------------
        try {
            List<String> args = Arrays.asList("arg1", "arg2");

            PythonRunner.RunResult res = PythonRunner.runSystemPython(
                    "python/",
                    "string_prioritize.py",
                    args,
                    30
            );

            Msg.showInfo(getClass(), cp.getComponent(), "Output", res.stdout);

        } catch (Exception e) {
            e.printStackTrace();
            Msg.showInfo(getClass(), cp.getComponent(), "AAHA", "Threw an error: " + e.getMessage());
        }
    }

    @Override
    public boolean isEnabledForContext(ActionContext context) {
        return context != null && context.getComponentProvider() instanceof StringSniperComponentProvider;
    }
}
