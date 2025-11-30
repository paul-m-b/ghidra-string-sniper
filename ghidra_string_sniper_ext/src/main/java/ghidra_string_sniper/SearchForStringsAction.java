package ghidra_string_sniper;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import javax.swing.JOptionPane;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.services.ProgramManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.util.DefinedStringIterator;
import ghidra.util.Msg;
import resources.Icons;

public class SearchForStringsAction extends DockingAction {
    public SearchForStringsAction(StringSniperComponentProvider provider, String owner) {
        super("Search For Strings", owner);
        setToolBarData(new ToolBarData(Icons.REFRESH_ICON));
    }
    @Override
    public void actionPerformed(ActionContext context) {
        // Prompt user for API key
        String tokenValue = JOptionPane.showInputDialog("Enter your Openrouter API key here:", "EnterValue");

        try {
            File keyFile = File.createTempFile("SniperKey", ".txt");
            //removes file when JVM exits
            keyFile.deleteOnExit(); 

            //Write the API key into the temp file
            try (FileWriter writer = new FileWriter(keyFile)) {
                writer.write(tokenValue);
            }

            //Stores the path for later when connecting to the backend (EXAMPLE: static global or provider)
            System.setProperty("StringSniperKeyFile", keyFile.getAbsolutePath());

        } catch (IOException e) {
            Msg.showError(this, null, "Key File Error", "Failed to write API key: " + e.getMessage());
        }

        /* 
        We can find the key later by using the following code block:

        String keyPath = System.getProperty("StringSniperKeyFile");
        if (keyPath != null) {
            File keyFile = new File(keyPath);

            String apiKey = Files.readString(keyFile.toPath());
        }
        
        May need to implement a different ability to pass key from front end to back end.        
        */


        
        ComponentProvider cp = context.getComponentProvider();
        if (cp instanceof StringSniperComponentProvider) {
            // get component provider and program
            StringSniperComponentProvider sscp = (StringSniperComponentProvider)cp;
            Program program = sscp.getTool().getService(ProgramManager.class).getCurrentProgram();
            sscp.clearStrings();
            // start the search
            DefinedStringIterator itr = DefinedStringIterator.forProgram(program);
            while (itr.hasNext()) {
                Data stringData = itr.next();
                StringDataInstance sdi = StringDataInstance.getStringDataInstance(stringData);
                if (sdi != null) {
					String stringValue = sdi.getStringValue();
					if (stringValue != null && !stringValue.isEmpty()) {
						// Get the starting address for the defined string
						Address addr = stringData.getAddress(); // or stringData.getMinAddress()
						// add to provider including address
						sscp.addString(new StringData(stringValue, addr));
					}
                }
            }
        }

		// temp run python script
		try {

			// run in python and display stdout
			List<String> args = Arrays.asList("arg1", "arg2");
			PythonRunner.RunResult res = PythonRunner.runSystemPython("python/", "string_prioritize.py", args, 30); // 30s timeout
			Msg.showInfo(getClass(), cp.getComponent(), "Output", res.stdout);

		} catch (Exception e) {
			e.printStackTrace();
			Msg.showInfo(getClass(), cp.getComponent(), "AAHA", "Threw an error" + e.getMessage());
		}
    }
    @Override
    public boolean isEnabledForContext(ActionContext context) {
        return context != null && context.getComponentProvider() instanceof StringSniperComponentProvider;
    }
}
