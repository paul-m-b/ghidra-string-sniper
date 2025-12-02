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
import ghidra.util.Msg;
import resources.Icons;

public class SearchForStringsAction extends DockingAction {
    public SearchForStringsAction(StringSniperComponentProvider provider, String owner) {
        super("Search For Strings", owner);
        setToolBarData(new ToolBarData(Icons.REFRESH_ICON));
    }

	@Override
	public void actionPerformed(ActionContext context) {
		
		ComponentProvider cp = context.getComponentProvider();
		if (cp instanceof StringSniperComponentProvider) {
		    // get component provider and program
		    StringSniperComponentProvider sscp = (StringSniperComponentProvider)cp;

			// Prompts user for their api key that will be used for later phases
			sscp.apiKey = JOptionPane.showInputDialog("Enter your Openrouter API key here:", "token1234");

			// write api key to temp file
			try (FileWriter writer = new FileWriter(sscp.tempDirectory.resolve("TOKEN").toFile())) {
				writer.write(sscp.apiKey);
			} catch (IOException e) {
				System.err.println("Error writing token file.");
			}

			// Run python script
			// temp run python script
			try {
				// run in python and display stdout
				List<String> args = Arrays.asList(sscp.getExecutablePath());
				PythonRunner.RunResult res = PythonRunner.runSystemPython(sscp.tempDirectory, "ext_get_strings.py", args, 30); // 30s timeout
				Msg.showInfo(getClass(), cp.getComponent(), "Output", res.stdout);

			} catch (Exception e) {
				e.printStackTrace();
				Msg.showInfo(getClass(), cp.getComponent(), "Python run failed:", "Threw an error" + e.getMessage());
			}

		    // Program program = sscp.getTool().getService(ProgramManager.class).getCurrentProgram();
		    // sscp.clearStrings();
		    // // start the search
		    // DefinedStringIterator itr = DefinedStringIterator.forProgram(program);
		    // while (itr.hasNext()) {
		    //     Data stringData = itr.next();
		    //     StringDataInstance sdi = StringDataInstance.getStringDataInstance(stringData);
		    //     if (sdi != null) {
			// 		String stringValue = sdi.getStringValue();
			// 		if (stringValue != null && !stringValue.isEmpty()) {
			// 			// Get the starting address for the defined string
			// 			Address addr = stringData.getAddress(); // or stringData.getMinAddress()
			// 			// add to provider including address
			// 			sscp.addString(new StringData(stringValue, addr));
			// 		}
		    //     }
		    // }
		}
    }
    @Override
    public boolean isEnabledForContext(ActionContext context) {
        return context != null && context.getComponentProvider() instanceof StringSniperComponentProvider;
    }
}
