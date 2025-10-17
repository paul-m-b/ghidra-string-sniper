package ghidra_string_sniper;

import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.services.ProgramManager;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.util.DefinedStringIterator;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import docking.ActionContext;
import docking.ComponentProvider;
import resources.Icons;
import ghidra.program.model.address.Address;

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
            Program program = sscp.getTool().getService(ProgramManager.class).getCurrentProgram();
            sscp.clearStringResults();
            // start the search
            List<String> foundStrings = new ArrayList<>();
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
						sscp.addStringResultWithAddress(stringValue, addr);

						// optionally still collect string values for alphabetical order
						foundStrings.add(stringValue);
					}
                }
            }
        
            //Sorts alphabetically when using this option. 
            Collections.sort(foundStrings, String.CASE_INSENSITIVE_ORDER);
            for (String s: foundStrings){
                sscp.addStringResult(s);
            }
        }
    }
    @Override
    public boolean isEnabledForContext(ActionContext context) {
        return context != null && context.getComponentProvider() instanceof StringSniperComponentProvider;
    }
}
