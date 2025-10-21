package ghidra_string_sniper;

import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.services.ProgramManager;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.util.DefinedStringIterator;
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
						sscp.addStringData(new StringData(stringValue, addr));
					}
                }
            }
        }
    }
    @Override
    public boolean isEnabledForContext(ActionContext context) {
        return context != null && context.getComponentProvider() instanceof StringSniperComponentProvider;
    }
}
