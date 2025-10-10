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
					sscp.addStringResult(stringValue);
					// println("Found string at: " + stringData.getAddress().toString());
					// println("String Value: " + stringValue);
				}
			}
		}
    }

    @Override
    public boolean isEnabledForContext(ActionContext context) {
        return context != null && context.getComponentProvider() instanceof StringSniperComponentProvider;
    }
}
