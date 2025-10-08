package ghidra_string_sniper;

import docking.action.DockingAction;
import docking.action.ToolBarData;
import docking.ActionContext;
import docking.ComponentProvider;
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
			Msg.showInfo(this, cp.getComponent(), "Important message", "Fuck yeah");
		}
    }

    @Override
    public boolean isEnabledForContext(ActionContext context) {
        return context != null && context.getComponentProvider() instanceof StringSniperComponentProvider;
    }
}
