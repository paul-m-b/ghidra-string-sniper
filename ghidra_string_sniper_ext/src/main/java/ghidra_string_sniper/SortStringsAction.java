package ghidra_string_sniper;

import docking.action.DockingAction;
import docking.action.ToolBarData;
import docking.ActionContext;
import resources.Icons;

public class SortStringsAction extends DockingAction {
	private final StringSniperComponentProvider provider;

	public SortStringsAction(StringSniperComponentProvider provider, String owner) {
		super("Sort Strings by Length", owner);
		this.provider = provider;

		setToolBarData(new ToolBarData(Icons.SORT_ASCENDING_ICON));
		setDescription("Sort strings by length (click again to toggle ascending/descending)");
	}

	@Override
	public void actionPerformed(ActionContext context) {
		// provider.sortStringResults();
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return context != null && context.getComponentProvider() instanceof StringSniperComponentProvider;
	}
}
