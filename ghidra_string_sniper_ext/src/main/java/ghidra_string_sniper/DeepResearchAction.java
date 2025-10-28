package ghidra_string_sniper;

import docking.action.DockingAction;
import docking.action.ToolBarData;
import docking.ActionContext;
import resources.Icons;

public class DeepResearchAction extends DockingAction {
	private final StringSniperComponentProvider provider;

	public DeepResearchAction(StringSniperComponentProvider provider, String owner) {
		super("Deep Research Action", owner);
		this.provider = provider;

		setToolBarData(new ToolBarData(Icons.STRONG_WARNING_ICON));
		setDescription("Click this button for Deep Research! Button still in development! DOES NOT WORK ATM!!!");
	}

	@Override
	public void actionPerformed(ActionContext context) {
		//provider.DeepResearchAction();
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return context != null && context.getComponentProvider() instanceof StringSniperComponentProvider;
	}
}
