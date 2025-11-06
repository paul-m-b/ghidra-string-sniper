package ghidra_string_sniper;

import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra_string_sniper.StringSniperComponentProvider;
import ghidra_string_sniper.StringSniperComponentProvider.StringTableModel;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import docking.ActionContext;
import resources.Icons;

public class SortStringsAction extends DockingAction {
	private final StringSniperComponentProvider provider;
	private boolean sortAscending = true;

	public SortStringsAction(StringSniperComponentProvider provider, String owner) {
		super("Sort Strings by Length", owner);
		this.provider = provider;

		setToolBarData(new ToolBarData(Icons.SORT_ASCENDING_ICON));
		setDescription("Sort strings by length (click again to toggle ascending/descending)");
	}

	@Override
	public void actionPerformed(ActionContext context) {
		List<StringData> strings = new ArrayList<>(provider.getStringData());
		if (sortAscending) {
			strings.sort(Comparator.comparingInt(s -> s.value.length()));
		} else {
			strings.sort(Comparator.comparingInt((StringData s) -> s.value.length()).reversed());
		}

		provider.getStringData().clear();
		provider.getStringData().addAll(strings);
		provider.getStringTableModel().fireTableDataChanged();

		sortAscending = !sortAscending;
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return context != null && context.getComponentProvider() instanceof StringSniperComponentProvider;
	}
}
