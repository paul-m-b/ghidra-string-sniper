package ghidra_string_sniper;

import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra_string_sniper.StringSniperComponentProvider;
import ghidra_string_sniper.StringSniperComponentProvider.StringTableModel;

import javax.swing.*;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import docking.ActionContext;
import resources.Icons;

public class SortStringsAction extends DockingAction {
    private final StringSniperComponentProvider provider;
    private boolean sortAscending = false;   // default: highest first

    public SortStringsAction(StringSniperComponentProvider provider, String owner) {
        super("Sort Strings by Rating", owner);
        this.provider = provider;

        setToolBarData(new ToolBarData(Icons.SORT_ASCENDING_ICON));
        setDescription("Sort strings by rating (click again to toggle ascending/descending)");
    }

    @Override
    public void actionPerformed(ActionContext context) {

        List<StringData> strings = new ArrayList<>(provider.getStringData());

        Comparator<StringData> comparator = Comparator
                // PRIMARY: sort by score, null = -∞
                .comparing((StringData s) -> s.score == null ? Float.NEGATIVE_INFINITY : s.score)
                // SECONDARY: filepath alphabetical
                .thenComparing(s -> s.value == null ? "" : s.value);

        if (!sortAscending) {
            // Descending for score
            comparator = comparator.reversed();
        }

        strings.sort(comparator);

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
