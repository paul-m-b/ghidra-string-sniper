package ghidra_string_sniper;

import javax.swing.*;

import docking.ComponentProvider;
import docking.action.DockingAction;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import resources.Icons;
import ghidra.framework.plugintool.PluginTool;

//@formatter:off
// metadata
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = "Ghidra String Sniper",
	category = PluginCategoryNames.COMMON,
	shortDescription = "Plugin short description goes here.",
	description = "Plugin long description goes here."
)
//@formatter:on
// plugin class
public class StringSniperPlugin extends ProgramPlugin {

	StringSniperDockableProvider provider;

	public StringSniperPlugin(PluginTool tool) {
		super(tool);

		createActions();
	}

	private void createActions() {

		// set up provider
		provider = new StringSniperDockableProvider(tool, getName());
		provider.addToTool();
	}

	static class StringSniperDockableProvider extends ComponentProvider {
		private JTabbedPane tabbedPane;

		public StringSniperDockableProvider(PluginTool tool, String owner) {
			super(tool, "Ghidra String Sniper Provider", owner);

			buildPanel();

			setTitle("String Sniper");
			setIcon(Icons.NOT_ALLOWED_ICON);
		}

		private void buildPanel() {
			// tabbed menu
			tabbedPane = new JTabbedPane();

			// strings panel
			JPanel stringsPanel = new JPanel();
			stringsPanel.setLayout(new BoxLayout(stringsPanel, BoxLayout.Y_AXIS));
			tabbedPane.add("String", stringsPanel);

			// string list
			DefaultListModel<String> listModel = new DefaultListModel<>();
			listModel.addElement("First Item");
			listModel.addElement("Second Item");
			listModel.addElement("Another item");
			listModel.addElement("Another item");
			listModel.addElement("Another item");
			listModel.addElement("Another item");
			listModel.addElement("Another item");
			listModel.addElement("Another item");
			listModel.addElement("Another item");
			listModel.addElement("Another item");
			JList<String> stringList = new JList<>(listModel);

			// scroll pane
			JScrollPane scrollPane = new JScrollPane(stringList);
			stringsPanel.add(scrollPane);

			// results panel
			JPanel resultsPanel = new JPanel();
			resultsPanel.setLayout(new BoxLayout(resultsPanel, BoxLayout.Y_AXIS)); 
			tabbedPane.addTab("Results", resultsPanel);
		}

		@Override
		public JComponent getComponent() {
			return tabbedPane;
		}
	}
}

