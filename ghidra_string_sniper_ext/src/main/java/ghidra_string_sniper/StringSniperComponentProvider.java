package ghidra_string_sniper;

import javax.swing.*;

import docking.ComponentProvider;
import ghidra.framework.plugintool.PluginTool;
import resources.Icons;

public class StringSniperComponentProvider extends ComponentProvider {
	private JTabbedPane tabbedPane;

	public StringSniperComponentProvider(PluginTool tool, String owner) {
		super(tool, "Ghidra String Sniper Provider", owner);

		buildPanel();

		// set title and icon
		setTitle("String Sniper");
		java.net.URL iconURL = getClass().getResource("/images/templogo.png");
		if (iconURL != null) {
			setIcon(new ImageIcon(iconURL));
		} else {
			setIcon(Icons.NOT_ALLOWED_ICON);
		}

		addLocalAction(new SearchForStringsAction(this, owner));
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
