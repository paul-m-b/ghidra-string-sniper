package ghidra_string_sniper;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableModel;

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.util.List;
import docking.ComponentProvider;
import ghidra.framework.plugintool.PluginTool;
import resources.Icons;

public class StringSniperComponentProvider extends ComponentProvider {

	// Data
    private StringTableModel stringsTableModel;
	
	// UI
    private JTabbedPane tabbedPane;
    private JTable stringsTable;
    private JPanel resultsPanel;

    public StringSniperComponentProvider(PluginTool tool, String owner) {
        super(tool, "Ghidra String Sniper Provider", owner);

        buildPanel();

        setTitle("String Sniper");
        java.net.URL iconURL = getClass().getResource("/images/templogo.png");
        if (iconURL != null) {
            setIcon(new ImageIcon(iconURL));
        } else {
            setIcon(Icons.NOT_ALLOWED_ICON);
        }

        addLocalAction(new SearchForStringsAction(this, owner));
        addLocalAction(new SortStringsAction(this, owner));
    }

    // === StringData Management
    public void clearStrings() {
		stringsTableModel.clear();
    }

    public void addString(StringData string) {
		stringsTableModel.add(string);
    }

	public void addResult(ResultData result) {
		// accordion panel using BoxLayout
		JPanel accordionPanel = new JPanel();
		accordionPanel.setLayout(new BoxLayout(accordionPanel, BoxLayout.Y_AXIS));

		JButton accordionButton = new JButton("► " + result.string.value);
		accordionButton.setMaximumSize(new Dimension(Integer.MAX_VALUE, accordionButton.getPreferredSize().height));
		accordionButton.setFocusPainted(false);

		JPanel accordionContent = new JPanel();
		accordionContent.setLayout(new BoxLayout(accordionContent, BoxLayout.Y_AXIS));
		accordionContent.add(new JLabel("Confidence: " + result.confidence));

		// start hidden
		accordionContent.setVisible(false);
		accordionButton.addActionListener(e -> {
				accordionContent.setVisible(!accordionContent.isVisible());
				accordionButton.setText((accordionContent.isVisible() ? "▼ " : "► ") + result.string.value);
				accordionPanel.revalidate();
				accordionPanel.repaint();
			});

		// add to panel
		accordionPanel.add(accordionButton);
		accordionPanel.add(accordionContent);

		// add panel to list
		resultsPanel.add(accordionPanel);
	}

    // public void sortStringResults() {
    //     List<String> strings = Collections.list(stringListModel.elements());
    //     if (sortAscending) {
    //         strings.sort(Comparator.comparingInt(String::length));
    //     } else {
    //         strings.sort(Comparator.comparingInt(String::length).reversed());
    //     }
    //     stringListModel.clear();
    //     for (String s : strings) {
    //         stringListModel.addElement(s);
    //     }
    //     sortAscending = !sortAscending;
    // }

    // private void filterStrings(String query) {
    //     stringListModel.clear();
    //     if (query == null || query.isEmpty()) {
    //         for (StringEntry e : allEntries) {
    //             if (!stringListModel.contains(e.value)) {
    //                 stringListModel.addElement(e.value);
    //             }
    //         }
    //         return;
    //     }

    //     String lower = query.toLowerCase();
    //     for (StringEntry e : allEntries) {
    //         if (e.value.toLowerCase().contains(lower)) {
    //             if (!stringListModel.contains(e.value)) {
    //                 stringListModel.addElement(e.value);
    //             }
    //         }
    //     }
    // }

    // === Build UI
    private void buildPanel() {
        tabbedPane = new JTabbedPane();

        // ===== Strings tab =====
        JPanel stringsPanel = new JPanel(new BorderLayout());

        // Search bar
        JTextField searchField = new JTextField();
        searchField.setToolTipText("Search for substring...");
        searchField.addKeyListener(new KeyAdapter() {
            @Override
            public void keyReleased(KeyEvent e) {
                // filterStrings(searchField.getText());
            }
        });
        stringsPanel.add(searchField, BorderLayout.NORTH);

        // String list
        stringsTableModel = new StringTableModel();
        stringsTable = new JTable(stringsTableModel);

        // Double-click handler: switch to Results tab
		stringsTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2 && SwingUtilities.isLeftMouseButton(e)) {
					int row = stringsTable.rowAtPoint(e.getPoint());
					if (row != -1) {
						addResult(new ResultData(1.0f, new StringData((String)stringsTable.getValueAt(row, 0), null)));
						tabbedPane.setSelectedIndex(1);
					}
				}
            }
		});

        JScrollPane scrollPane = new JScrollPane(stringsTable);
        stringsPanel.add(scrollPane, BorderLayout.CENTER);
        tabbedPane.add("Strings", stringsPanel);

        // ===== Results tab =====
        resultsPanel = new JPanel();
        resultsPanel.setLayout(new BoxLayout(resultsPanel, BoxLayout.Y_AXIS));
        tabbedPane.addTab("Results", resultsPanel);

		addResult(new ResultData(1.0f, new StringData("test", null)));
		addResult(new ResultData(1.0f, new StringData("string2", null)));
		addResult(new ResultData(1.0f, new StringData("lol", null)));
    }

    @Override
    public JComponent getComponent() {
        return tabbedPane;
    }

	public class StringTableModel extends AbstractTableModel {
		List<StringData> stringData = new ArrayList<>();

		@Override
		public int getRowCount() {
			return stringData.size();
		}

		@Override
		public int getColumnCount() {
			return 2;
		}

		@Override
		public String getColumnName(int col) {
			if (col == 0) return "String";
			if (col == 1) return "Address";
			return "";
		}

		@Override
		public Object getValueAt(int row, int col) {
			StringData s = stringData.get(row);
			switch (col) {
            case 0: return s.value;
            case 1: return s.address.toString();
            default: return null;
			}
		}

		@Override
		public boolean isCellEditable(int row, int col) {
			return false;
		}

		public void add(StringData string) {
			stringData.add(string);
			int row = stringData.size() - 1;
			fireTableRowsInserted(row, row);
		}

		public void clear() {
			int rows = getRowCount();
			stringData.clear();
			fireTableRowsDeleted(0, rows);
		}
	}
}
