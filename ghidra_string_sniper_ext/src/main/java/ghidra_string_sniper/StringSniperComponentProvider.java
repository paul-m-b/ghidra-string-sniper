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
	private Map<String, ResultData> resultData = new HashMap<>();
	
    private JTabbedPane tabbedPane;

	// Strings UI
    private JTable stringsTable;

    // Results UI
    private JPanel resultsPanel;
    private JTable resultsTable;
    private DefaultTableModel resultsTableModel;
    private JPanel accordionPanel;
    private JButton accordionButton;
    private JPanel accordionContent;

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
    public void clearStringResults() {
		stringsTableModel.clear();
    }

    public void addStringData(StringData data) {
		stringsTableModel.add(data);
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
        // stringList.addMouseListener(new MouseAdapter() {
        //     @Override
        //     public void mouseClicked(MouseEvent e) {
        //         if (e.getClickCount() == 2) {
        //             String selected = stringList.getSelectedValue();
        //             if (selected != null) {
        //                 showResultForString(selected);
        //             }
        //         }
        //     }
        // });

        JScrollPane scrollPane = new JScrollPane(stringsTable);
        stringsPanel.add(scrollPane, BorderLayout.CENTER);
        tabbedPane.add("Strings", stringsPanel);

        // ===== Results tab =====
        resultsPanel = new JPanel();
        resultsPanel.setLayout(new BoxLayout(resultsPanel, BoxLayout.Y_AXIS));

        // Accordion button visuals 
        accordionButton = new JButton("▼ String Details");
        accordionButton.setFocusPainted(false);
        accordionButton.setHorizontalAlignment(SwingConstants.LEFT);
        // Pressing it opens up the data
        accordionButton.addActionListener(e -> toggleAccordion());

        // Accordion content
        // Can be adjusted if we want a different table model
        // Sourcegraph results can go into field 1/2.  May need way to dynamically size based on results.
        accordionContent = new JPanel(new BorderLayout());
        String[] columnNames = {"String", "Memory Location", "Field 1", "Field 2"};
        resultsTableModel = new DefaultTableModel(columnNames, 0);
        resultsTable = new JTable(resultsTableModel);
        accordionContent.add(new JScrollPane(resultsTable), BorderLayout.CENTER);
        accordionContent.setVisible(true);

        // Accordion panel
        accordionPanel = new JPanel(new BorderLayout());
        accordionPanel.add(accordionButton, BorderLayout.NORTH);
        accordionPanel.add(accordionContent, BorderLayout.CENTER);

        //Can manually add more panels later, this only makes one manually to display the basic info.
        resultsPanel.add(accordionPanel);
        tabbedPane.addTab("Results", resultsPanel);
    }

    private void toggleAccordion() {
        boolean visible = accordionContent.isVisible();
        accordionContent.setVisible(!visible);
        accordionButton.setText(visible ? "► String Details" : "▼ String Details");
        resultsPanel.revalidate();
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
