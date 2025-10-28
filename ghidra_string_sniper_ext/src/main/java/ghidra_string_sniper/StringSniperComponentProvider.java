package ghidra_string_sniper;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
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
    private boolean sortAscending = true;

    // UI
    private JTabbedPane tabbedPane;
    private JTable stringsTable;
    private JPanel resultsPanel;
    // Stores the latest result panel accordian tab
    private JPanel currentResultPanel;

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
        //New actions
        addLocalAction(new DeepResearchAction(this,owner));
    }

    // === StringData Management
    public void clearStrings() {
        stringsTableModel.clear();
    }

    public void addString(StringData string) {
        stringsTableModel.add(string);
    }

    public void addResult(ResultData result) {
        JPanel accordionPanel = new JPanel();
        accordionPanel.setLayout(new BoxLayout(accordionPanel, BoxLayout.Y_AXIS));

        JButton accordionButton = new JButton("► " + result.string.value);
        accordionButton.setMaximumSize(new Dimension(Integer.MAX_VALUE, accordionButton.getPreferredSize().height));
        accordionButton.setFocusPainted(false);

        JPanel accordionContent = new JPanel();
        accordionContent.setLayout(new BoxLayout(accordionContent, BoxLayout.Y_AXIS));
        accordionContent.add(new JLabel("Confidence: " + result.confidence));

        accordionContent.setVisible(false);
        accordionButton.addActionListener(e -> {
            accordionContent.setVisible(!accordionContent.isVisible());
            accordionButton.setText((accordionContent.isVisible() ? "▼ " : "► ") + result.string.value);
            accordionPanel.revalidate();
            accordionPanel.repaint();
        });

        accordionPanel.add(accordionButton);
        accordionPanel.add(accordionContent);
        resultsPanel.add(accordionPanel);
    }

    // === Sorting (restored)
    public void sortStringResults() {
        List<StringData> strings = new ArrayList<>(stringsTableModel.stringData);
        if (sortAscending) {
            strings.sort(Comparator.comparingInt(s -> s.value.length()));
        } else {
            strings.sort(Comparator.comparingInt((StringData s) -> s.value.length()).reversed());
        }

        stringsTableModel.stringData.clear();
        stringsTableModel.stringData.addAll(strings);
        stringsTableModel.fireTableDataChanged();

        sortAscending = !sortAscending;
    }

    // === Filtering (restored)
    private void filterStrings(String query) {
        stringsTableModel.filter(query);
    }

    
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
                filterStrings(searchField.getText());
            }
        });
        
        
        // Top panel with search + remove button
        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.add(searchField, BorderLayout.CENTER);

        JButton removeButton = new JButton("Remove Selected");
        removeButton.setEnabled(false);
        // False until something is selected 

        removeButton.setToolTipText("Remove the selected string from the table");
        removeButton.addActionListener(e -> {
            int selectedRow = stringsTable.getSelectedRow();
            if (selectedRow != -1) {
                stringsTableModel.removeRow(selectedRow);
            } else {
                JOptionPane.showMessageDialog(stringsPanel, "Please select a string to remove.", "No Selection", JOptionPane.WARNING_MESSAGE);
            }
        });
        topPanel.add(removeButton, BorderLayout.EAST);

        stringsPanel.add(topPanel, BorderLayout.NORTH);

        // ^^ panel with removing option

        // String list
        stringsTableModel = new StringTableModel();
        stringsTable = new JTable(stringsTableModel);

        stringsTable.getSelectionModel().addListSelectionListener(e -> {
            boolean hasSelection = stringsTable.getSelectedRow() != -1;
            removeButton.setEnabled(hasSelection);
        });

        // Double-click handler: switch to Results tab
        stringsTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && SwingUtilities.isLeftMouseButton(e)) {
                    int row = stringsTable.rowAtPoint(e.getPoint());
                    if (row != -1) {
                        addResult(new ResultData(1.0f,
                                new StringData((String) stringsTable.getValueAt(row, 0), null)));
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

        // Demo data
        addResult(new ResultData(1.0f, new StringData("test", null)));
        addResult(new ResultData(1.0f, new StringData("string2", null)));
        addResult(new ResultData(1.0f, new StringData("lol", null)));
    }

    @Override
    public JComponent getComponent() {
        return tabbedPane;
    }

    // === Table model
    public class StringTableModel extends AbstractTableModel {
        List<StringData> stringData = new ArrayList<>();
        private List<StringData> allData = new ArrayList<>();

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
                case 0:
                    return s.value;
                case 1:
                    return s.address != null ? s.address.toString() : "N/A";
                default:
                    return null;
            }
        }

        @Override
        public boolean isCellEditable(int row, int col) {
            return false;
        }

        public void add(StringData string) {
            stringData.add(string);
            allData.add(string);
            int row = stringData.size() - 1;
            fireTableRowsInserted(row, row);
        }

        public void clear() {
            int rows = getRowCount();
            stringData.clear();
            allData.clear();
            if (rows > 0) fireTableRowsDeleted(0, rows - 1);
        }

        // Used by filterStrings()
        public void filter(String query) {
            stringData.clear();
            if (query == null || query.isEmpty()) {
                stringData.addAll(allData);
            } else {
                String lower = query.toLowerCase();
                for (StringData s : allData) {
                    if (s.value.toLowerCase().contains(lower)) {
                        stringData.add(s);
                    }
                }
            }
            fireTableDataChanged();
        }
        // For removing string entries
        public void removeRow(int row) {
            if (row >= 0 && row < stringData.size()) {
                StringData removed = stringData.remove(row);
                allData.remove(removed); // Keep filtered/all data consistent
                fireTableRowsDeleted(row, row);
            }
        }
        

    }
}
