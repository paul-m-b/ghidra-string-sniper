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
import java.net.URI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.app.services.GoToService;
import ghidra.util.Msg;

public class StringSniperComponentProvider extends ComponentProvider {
    // Ghidra data
    private Program currentProgram;
    // private StringSniperPlugin plugin; // Optional, comment if unused

    // Data
    private StringTableModel stringsTableModel;

    // UI
    private JTabbedPane tabbedPane;
    private JTable stringsTable;
    private JPanel resultsPanel;
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
        addLocalAction(new HelpAction(this, owner));
    }

    public void clearStrings() {
        stringsTableModel.clear();
    }

    // Sets the current program (optional, can comment if not needed)
    public void setProgram(Program program) {
        this.currentProgram = program;
    }

    public void addString(StringData string) {
        stringsTableModel.add(string);
    }

    public StringTableModel getStringTableModel() {
        return stringsTableModel;
    }

    public List<StringData> getStringData() {
        return stringsTableModel.getStringData();
    }

    public void addResult(ResultData result) {
        // Commented out to prevent unused compilation errors
        /*
        JPanel accordionPanel = new JPanel();
        accordionPanel.setLayout(new BoxLayout(accordionPanel, BoxLayout.Y_AXIS));

        JButton accordionButton = new JButton("► " + result.string.value);
        accordionButton.setMaximumSize(new Dimension(Integer.MAX_VALUE, accordionButton.getPreferredSize().height));
        accordionButton.setFocusPainted(false);

        JPanel accordionContent = new JPanel();
        accordionContent.setLayout(new BoxLayout(accordionContent, BoxLayout.Y_AXIS));

        JLabel confidenceScore = new JLabel("Confidence: " + result.confidence + "/10");
        if(result.confidence >= 7.5){
            confidenceScore.setForeground(Color.GREEN);
        } else if(result.confidence >= 3.5){
            confidenceScore.setForeground(Color.BLUE);
        } else {
            confidenceScore.setForeground(Color.RED);
        }
        accordionContent.add(confidenceScore);

        JPanel repoPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        repoPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        repoPanel.setOpaque(false);

        JLabel repoLabel = new JLabel("URL of repository where code appears: ");
        JLabel linkText = new JLabel("<html><u>Visit Website</u></html>");
        linkText.setForeground(Color.BLUE);
        linkText.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        linkText.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                try {
                    Desktop.getDesktop().browse(new URI("https://www.google.com"));
                } catch (Exception ex) {
                    Msg.showError(StringSniperComponentProvider.this, null,
                            "Failed to open URL", ex.getMessage(), ex);
                }
            }
            @Override
            public void mouseEntered(MouseEvent e) {
                linkText.setText("<html><u><b>Visit Website</b></u></html>");
            }
            @Override
            public void mouseExited(MouseEvent e) {
                linkText.setText("<html><u>Visit Website</u></html>");
            }
        });
        repoPanel.add(repoLabel);
        repoPanel.add(linkText);

        Dimension pref = repoPanel.getPreferredSize();
        repoPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, pref.height));
        accordionContent.add(repoPanel);

        accordionContent.add(new JLabel("LLM Assessment : Pending"));
        accordionContent.add(new JLabel("MD5 Hash: Pending"));
        accordionContent.add(new JLabel("Entropy: Pending"));

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
        */
    }

    private void filterStrings(String query) {
        stringsTableModel.filter(query);
    }

    private void buildPanel() {
        tabbedPane = new JTabbedPane();

        JPanel stringsPanel = new JPanel(new BorderLayout());

        JTextField searchField = new JTextField();
        searchField.setToolTipText("Search for substring...");
        searchField.addKeyListener(new KeyAdapter() {
            @Override
            public void keyReleased(KeyEvent e) {
                filterStrings(searchField.getText());
            }
        });

        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.add(searchField, BorderLayout.CENTER);

        JButton removeButton = new JButton("Remove Selected");
        removeButton.setEnabled(false);
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

        stringsTableModel = new StringTableModel();
        stringsTable = new JTable(stringsTableModel);

        stringsTable.getSelectionModel().addListSelectionListener(e -> {
            removeButton.setEnabled(stringsTable.getSelectedRow() != -1);
        });

        stringsTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && SwingUtilities.isLeftMouseButton(e)) {
                    int row = stringsTable.rowAtPoint(e.getPoint());
                    int col = stringsTable.columnAtPoint(e.getPoint());
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

    // ---------------- Table Model ----------------
    public class StringTableModel extends AbstractTableModel {
        List<StringData> stringData = new ArrayList<>();
        private List<StringData> allData = new ArrayList<>();

        public List<StringData> getStringData() {
            return stringData;
        }

        @Override
        public int getRowCount() {
            return stringData.size();
        }

        @Override
        public int getColumnCount() {
            return 3;
        }

        @Override
        public String getColumnName(int col) {
            switch (col) {
                case 0: return "String";
                case 1: return "Hash";
                case 2: return "Score";
            }
            return "";
        }


        @Override
        public Object getValueAt(int row, int col) {
            StringData s = stringData.get(row);
            switch (col) {
                case 0: return s.value;      // the extracted text SHOULD show here now
                case 1: return s.address;    // the hash
                case 2: return (s.score != null)
                            ? String.format("%.2f", s.score)
                            : "N/A";
            }
            return null;
        }



        @Override
        public boolean isCellEditable(int row, int col) {
            return false;
        }

        public void add(StringData string) {
            stringData.add(string);
            allData.add(string);
            fireTableRowsInserted(stringData.size() - 1, stringData.size() - 1);
        }

        public void clear() {
            int rows = getRowCount();
            stringData.clear();
            allData.clear();
            if (rows > 0) fireTableRowsDeleted(0, rows - 1);
        }

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

        public void removeRow(int row) {
            if (row >= 0 && row < stringData.size()) {
                StringData removed = stringData.remove(row);
                allData.remove(removed);
                fireTableRowsDeleted(row, row);
            }
        }
    }
    public void applyDefaultSort() {
        //Does not replace the button, just default sorts them this way for initial convienence.
        List<StringData> strings = new ArrayList<>(getStringData());

        Comparator<StringData> comparator = Comparator
                .comparing((StringData s) -> s.score == null ? Float.NEGATIVE_INFINITY : s.score)
                .thenComparing(s -> s.value == null ? "" : s.value);

        // Default behavior: highest score first
        comparator = comparator.reversed();

        strings.sort(comparator);

        getStringData().clear();
        getStringData().addAll(strings);
        getStringTableModel().fireTableDataChanged();
    }

    // ---------------- Navigation ----------------
    private void navigateToAddress(String addressString) {
        if (currentProgram == null) {
            Msg.showError(this, null, "Navigation Error", "No program is currently open.");
            return;
        }

        GoToService goToService = getTool().getService(GoToService.class);
        if (goToService == null) {
            Msg.showError(this, null, "Navigation Error", "GoToService not found.");
            return;
        }

        try {
            Address address = currentProgram.getAddressFactory().getAddress(addressString);
            if (address != null) {
                goToService.goTo(address, currentProgram);
            } else {
                Msg.showWarn(this, null, "Invalid Address", "Could not resolve address: " + addressString);
            }
        } catch (Exception e) {
            Msg.showError(this, null, "Navigation Error", "Failed to navigate to address: " + e.getMessage(), e);
        }
    }
}
