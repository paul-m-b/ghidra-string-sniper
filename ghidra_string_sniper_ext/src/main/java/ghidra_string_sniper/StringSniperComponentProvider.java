package ghidra_string_sniper;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.util.List;
import docking.ComponentProvider;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import resources.Icons;

public class StringSniperComponentProvider extends ComponentProvider {
    private JTabbedPane tabbedPane;
    private DefaultListModel<String> stringListModel;
    private List<StringEntry> allEntries = new ArrayList<>();
    private boolean sortAscending = true;

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

    // ===== String data management =====
    public void clearStringResults() {
        stringListModel.clear();
        allEntries.clear();
    }

    public void addStringResultWithAddress(String result, Address addr) {
        if (allEntries == null) {
            allEntries = new ArrayList<>();
        }

        // Remove N/A entries if real address exists
        if (addr != null) {
            allEntries.removeIf(e -> e.value.equals(result) && e.address == null);
        }

        // Avoid duplicate entry with same value and address
        boolean alreadyExists = allEntries.stream()
                .anyMatch(e -> Objects.equals(e.value, result) && Objects.equals(e.address, addr));
        if (!alreadyExists) {
            allEntries.add(new StringEntry(result, addr));
        }

        // Update JList to show string if not already present
        if (!stringListModel.contains(result)) {
            stringListModel.addElement(result);
        }
    }

    public void addStringResult(String result) {
        addStringResultWithAddress(result, null);
    }

    public void sortStringResults() {
        List<String> strings = Collections.list(stringListModel.elements());
        if (sortAscending) {
            strings.sort(Comparator.comparingInt(String::length));
        } else {
            strings.sort(Comparator.comparingInt(String::length).reversed());
        }
        stringListModel.clear();
        for (String s : strings) {
            stringListModel.addElement(s);
        }
        sortAscending = !sortAscending;
    }

    private void filterStrings(String query) {
        stringListModel.clear();
        if (query == null || query.isEmpty()) {
            for (StringEntry e : allEntries) {
                if (!stringListModel.contains(e.value)) {
                    stringListModel.addElement(e.value);
                }
            }
            return;
        }

        String lower = query.toLowerCase();
        for (StringEntry e : allEntries) {
            if (e.value.toLowerCase().contains(lower)) {
                if (!stringListModel.contains(e.value)) {
                    stringListModel.addElement(e.value);
                }
            }
        }
    }

    // ===== Build UI =====
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
        stringsPanel.add(searchField, BorderLayout.NORTH);

        // String list
        stringListModel = new DefaultListModel<>();
        JList<String> stringList = new JList<>(stringListModel);
        stringList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        // Double-click handler: switch to Results tab
        stringList.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    String selected = stringList.getSelectedValue();
                    if (selected != null) {
                        showResultForString(selected);
                    }
                }
            }
        });

        JScrollPane scrollPane = new JScrollPane(stringList);
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

    private void showResultForString(String str) {
        if (allEntries == null) allEntries = new ArrayList<>();

        // Switch to Results tab
        tabbedPane.setSelectedIndex(1);

        // Clear previous rows
        resultsTableModel.setRowCount(0);

        // Add only entries with a valid address; if multiple, show all
        for (StringEntry e : allEntries) {
            if (e.value.equals(str) && e.address != null) {
                resultsTableModel.addRow(new Object[]{e.value, e.address.toString(), "", ""});
            }
        }
    }

    @Override
    public JComponent getComponent() {
        return tabbedPane;
    }

    // ===== Helper class for string entries =====
    private static class StringEntry {
        final String value;
        final Address address;

        StringEntry(String value, Address address) {
            this.value = value;
            this.address = address;
        }
    }
}
