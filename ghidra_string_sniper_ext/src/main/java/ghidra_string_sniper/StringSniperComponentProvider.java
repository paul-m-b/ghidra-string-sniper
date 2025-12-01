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
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Program;
import ghidra.app.services.GoToService;
import ghidra.util.Msg;



public class StringSniperComponentProvider extends ComponentProvider {
    // Ghidra data
    private Program currentProgram;
    private StringSniperPlugin plugin;

    // Data
    private StringTableModel stringsTableModel;

    // UI
    private JTabbedPane tabbedPane;
    private JTable stringsTable;
    private JPanel resultsPanel;
    // Stores the latest result panel accordian tab
    private JPanel currentResultPanel;

    public StringSniperComponentProvider(StringSniperPlugin plugin, PluginTool tool, String owner) {
        super(tool, "Ghidra String Sniper Provider", owner);
        this.plugin = plugin; 
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
        addLocalAction(new DeepResearchAction(this,owner));
        addLocalAction(new HelpAction(this,owner));
    }

    public void clearStrings() {
        stringsTableModel.clear();
    }

    // Sets the current program so that Ghidra can go to it for addresses when navigating.
    public void setProgram(Program program) {
        this.currentProgram = program;
    }

    public void addString(StringData string) {
        stringsTableModel.add(string);
    }
    
    public StringTableModel getStringTableModel(){
        return stringsTableModel;
    }
    public List<StringData> getStringData() {
        return stringsTableModel.getStringData();
    }


    /**
    This creates a collapsible accordion UI element for each search result from source graph based on the string you selected.
    Each accordion contains:
        A header button showing the string value
        A collapsible content area showing metadata (confidence, repo link, assessment)
    This keeps Result UI logic isolated from the main provider class.
    */
    public void addResult(ResultData result) {
        // Can be implemented later.  Purpose is to remove old results for only the current one to appear.
        //resultsPanel.removeALL();
        JPanel accordionPanel = new JPanel();
        accordionPanel.setLayout(new BoxLayout(accordionPanel, BoxLayout.Y_AXIS));

        JButton accordionButton = new JButton("► " + result.string.value);
        accordionButton.setMaximumSize(new Dimension(Integer.MAX_VALUE, accordionButton.getPreferredSize().height));
        accordionButton.setFocusPainted(false);

        JPanel accordionContent = new JPanel();
        accordionContent.setLayout(new BoxLayout(accordionContent, BoxLayout.Y_AXIS));

        // Below are the results panel format that sourcegraph data will be entered into.
        // Colors text based on how confident it's related to the repository 
        // (I'm assuming we'll implrement a way to make it score out of 10)
        JLabel confidenceScore = new JLabel("Confidence: " + result.confidence + "/10");
        if(result.confidence >= 7.5){
            confidenceScore.setForeground(Color.GREEN);
        } else if(result.confidence >= 3.5){
            confidenceScore.setForeground(Color.BLUE);
        }else{
            confidenceScore.setForeground(Color.RED);
        }
        accordionContent.add(confidenceScore);


        //Makes a new JPanel to host the text for the repo URL.  User can interact by clicking on link of repo
        //and be taken to the sourcegraph.com page.  Google.com used for now as placeholder but will be replaced with a variable
        //that gets the data from parsed data from the fun
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

            //Link becomes bold when hovered over and returns to normal after it's hovered off
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


        //We will get all of the data after parsing through the backend api response.
        //Space for our LLM assessment.
        accordionContent.add(new JLabel("LLM Assessment : " + "Pending"));
        
        //Hash Result
        accordionContent.add(new JLabel("MD5 Hash: "+ "Pending"));

        //Entropy level
        accordionContent.add(new JLabel("Entropy: "+ "Pending"));

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

    // Filtering strings based on query
    private void filterStrings(String query) {
        stringsTableModel.filter(query);
    }

    
    // Build UI
    private void buildPanel() {
        tabbedPane = new JTabbedPane();
        		
        // Strings tab 
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
                    int col = stringsTable.columnAtPoint(e.getPoint());
                    if (row != -1) {
                        if (col == 1) {
                            // Double clicking the Address column takes you to the section in ghidra as if you went Navigation, Go to, manually enter adress
                            Object addressValue = stringsTable.getValueAt(row, 1);
                            if (addressValue != null && !"N/A".equals(addressValue)) {
                                navigateToAddress(addressValue.toString());
                            } else {
                                JOptionPane.showMessageDialog(stringsTable, 
                                    // Have not tested this fail case so may not work.  Needs testing.
                                    "No valid address for this string.", 
                                    "Invalid Address", JOptionPane.WARNING_MESSAGE);
                            }
                        } else {
                            // Double clicking works as normal for the strings column 
                            addResult(new ResultData(1.0f,
                                    new StringData((String) stringsTable.getValueAt(row, 0), null)));
                            tabbedPane.setSelectedIndex(1);
                        }
                    }
                }
            }
        });
     
        JScrollPane scrollPane = new JScrollPane(stringsTable);
        stringsPanel.add(scrollPane, BorderLayout.CENTER);
        tabbedPane.add("Strings", stringsPanel);

        // Results tab
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



    
    // Table model
    public class StringTableModel extends AbstractTableModel {
        List<StringData> stringData = new ArrayList<>();
        private List<StringData> allData = new ArrayList<>();


        public List<StringData> getStringData(){
            return stringData;
        }

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

    // For double clicking adress to navigate inside of ghidra to the address.
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
