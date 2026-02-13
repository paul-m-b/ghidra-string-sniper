package ghidra_string_sniper;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.awt.event.*;
import java.io.File;
import java.io.IOException;
import java.io.BufferedReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.List;
import docking.ComponentProvider;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.model.Project;
import resources.Icons;
import java.net.URI;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

public class StringSniperComponentProvider extends ComponentProvider {
    private Program currentProgram;
    @SuppressWarnings("unused")
    private StringSniperPlugin plugin;
    private PluginTool pluginTool;

    private StringTableModel stringsTableModel;
    private JTabbedPane tabbedPane;
    private JTable stringsTable;
    private JPanel resultsPanel;
    private Path lastOutputDir;

    public StringSniperComponentProvider(StringSniperPlugin plugin, PluginTool tool, String owner) {
        super(tool, "Ghidra String Sniper Provider", owner);
        this.plugin = plugin;
        this.pluginTool = tool;
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

    public void clearResults() {
        resultsPanel.removeAll();
        resultsPanel.revalidate();
        resultsPanel.repaint();
    }

    public void setProgram(Program program) {
        this.currentProgram = program;
    }

    public Program getProgram() {
        return currentProgram;
    }

    public void setLastOutputDir(Path outputDir) {
        this.lastOutputDir = outputDir;
    }

    public Path getProjectDir() {
        if (pluginTool == null) {
            return null;
        }
        Project project = pluginTool.getProject();
        if (project == null || project.getProjectLocator() == null) {
            return null;
        }
        return project.getProjectLocator().getProjectDir().toPath();
    }

    public PluginTool getPluginTool() {
        return pluginTool;
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
        JPanel accordionPanel = new JPanel();
        accordionPanel.setLayout(new BoxLayout(accordionPanel, BoxLayout.Y_AXIS));

        JButton accordionButton = new JButton("> " + result.string.value);
        accordionButton.setMaximumSize(new Dimension(Integer.MAX_VALUE, accordionButton.getPreferredSize().height));
        accordionButton.setFocusPainted(false);

        JPanel accordionContent = new JPanel();
        accordionContent.setLayout(new BoxLayout(accordionContent, BoxLayout.Y_AXIS));

        JLabel confidenceScore = new JLabel("LLM Confidence: " + Math.max(result.confidence, 0) + "/10");
        if (result.confidence >= 7.5f) {
            confidenceScore.setForeground(Color.GREEN);
        } else if (result.confidence >= 3.5f) {
            confidenceScore.setForeground(Color.BLUE);
        } else {
            confidenceScore.setForeground(Color.RED);
        }
        accordionContent.add(confidenceScore);

        JPanel repoPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        repoPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        repoPanel.setOpaque(false);

        JLabel repoLabel = new JLabel("URL of repository where code appears: ");
        JLabel linkText = new JLabel("<html><u>Visit Repo</u></html>");
        linkText.setForeground(Color.BLUE);
        linkText.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        linkText.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                String matchPath = result.string.matchPath;
                if (matchPath == null || matchPath.isBlank()) {
                    JOptionPane.showMessageDialog(accordionContent, "No Sourcegraph match available.", "No Match", JOptionPane.INFORMATION_MESSAGE);
                    return;
                }
                String url = extractSourcegraphUrl(Path.of(matchPath));
                if (url == null || url.isBlank()) {
                    JOptionPane.showMessageDialog(accordionContent, "No Sourcegraph URL found for this match.", "URL Not Found", JOptionPane.WARNING_MESSAGE);
                    return;
                }
                try {
                    Desktop.getDesktop().browse(new URI(url));
                } catch (Exception ex) {
                    Msg.showError(StringSniperComponentProvider.this, null,
                            "Failed to open URL", ex.getMessage(), ex);
                }
            }

            @Override
            public void mouseEntered(MouseEvent e) {
                linkText.setText("<html><u><b>Visit Repo</b></u></html>");
            }

            @Override
            public void mouseExited(MouseEvent e) {
                linkText.setText("<html><u>Visit Repo</u></html>");
            }
        });

        repoPanel.add(repoLabel);
        repoPanel.add(linkText);
        Dimension pref = repoPanel.getPreferredSize();
        repoPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, pref.height));
        accordionContent.add(repoPanel);

        String hashValue = (result.hash != null) ? result.hash : "N/A";
        accordionContent.add(new JLabel("MD5 Hash: " + hashValue));

        String entropyValue = (result.entropy != null)
                ? String.format("%.4f", result.entropy)
                : "N/A";
        accordionContent.add(new JLabel("Entropy: " + entropyValue));

        if (!hashValue.equals("N/A")) {
            JButton viewFileButton = new JButton("View Source File");
            viewFileButton.setAlignmentX(Component.LEFT_ALIGNMENT);
            viewFileButton.addActionListener(e -> {
                Path tempDir = resolveHashDir(hashValue);
                if (tempDir == null || !tempDir.toFile().exists()) {
                    JOptionPane.showMessageDialog(accordionContent, "No file found for this hash.", "File Not Found", JOptionPane.WARNING_MESSAGE);
                    return;
                }

                try {
                    File[] files = tempDir.toFile().listFiles();
                    if (files != null && files.length > 0) {
                        File fileToShow = files[0];
                        String content = Files.readString(fileToShow.toPath());
                        JTextArea textArea = new JTextArea(content);
                        textArea.setEditable(false);
                        JScrollPane scrollPane = new JScrollPane(textArea);
                        scrollPane.setPreferredSize(new Dimension(800, 600));
                        JOptionPane.showMessageDialog(accordionContent, scrollPane, fileToShow.getName(), JOptionPane.INFORMATION_MESSAGE);
                    } else {
                        JOptionPane.showMessageDialog(accordionContent, "No file found for this hash.", "File Not Found", JOptionPane.WARNING_MESSAGE);
                    }
                } catch (IOException ex) {
                    Msg.showError(StringSniperComponentProvider.this, null, "File Read Error", ex.getMessage(), ex);
                }
            });
            accordionContent.add(viewFileButton);
        }

        accordionContent.setVisible(false);
        accordionButton.addActionListener(e -> {
            accordionContent.setVisible(!accordionContent.isVisible());
            accordionButton.setText((accordionContent.isVisible() ? "v " : "> ") + result.string.value);
            accordionPanel.revalidate();
            accordionPanel.repaint();
        });

        accordionPanel.add(accordionButton);
        accordionPanel.add(accordionContent);
        resultsPanel.add(accordionPanel);
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
        stringsTable.getColumnModel().getColumn(2).setCellRenderer(new MatchConfidenceRenderer());

        stringsTable.getSelectionModel().addListSelectionListener(e -> {
            removeButton.setEnabled(stringsTable.getSelectedRow() != -1);
        });

        stringsTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && SwingUtilities.isLeftMouseButton(e)) {
                    int row = stringsTable.rowAtPoint(e.getPoint());
                    if (row != -1) {
                        StringData s = stringsTableModel.getStringData().get(row);

                        float score = s.score != null ? s.score : 0.0f;
                        int confidence = s.resultsScore != null ? s.resultsScore.intValue() : 0;
                        String hash = s.address != null ? s.address : "N/A";
                        Double entropy = s.entropy != null ? s.entropy.doubleValue() : null;

                        addResult(new ResultData(score, confidence, hash, entropy, s));
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
    }

    @Override
    public JComponent getComponent() {
        return tabbedPane;
    }

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
                case 1: return "Open Source Confidence";
                case 2: return "Match Confidence";
            }
            return "";
        }

        @Override
        public Object getValueAt(int row, int col) {
            StringData s = stringData.get(row);
            switch (col) {
                case 0: return s.value;
                case 1:
                    if (s.resultsScore != null) {
                        return String.format("%.2f", s.resultsScore.floatValue());
                    }
                    return "N/A";
                case 2:
                    return (s.score != null) ? String.format("%.2f", s.score) : "N/A";
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

            Comparator<StringData> comparator = Comparator
                    .comparing((StringData s) -> s.resultsScore == null ? Float.NEGATIVE_INFINITY : s.resultsScore.floatValue())
                    .thenComparing(s -> s.value == null ? "" : s.value);
            comparator = comparator.reversed();
            stringData.sort(comparator);

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
        List<StringData> strings = new ArrayList<>(getStringData());

        Comparator<StringData> comparator = Comparator
                .comparing((StringData s) -> s.resultsScore == null ? Float.NEGATIVE_INFINITY : s.resultsScore.floatValue())
                .thenComparing(s -> s.value == null ? "" : s.value);

        comparator = comparator.reversed();

        strings.sort(comparator);

        getStringData().clear();
        getStringData().addAll(strings);
        getStringTableModel().fireTableDataChanged();
    }

    private static class MatchConfidenceRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus,
                                                       int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (!isSelected) {
                c.setBackground(table.getBackground());
            }

            if (column == 2 && value != null) {
                String text = value.toString();
                boolean hasMatch = !text.equals("N/A");
                if (hasMatch && !isSelected) {
                    c.setBackground(new Color(198, 239, 206));
                }
            }
            return c;
        }
    }

    private Path resolveHashDir(String hash) {
        if (hash == null || hash.isBlank()) {
            return null;
        }

        Path baseDir = lastOutputDir;
        if (baseDir != null) {
            Path direct = baseDir.resolve("GSS_Results").resolve(hash);
            if (Files.isDirectory(direct)) {
                return direct;
            }
        }

        Path projectDir = getProjectDir();
        if (projectDir == null) {
            return null;
        }
        Path gssRoot = projectDir.resolve("gss_runs");
        if (!Files.isDirectory(gssRoot)) {
            return null;
        }
        try (var stream = Files.list(gssRoot)) {
            for (Path p : stream.toList()) {
                Path candidate = p.resolve("GSS_Results").resolve(hash);
                if (Files.isDirectory(candidate)) {
                    return candidate;
                }
            }
        } catch (IOException e) {
            return null;
        }
        return null;
    }

    private static String extractSourcegraphUrl(Path matchFile) {
        if (matchFile == null || !Files.exists(matchFile)) {
            return null;
        }

        String repo = null;
        String repoUrl = null;
        String filePath = null;
        String fileUrl = null;
        String firstLine = null;

        try (BufferedReader reader = Files.newBufferedReader(matchFile, StandardCharsets.UTF_8)) {
            String line;
            int linesRead = 0;
            while ((line = reader.readLine()) != null && linesRead < 50) {
                linesRead++;
                if (line.startsWith("repo: ")) {
                    repo = line.substring("repo: ".length()).trim();
                } else if (line.startsWith("repo_url: ")) {
                    repoUrl = line.substring("repo_url: ".length()).trim();
                } else if (line.startsWith("file_path: ")) {
                    filePath = line.substring("file_path: ".length()).trim();
                } else if (line.startsWith("file_url: ")) {
                    fileUrl = line.substring("file_url: ".length()).trim();
                } else if (line.startsWith("line_matches: ")) {
                    String rest = line.substring("line_matches: ".length()).trim();
                    if (!rest.isEmpty()) {
                        firstLine = rest.split("\\s+")[0];
                    }
                }
                if (fileUrl != null && !fileUrl.isBlank()) {
                    return normalizeSourcegraphUrl(fileUrl);
                }
            }
        } catch (IOException e) {
            return null;
        }

        if (repo == null || repo.isBlank() || filePath == null || filePath.isBlank()) {
            return normalizeSourcegraphUrl(repoUrl);
        }

        String url = "https://sourcegraph.com/" + repo + "/-/blob/" + filePath;
        if (firstLine != null && !firstLine.isBlank()) {
            url = url + "?L" + firstLine;
        }
        return url;
    }

    private static String normalizeSourcegraphUrl(String url) {
        if (url == null || url.isBlank()) {
            return null;
        }
        String trimmed = url.trim();
        if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
            return trimmed;
        }
        if (trimmed.startsWith("/")) {
            return "https://sourcegraph.com" + trimmed;
        }
        return trimmed;
    }
}
