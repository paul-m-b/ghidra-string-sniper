package ghidra_string_sniper;

import ghidra.app.script.GhidraScript;
import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.services.ProgramManager;
import ghidra.util.Msg;
import ghidra_string_sniper.StringSniperComponentProvider;
import resources.Icons;
import javax.swing.*;
import java.awt.event.MouseEvent;
import java.awt.event.MouseAdapter;


import java.awt.*;
import java.net.URI;


public class HelpAction extends DockingAction {
	private final StringSniperComponentProvider provider;

	public HelpAction(StringSniperComponentProvider provider, String owner) {
		super("Help Action", owner);
		this.provider = provider;

		setToolBarData(new ToolBarData(Icons.HELP_ICON));
		setDescription("Help, Tutorial, and Misc.");
	}

	private JTabbedPane tabbedPane;
	
	@Override
	public void actionPerformed(ActionContext context) {
		tabbedPane = new JTabbedPane();
		//TODO: Add roles when project is in final steps.  Update as more features are added.

		SwingUtilities.invokeLater(new Runnable(){
			public void run(){
				JFrame window = new JFrame("Help, Tutorial, and Misc.");
				
				window.setSize(600,450);
				window.setLocationRelativeTo(null);
				JTabbedPane tabPanel = new JTabbedPane();
				
				//Tutorial tab:
				JPanel tutorialPage = new JPanel(new BorderLayout());
				tutorialPage.add(new JLabel("Tutorial page here!"));
				tabPanel.addTab("Tutorial", tutorialPage);
				JTextArea tutorialText = new JTextArea("Welcome to Ghidra String Sniper!\n\n"
				+ "This plugin helps you analyze strings in binaries efficiently.\n\n"
				+ "Basic Usage:\n"
				+ "1. Press the Refresh icon to search for strings within your current binary file.\n"
				+ "2. View the extracted strings found in the table.\n"
				+ "3. Double click on a string to be taken to the Results tab to see our LLM analysis as well as the repos this string appears inside of.\n\n"
				//Change ^^ to double click or press deep research button once our prioritization and python scripts are integrated.
				+ "Tip: You can click the ascending/descending button to sort by length.");
				tutorialText.setLineWrap(true);
				tutorialText.setWrapStyleWord(true);
				tutorialText.setEditable(false);
				JScrollPane tutorialScrollPane = new JScrollPane(tutorialText);
				tutorialPage.add(tutorialScrollPane, BorderLayout.CENTER);



				//Features section
				JPanel featuresPage = new JPanel(new BorderLayout());
				featuresPage.add(new JLabel("Features page here!"));
				tabPanel.addTab("Features",featuresPage);
				JTextArea featuresText = new JTextArea("Included features:\n\n"
					+ "• Search for strings — Searches for all strings within your current binary file.\n"
					+ "• Sort Strings — Sorts strings by length (Ascending by default).\n"
					+ "• Search Strings — Filters strings input and returns results to the table.\n"
					+ "• Remove Strings — Removes the selected string from the table.\n"
					+ "• Double clicking on a String — Performs analysis on the selected string, producing result to results tab.\n"
					// ^^ Subject to change if we eventually make dedicated button for analysis			
					+ "• Double clicking on an Address — Takes user to address location within Ghidra.\n"
					//Will include this feature later + "• Export — Saves results to file.\n"
					+ "• Help — Displays this help window."
				);
				featuresText.setEditable(false);
				featuresText.setLineWrap(true);
				featuresText.setWrapStyleWord(true);
				JScrollPane featuresScrollPane = new JScrollPane(featuresText);
				featuresPage.add(featuresScrollPane, BorderLayout.CENTER);


				//Credits Section
				JPanel creditsPage = new JPanel();
				creditsPage.setLayout(new BoxLayout(creditsPage, BoxLayout.Y_AXIS));
				creditsPage.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

				// Helper: creates a clickable label
				java.util.function.BiFunction<String, String, JPanel> createPersonLink = (name, url) -> {
				JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
				panel.setOpaque(false);

				JLabel label = new JLabel("<html><b>" + name + ":</b> </html>");

				JLabel link = new JLabel("<html><u>GitHub</u></html>");
				link.setForeground(Color.BLUE);
				link.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));

				link.addMouseListener(new MouseAdapter() {
					@Override
					public void mouseClicked(MouseEvent e) {
						try {
							Desktop.getDesktop().browse(new URI(url));
						} catch (Exception ex) {
							Msg.showError(provider, null, "Failed to open URL", ex.getMessage(), ex);
						}
					}

					@Override
					public void mouseEntered(MouseEvent e) {
						link.setText("<html><u><b>GitHub</b></u></html>");
					}

					@Override
					public void mouseExited(MouseEvent e) {
						link.setText("<html><u>GitHub</u></html>");
					}
				});

				panel.add(label);
				panel.add(link);
				return panel;
				};

				//Add contributors
				creditsPage.add(new JLabel("<html><h3>Contributors</h3></html>"));
				creditsPage.add(Box.createVerticalStrut(5));

				//Add members to page
				creditsPage.add(createPersonLink.apply("Paul Biernat '27 (Project Lead)", "https://github.com/paul-m-b"));
				creditsPage.add(createPersonLink.apply("Jack J '28", "https://github.com/JackJ30"));
				creditsPage.add(createPersonLink.apply("Jack A '28", "https://github.com/J-AngeI"));
				creditsPage.add(createPersonLink.apply("Cory Tsang '26", "https://github.com/CoryTsang"));

				// Add tab
				tabPanel.addTab("Credits", creditsPage);


				//Useful Links
				JPanel linksPage = new JPanel();
				linksPage.setLayout(new BoxLayout(linksPage, BoxLayout.Y_AXIS));
				linksPage.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

				// Helper: create clickable link label
				java.util.function.BiFunction<String, String, JLabel> createHyperlink = (text, url) -> {
					JLabel link = new JLabel("<html><u>" + text + "</u></html>");
					link.setForeground(Color.BLUE);
					link.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));

					link.addMouseListener(new MouseAdapter() {
						@Override
						public void mouseClicked(MouseEvent e) {
							try {
								Desktop.getDesktop().browse(new URI(url));
							} catch (Exception ex) {
								Msg.showError(provider, null, "Failed to open URL", ex.getMessage(), ex);
							}
						}

						@Override
						public void mouseEntered(MouseEvent e) {
							link.setText("<html><u><b>" + text + "</b></u></html>");
						}

						@Override
						public void mouseExited(MouseEvent e) {
							link.setText("<html><u>" + text + "</u></html>");
						}
					});

					return link;
				};

				linksPage.add(new JLabel("<html><h3>Useful Links</h3></html>"));
				linksPage.add(Box.createVerticalStrut(10));

				//Adding each clickable link
				linksPage.add(createHyperlink.apply("Ghidra String Sniper Repository", "https://github.com/paul-m-b/ghidra-string-sniper"));

				linksPage.add(Box.createVerticalStrut(5));

				linksPage.add(createHyperlink.apply("RCOS (Rensselaer Center for Open Source)", "https://handbook.rcos.io/#/"));

				linksPage.add(Box.createVerticalStrut(5));

				linksPage.add(createHyperlink.apply("Ghidra Repository", "https://github.com/NationalSecurityAgency/ghidra"));

				tabPanel.addTab("Links", linksPage);



				//Adding tabs to the tab panel.  Can be increased for later additions
				tabPanel.addTab("Tutorial",tutorialPage);
				tabPanel.addTab("Features",featuresPage);
				tabPanel.addTab("Credits",creditsPage);
				tabPanel.addTab("Links",linksPage);


				window.add(tabPanel);
				window.setVisible(true);
			}
		});
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return context != null && context.getComponentProvider() instanceof StringSniperComponentProvider;
	}
}
