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
import java.awt.*;


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
				
				window.setSize(800,450);
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


				//Credits
				JPanel creditsPage = new JPanel(new BorderLayout());
				creditsPage.add(new JLabel("Credits page here!"));
				tabPanel.addTab("Credits",creditsPage);
				JTextArea creditsText = new JTextArea("Credits section:\n\n"
				+ "Ghidra :https://github.com/NationalSecurityAgency/ghidra\n"
				//Turn this into a hyperlink^^
				+ "Contributors:\nPaul Biernat '27 (Projet Lead)\n" 
				+ "Jack J '28 (Role Here)\n"
				+ "Jack A '28 (Role Here)\n"
				+ "Cory Tsang '26 (Role Here)"
				//Change roles later
				//Make it hyperlink to our LinkedIns
				);
				creditsText.setEditable(false);
				creditsText.setLineWrap(true);
				creditsText.setWrapStyleWord(true);
				JScrollPane creditsScrollPane = new JScrollPane(creditsText);
				creditsPage.add(creditsScrollPane, BorderLayout.CENTER);


				//Useful Links
				JPanel linksPage = new JPanel(new BorderLayout());
				linksPage.add(new JLabel("Links page here!"));
				tabPanel.addTab("Links",linksPage);
				JTextArea linksText = new JTextArea("Useful links section:\n\n"
				+ "Ghidra String Sniper Repository: https://github.com/paul-m-b/ghidra-string-sniper\n"
				//Should I add: "Ghidra :https://github.com/NationalSecurityAgency/ghidra\n"? I already have it in credits but I feel like it should go here as well.
				//Turn this into a hyperlink^^
				);
				linksText.setEditable(false);
				linksText.setLineWrap(true);
				linksText.setWrapStyleWord(true);
				JScrollPane linksScrollPane = new JScrollPane(linksText);
				linksPage.add(linksScrollPane, BorderLayout.CENTER);


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
