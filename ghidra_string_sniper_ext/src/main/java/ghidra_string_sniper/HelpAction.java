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
		setDescription("Help and Tutorial");
	}

	@Override
	public void actionPerformed(ActionContext context) {
		JTabbedPane tabbedPane = new JTabbedPane();

		//Tutorial section
		JPanel tutorialPanel = new JPanel(new BorderLayout());
		JTextArea tutorialText = new JTextArea("Welcome to Ghidra String Sniper!\n\n"
		+ "This plugin helps you analyze strings in binaries efficiently.\n\n"
		+ "Basic Usage:\n"
		+ "1. Press the Refresh icon to search for strings within your current binary file.\n"
		+ "2. View the extracted strings found in the table.\n"
		+ "3. Double click on a string to be taken to the Results tab to see our LLM analysis as well as the repos this string appears inside of.\n\n"
		//Change ^^ to double click or press deep research button once our prioritization and python scripts are integrated.
		+ "Tip: You can click the ascending/descending button to sort by length.  "
		);
		tutorialText.setEditable(false);
		tutorialText.setLineWrap(true);
		tutorialText.setWrapStyleWord(true);
		tutorialText.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		tutorialPanel.add(new JScrollPane(tutorialText), BorderLayout.CENTER);
		
		//Features section
		JPanel featuresPanel = new JPanel(new BorderLayout());
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
		featuresText.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		featuresPanel.add(new JScrollPane(featuresText), BorderLayout.CENTER);

		
		//Credits
		JPanel creditsPanel = new JPanel(new BorderLayout());
		JTextArea creditsText = new JTextArea("Credits section:\n\n"
		+ "Ghidra :https://github.com/NationalSecurityAgency/ghidra\n"
		//Turn this into a hyperlink^^
		+ "Contributors:\n Paul Biernat '27 (Projet Lead)\n"
		+ "Jack J '28 (Role Here)\n"
		+ "Jack A '28 (Role Here)\n"
		+ "Cory Tsang '26 (Role Here)"
		//Change roles later
		);
		creditsText.setEditable(false);
		creditsText.setLineWrap(true);
		creditsText.setWrapStyleWord(true);
		creditsText.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		creditsPanel.add(new JScrollPane(creditsText), BorderLayout.CENTER);
		

		//Useful Links
		JPanel linksPanel = new JPanel(new BorderLayout());
		JTextArea linksText = new JTextArea("Useful links section:\n\n"
		+ "Ghidra String Sniper Repository: https://github.com/paul-m-b/ghidra-string-sniper\n"
		//Should I add: "Ghidra :https://github.com/NationalSecurityAgency/ghidra\n"? I already have it in credits but I feel like it should go here as well.
		//Turn this into a hyperlink^^
		);
		linksText.setEditable(false);
		linksText.setLineWrap(true);
		linksText.setWrapStyleWord(true);
		linksText.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		linksPanel.add(new JScrollPane(linksText), BorderLayout.CENTER);


		// Adding tabs
		tabbedPane.addTab("Tutorial",tutorialPanel);
		tabbedPane.addTab("Tutorial",featuresPanel);
		tabbedPane.addTab("Credits",creditsPanel);
		tabbedPane.addTab("Useful links",linksPanel);

		JOptionPane.showMessageDialog(null,tabbedPane,	"String Sniper - Help & Tutorial", JOptionPane.INFORMATION_MESSAGE);
		//TODO: Fix panel ui.  Looks scrunched up. Add roles when project is in final steps.  Update as more features are added.
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return context != null && context.getComponentProvider() instanceof StringSniperComponentProvider;
	}
}
