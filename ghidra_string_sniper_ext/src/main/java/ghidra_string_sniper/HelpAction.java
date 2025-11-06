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

		JPanel tutorialPanel = new JPanel(new BorderLayout());
		JTextArea tutorialText = new JTextArea("Tutorial stuff goes here!");
		tutorialPanel.add(new JScrollPane(tutorialText), BorderLayout.CENTER);



		tabbedPane.addTab("Tutorial",tutorialPanel);

		JOptionPane.showMessageDialog(null,tabbedPane,	"String Sniper - Help & Tutorial", JOptionPane.INFORMATION_MESSAGE);
		//TODO: Make Features panel to explain features

		//Hello! Helpful info goes here.\n Content to be added: \nTutorial on how to use Ghidra String Sniper ot analyze binaries, What button features are included,  Link to Github page, and maybe Credits for developers
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return context != null && context.getComponentProvider() instanceof StringSniperComponentProvider;
	}
}
