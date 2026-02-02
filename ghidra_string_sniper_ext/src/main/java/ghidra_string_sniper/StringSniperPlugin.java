package ghidra_string_sniper;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

//@formatter:off
// metadata
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = "Ghidra String Sniper",
	category = PluginCategoryNames.COMMON,
	shortDescription = "Plugin short description goes here.",
	description = "Plugin long description goes here."
)
//@formatter:on
// plugin class
public class StringSniperPlugin extends ProgramPlugin {
	StringSniperComponentProvider provider;
	
	public StringSniperPlugin(PluginTool tool) {
		super(tool);

		// set up component provider
		provider = new StringSniperComponentProvider(tool, getName());
		provider.addToTool();
	}

	@Override
	protected void programActivated(Program activatedProgram) {
		super.programActivated(activatedProgram);
		if (provider != null) {
			provider.setProgram(activatedProgram);
		}
	}

	@Override
	protected void programDeactivated(Program deactivatedProgram) {
		super.programDeactivated(deactivatedProgram);
		if (provider != null) {
			provider.setProgram(null);
		}
	}
}
