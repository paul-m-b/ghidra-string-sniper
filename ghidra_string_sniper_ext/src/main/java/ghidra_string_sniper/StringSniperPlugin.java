package ghidra_string_sniper;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.plugintool.PluginTool;

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
}

