/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra_string_sniper;

import javax.swing.*;

import docking.ComponentProvider;
import docking.action.DockingAction;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import resources.Icons;
import ghidra.framework.plugintool.PluginTool;

/**
 * Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = ExamplesPluginPackage.NAME,
	category = PluginCategoryNames.EXAMPLES,
	shortDescription = "Plugin short description goes here.",
	description = "Plugin long description goes here."
)
//@formatter:on
public class ghidra_string_sniperPlugin extends ProgramPlugin {

	DockingAction action;
	StringSniperDockableProvider provider;

	public ghidra_string_sniperPlugin(PluginTool tool) {
		super(tool);

		createActions();
	}

	private void createActions() {

		// set up provider
		provider = new StringSniperDockableProvider(tool, getName());
		provider.addToTool();
	}

	static class StringSniperDockableProvider extends ComponentProvider {
		private JPanel panel;

		public StringSniperDockableProvider(PluginTool tool, String owner) {
			super(tool, "Ghidra String Sniper Provider", owner);

			buildPanel();

			setTitle("String Sniper");
			setIcon(Icons.NOT_ALLOWED_ICON);
		}

		private void buildPanel() {
			panel = new JPanel();
			panel.add(new JLabel("Hello, this is my dockable window!"));
		}

		@Override
		public JComponent getComponent() {
			return panel;
		}
	}
}

