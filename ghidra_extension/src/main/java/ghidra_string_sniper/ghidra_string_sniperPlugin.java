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

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.context.ListingActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import resources.Icons;

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

	public ghidra_string_sniperPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	public void init() {
		super.init();

		// Acquire services if necessary
		DockingAction popupAction = new DockingAction("String Sniper Popup", getName()) {
	        @Override
	        public void actionPerformed(ActionContext context) {
	            // Show your popup window
	            JOptionPane.showMessageDialog(null, "Hello from String Sniper!");
	        }
	        @Override
	        public boolean isEnabledForContext(ActionContext context) {
	            return context instanceof ListingActionContext;
	        }
	    };

	    // Put the action in the right-click menu
	    popupAction.setPopupMenuData(new MenuData(
	        new String[] { "String Sniper..." }, // Menu path
	        Icons.INFO_ICON));       // Optional icon

	    // Make the action always enabled (or add your own enablement logic)
	    popupAction.setEnabled(true);

	    // Register the action
	    tool.addAction(popupAction);

	}
}
