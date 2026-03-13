package ghidra_string_sniper;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.script.AskDialog;
import ghidra.app.script.MultipleOptionsDialog;
import ghidra.feature.vt.api.main.VTSession;
import ghidra.feature.vt.api.main.VTProgramCorrelator;
import ghidra.feature.vt.api.util.VTAbstractProgramCorrelatorFactory;
import ghidra.feature.vt.api.util.VTOptions;
import ghidra.feature.vt.api.util.VersionTrackingApplyOptions;
import ghidra.feature.vt.auto.VTAutoVersionTrackingTask;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskLauncher;

import java.util.ArrayList;
import java.util.List;

//@formatter:off
@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = "Ghidra Version Tracker",
    category = PluginCategoryNames.COMMON,
    shortDescription = "Automated version tracking.",
    description = "Starts a version tracking session and performs automated version tracking."
)
//@formatter:on
public class VersionTrackerPlugin extends ProgramPlugin {

    public VersionTrackerPlugin(PluginTool tool) {
        super(tool);
        createActions();
    }

    private void createActions() {
        DockingAction trackAction = new DockingAction("Track Version", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                try {
                    runVersionTracker();
                }
                catch (CancelledException e) {
                    // user cancelled
                }
            }
        };
        trackAction.setMenuBarData(new MenuData(new String[] { ToolConstants.MENU_TOOLS, "Track Version" }));
        tool.addAction(trackAction);
    }

