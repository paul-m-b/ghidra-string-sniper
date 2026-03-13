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

    private void runVersionTracker() throws CancelledException {
        AskDialog<DomainFile> sourceDialog = new AskDialog<>("Source Program", "Select the source program:");
        DomainFile sourceFile = sourceDialog.getChoice(tool.getProject().getProjectData().getRootFolder().getFiles());
        if (sourceFile == null) {
            return;
        }

        AskDialog<DomainFile> destinationDialog = new AskDialog<>("Destination Program", "Select the destination program:");
        DomainFile destinationFile = destinationDialog.getChoice(tool.getProject().getProjectData().getRootFolder().getFiles());
        if (destinationFile == null) {
            return;
        }

        Program sourceProgram = null;
        Program destinationProgram = null;
        try {
            sourceProgram = (Program) sourceFile.getDomainObject(this, false, false, null);
            destinationProgram = (Program) destinationFile.getDomainObject(this, false, false, null);

            VTSession session = VTSession.create(tool, sourceProgram, destinationProgram);
            List<VTProgramCorrelator> correlators = VTAbstractProgramCorrelatorFactory.getAllAvailableCorrelators(session);
            
            MultipleOptionsDialog<VTProgramCorrelator> correlatorDialog = new MultipleOptionsDialog<>(
                "Correlator Selection",
                "Select the correlators to use:",
                correlators,
                true);
            correlatorDialog.show();
            if (correlatorDialog.isCanceled()) {
                return;
            }
            List<VTProgramCorrelator> selectedCorrelators = correlatorDialog.getUserChoices();


            VTOptions options = new VTOptions("Default");
            for (VTProgramCorrelator correlator : correlators) {
                if (selectedCorrelators.contains(correlator)) {
                    options.setCorrelator(correlator, true);
                } else {
                    options.setCorrelator(correlator, false);
                }
            }
            VTAutoVersionTrackingTask task = new VTAutoVersionTrackingTask(session, options, new VersionTrackingApplyOptions());
            new TaskLauncher(task, null);

        }
        finally {
            if (sourceProgram != null) {
                sourceProgram.release(this);
            }
            if (destinationProgram != null) {
                destinationProgram.release(this);
            }
        }
    }
}
