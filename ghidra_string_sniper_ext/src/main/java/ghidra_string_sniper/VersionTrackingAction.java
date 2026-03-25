package ghidra_string_sniper;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.VTSession;
import ghidra.feature.vt.api.util.VTOptions;
import ghidra.feature.vt.gui.actions.AutoVersionTrackingTask;
import ghidra.feature.vt.gui.util.VTOptionDefines;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import resources.Icons;
import java.io.IOException;


public class VersionTrackingAction extends DockingAction {
    private final StringSniperComponentProvider provider;
    private final PluginTool tool;

    public VersionTrackingAction(StringSniperComponentProvider provider, String owner, PluginTool tool) {
        super("VersionTrackingAction", owner);
        this.provider = provider;
        this.tool = tool;
        setToolBarData(new ToolBarData(Icons.STRONG_WARNING_ICON));
        setDescription("CLICK THIS FOR VERSION TRACKING (BETA)");
    }

    @Override
    public void actionPerformed(ActionContext context) {
        Program sourceProgram = provider.getProgram();
        if (sourceProgram == null) {
            Msg.showError(this, null, "Error", "Please open a program first.");
            return;
        }
        Program destinationProgram = sourceProgram; // Using the same program for both
	
	String vtSessionName = sourceProgram.getName() + "_" + destinationProgram.getName();

        VTSession session = null;
        try {
            session = new VTSessionDB(vtSessionName, sourceProgram, destinationProgram, this);

            Project project = tool.getProject();
            DomainFolder folder = project.getProjectData().getRootFolder();
            if (folder.getFile(vtSessionName) == null) {
                folder.createFile(vtSessionName, session, TaskMonitor.DUMMY);
            }
            session.save();
            Msg.showInfo(this, null, "Success", "VT Session created.");
	    
	    ToolOptions vtOptions = createAutoVTOptions();
	    AutoVersionTrackingTask autoTask = new AutoVersionTrackingTask(session, vtOptions);
	    TaskLauncher.launch(autoTask);

	    destinationProgram.save("Updated with auto version tracking", TaskMonitor.DUMMY);
	    session.save();


        } catch (IOException | CancelledException e) {
            Msg.showError(this, null, "Error creating VT Session", e.getMessage(), e);
        } catch (InvalidNameException e) {
	    Msg.showError(this, null, "Create file failed", "Invalid file name", e);
	}

        finally {
            if (session != null) {
                session.release(this);
            }
        }
    }
    private ToolOptions createAutoVTOptions() {
	    ToolOptions toolOptions = new VTOptions("Auto Version Tracking Options");

	    toolOptions.setBoolean(VTOptionDefines.CREATE_IMPLIED_MATCHES_OPTION, true);
	    toolOptions.setBoolean(VTOptionDefines.APPLY_IMPLIED_MATCHES_OPTION, true);

	    toolOptions.setBoolean(VTOptionDefines.RUN_EXACT_SYMBOL_OPTION, true);
	    toolOptions.setBoolean(VTOptionDefines.RUN_EXACT_DATA_OPTION, true);
	    toolOptions.setBoolean(VTOptionDefines.RUN_EXACT_FUNCTION_BYTES_OPTION, true);
	    toolOptions.setBoolean(VTOptionDefines.RUN_EXACT_FUNCTION_INST_OPTION, true);

	    toolOptions.setBoolean(VTOptionDefines.RUN_DUPE_FUNCTION_OPTION, true);
	    toolOptions.setBoolean(VTOptionDefines.RUN_REF_CORRELATORS_OPTION, true);

	    toolOptions.setInt(VTOptionDefines.DATA_CORRELATOR_MIN_LEN_OPTION, 5);
	    toolOptions.setInt(VTOptionDefines.SYMBOL_CORRELATOR_MIN_LEN_OPTION, 3);
	    toolOptions.setInt(VTOptionDefines.FUNCTION_CORRELATOR_MIN_LEN_OPTION, 10);
	    toolOptions.setInt(VTOptionDefines.DUPE_FUNCTION_CORRELATOR_MIN_LEN_OPTION, 10);

	    toolOptions.setInt(VTOptionDefines.MIN_VOTES_OPTION, 2);
	    toolOptions.setInt(VTOptionDefines.MAX_CONFLICTS_OPTION, 0);
	    toolOptions.setDouble(VTOptionDefines.REF_CORRELATOR_MIN_SCORE_OPTION, 0.95);
	    toolOptions.setDouble(VTOptionDefines.REF_CORRELATOR_MIN_CONF_OPTION, 10.0);

	    return toolOptions;
    }
}
