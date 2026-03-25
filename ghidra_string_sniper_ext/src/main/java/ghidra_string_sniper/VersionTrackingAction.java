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

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.util.Collection;
import java.util.List;

import ghidra.feature.vt.api.main.VTAssociation;
import ghidra.feature.vt.api.main.VTMatch;
import ghidra.feature.vt.api.main.VTMatchSet;
import ghidra.feature.vt.api.main.VTSession;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;

import ghidra.framework.model.DomainFile;
import ghidra.util.exception.VersionException;

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
	// Destination program should be the one we're analyzing, maybe a little different from typical workflow.
	// We will open the 'compiled' binary and use that as the source. We want to apply changes to the one we're investigating
        Program destinationProgram = provider.getProgram();
        if (destinationProgram == null) {
            Msg.showError(this, null, "Error", "Please open a program first.");
            return;
        }
	// open compiled program here
	// hard coded for now, add actual logic later
	
	DomainFile domainFile = tool.getProject().getProjectData().getFile("/server_symbols");
	Program sourceProgram = null;
	try {
		sourceProgram = (Program) domainFile.getDomainObject(this, true, false, TaskMonitor.DUMMY);
	} catch (VersionException e) {
		Msg.showError(this, null, "Open program failed","Version mismatch" + e.getMessage(), e);
		return;
	} catch (IOException | CancelledException e) {
		Msg.showError(this, null, "Open program failed", e.getMessage(), e);
		return;
	}
	
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

	    List<VTMatchSet> matchSets = session.getMatchSets();

	    for (int i=0; i < matchSets.size(); i++){
		VTMatchSet matchSet = matchSets.get(i);

		Collection<VTMatch> matches = matchSet.getMatches();

		for (VTMatch match : matches) {
			Address srcAddr = match.getSourceAddress();
			Address dstAddr = match.getDestinationAddress();
			String similarity_score = String.valueOf(match.getSimilarityScore());
			String confidence_score = String.valueOf(match.getConfidenceScore());


		}

	    }

	    Msg.showInfo(this, null, "Success", "VT Correlators Ran");


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

	    // Auto apply strong/implied matches (I think)
	    toolOptions.setBoolean(VTOptionDefines.CREATE_IMPLIED_MATCHES_OPTION, true);
	    toolOptions.setBoolean(VTOptionDefines.APPLY_IMPLIED_MATCHES_OPTION, true);

	    // Exact data matches are safe to run first / auto apply if they exist
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

	    // Matches need agreement from 2 correlators before applying
	    toolOptions.setInt(VTOptionDefines.MIN_VOTES_OPTION, 2);
	    // No conflicts allowed to be considered a match
	    toolOptions.setInt(VTOptionDefines.MAX_CONFLICTS_OPTION, 0);
	    // Reference correlation must be near perfect to be considered match
	    toolOptions.setDouble(VTOptionDefines.REF_CORRELATOR_MIN_SCORE_OPTION, 0.95);
	    // Reference confidence must be perfect
	    toolOptions.setDouble(VTOptionDefines.REF_CORRELATOR_MIN_CONF_OPTION, 10.0);

	    return toolOptions;
    }
}
