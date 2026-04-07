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

import java.nio.charset.StandardCharsets;
import java.nio.file.StandardOpenOption;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.ArrayList;

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
import ghidra.feature.vt.api.main.VTAssociationStatus;
import ghidra.feature.vt.api.util.VTAssociationStatusException;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import ghidra.app.services.ConsoleService;
import java.io.BufferedWriter;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.stream.Stream;

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

            Program destinationProgram = provider.getProgram();

            if (destinationProgram == null) {
                Msg.showError(this, null, "Error", "Please open a program first.");
                return;
            }
            Path projectDir = provider.getProjectDir();

            if (projectDir == null) {
                Msg.showError(this, null, "No Project", "No project is currently open in the component provider.");
                return;
            }

    

            Path gssRoot = projectDir.resolve("gss_vt_runs");

            String binaryId = destinationProgram.getName() + "_" + destinationProgram.getDomainFile().getLastModifiedTime();

            Path outputDir = gssRoot.resolve(binaryId);

    

            final Path outputDirFinal = outputDir;

            AtomicReference<BufferedWriter> logWriterRef = new AtomicReference<>();

            final ConsoleService consoleService = tool != null ? tool.getService(ConsoleService.class) : null;

    

            try {

                if (Files.exists(outputDirFinal)) {

                    // Assuming a utility method for deleting directories, similar to SearchForStringsAction

                    deleteDirectory(outputDirFinal);

                }

                Files.createDirectories(outputDirFinal);

                Path logPath = outputDirFinal.resolve("vt_pipeline.log");

                logWriterRef.set(Files.newBufferedWriter(

                        logPath,

                        StandardCharsets.UTF_8,

                        StandardOpenOption.CREATE,

                        StandardOpenOption.APPEND

                ));

                logLine(logWriterRef.get(), consoleService, "VT Pipeline start for: " + destinationProgram.getName());

                logLine(logWriterRef.get(), consoleService, "Output directory: " + outputDirFinal);

    

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

    

                    // list of dictionaries for matches that can be passed to an LLM for context

                    List<Map<String,Object>> remainingMatches = new ArrayList<>();

    

                    for (int i=0; i < matchSets.size(); i++){

                        VTMatchSet matchSet = matchSets.get(i);

    

                        Collection<VTMatch> matches = matchSet.getMatches();

                        for (VTMatch match : matches) {
                            VTAssociation assoc = match.getAssociation();
                            VTAssociationStatus status = assoc.getStatus();
                            // skip any matches that have already been accepted/applied.
                            if (status == VTAssociationStatus.ACCEPTED) {
                                continue;
                            }

                            Address srcAddr = match.getSourceAddress();
                            Address dstAddr = match.getDestinationAddress();
                            String similarity_score = String.valueOf(match.getSimilarityScore());
                            String confidence_score = String.valueOf(match.getConfidenceScore());

                            Map<String, Object> matchInfo = new HashMap<>();
                            matchInfo.put("similarity_score",similarity_score);
                            matchInfo.put("confidence_score",confidence_score);
    
                            // get decomp, save it, and provide path here

                            String srcDecomp = getFunctionDecomp(sourceProgram, srcAddr);
                            String dstDecomp = getFunctionDecomp(destinationProgram, dstAddr);

                            // decompilation failure cases
                            if (srcDecomp.equals("gss_no_function") || dstDecomp.equals("gss_no_function")){
                                // no function here, maybe log this event, but continue
                                // continue;
                            } else if (srcDecomp.equals("gss_decomp_failed") || dstDecomp.equals("gss_decomp_failed")) {
                                Msg.showError(this, null, "Decomp Failed", "Failed to get decomp... continuing");
                                continue;
                            }

                            Path tempSrcDecompFile = null;
                            Path tempDstDecompFile = null;
                            try {
                                // Create temporary files
                                tempSrcDecompFile = Files.createTempFile("ghidra_src_decomp_", ".c");
                                tempDstDecompFile = Files.createTempFile("ghidra_dst_decomp_", ".c");

				matchInfo.put("src_file_path",tempSrcDecompFile.toString());
				matchInfo.put("dst_file_path",tempSrcDecompFile.toString());

                                // Write decompilation to files

                                Files.writeString(tempSrcDecompFile, srcDecomp);
                                Files.writeString(tempDstDecompFile, dstDecomp);
				
				// write JSON file for python script context
				Gson gson = new GsonBuilder().setPrettyPrinting().create();
				try (FileWriter writer = new FileWriter(tempSrcDecompFile.toString()+".json")) {
					gson.toJson(matchInfo, writer);
				}

				List<String> vtArgs = new ArrayList<>();
				vtArgs.add("--jsonpath");
				vtArgs.add(tempSrcDecompFile.toString()+".json");
                                PythonRunner.RunResult analysisResult = PythonRunner.runSystemPython(
                                	"python",
                                	"extension_interface/run_vt_analysis.py",
					vtArgs,
                                	0,
					null
                                );
                                if (analysisResult == null || analysisResult.exitCode != 0) {
                                	Msg.showError(this, null, "Python VT Analysis Failed", "Python script failed or timed out.");

                                }

				if (analysisResult.stdout.contains("true")) {
					// apply the match
					// might need to do more here than just this accept lol
					// does this apply markups? (probably not)
					assoc.setAccepted();

				} else {
					continue;
				}
                            } catch (IOException | InterruptedException | VTAssociationStatusException e) {

                                Msg.showError(this, null, "File Operation Error", "Failed to create or write temporary decomp files: " + e.getMessage(), e);

                            } finally {

                                // Clean up temporary files

                                try {

                                    if (tempSrcDecompFile != null) {

                                        Files.deleteIfExists(tempSrcDecompFile);

                                    }

                                    if (tempDstDecompFile != null) {

                                        Files.deleteIfExists(tempDstDecompFile);

                                    }

                                } catch (IOException e) {

                                    Msg.showInfo(this, null, "Cleanup Warning", "Failed to delete temporary decomp files");

                                }

                            }

                        }

                    }

                    Msg.showInfo(this, null, "Success", "VT Correlators Ran");

                } catch (IOException | CancelledException e) {

                    logLine(logWriterRef.get(), consoleService, "VT Pipeline error: " + e.getMessage());

                    Msg.showError(this, null, "Error creating VT Session", e.getMessage(), e);
                } catch (InvalidNameException e) {
                    logLine(logWriterRef.get(), consoleService, "VT Pipeline error: " + e.getMessage());
                    Msg.showError(this, null, "Create file failed", "Invalid file name", e);
                } finally {
                    if (session != null) {
                        session.release(this);
                    }
                    BufferedWriter logWriter = logWriterRef.get();
                    if (logWriter != null) {
                        try {
                            logWriter.flush();
                            logWriter.close();
                        } catch (IOException ignored) {
                        }
                    }
                }
            } catch (IOException e) {
                Msg.showError(this, null, "VT Pipeline Setup Error", "Failed to set up pipeline output directory: " + e.getMessage(), e);
            }
        }

    private String getFunctionDecomp(Program program, Address target) { 
	    Function f = program.getFunctionManager().getFunctionContaining(target);
	    DecompInterface ifc = new DecompInterface();
	    if (f == null){
		    return "gss_no_function";
	    }

	    DecompileResults res = ifc.decompileFunction(f, 30, null);
	    if (res == null) {
		    return "gss_decomp_failed";
	    }

	    return res.getDecompiledFunction().getC();
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

    private static void logLine(BufferedWriter writer, ConsoleService consoleService, String message) {
        String ts = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
        String line = "[" + ts + "] " + message;
        Msg.info(VersionTrackingAction.class, line);
        if (consoleService != null) {
            consoleService.println("StringSniper> " + line);
        } else {
            System.out.println(line);
        }
        if (writer == null) {
            return;
        }
        try {
            writer.write(line);
            writer.newLine();
            writer.flush();
        } catch (IOException ignored) {
        }
    }

    private static void deleteDirectory(Path path) throws IOException {
        if (!Files.exists(path)) {
            return;
        }
        try (Stream<Path> walk = Files.walk(path)) {
            walk.sorted((a, b) -> b.compareTo(a)).forEach(p -> {
                try {
                    Files.deleteIfExists(p);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            });
        } catch (RuntimeException e) {
            if (e.getCause() instanceof IOException) {
                throw (IOException) e.getCause();
            }
            throw e;
        }
    }
}
