package ghidra_string_sniper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Set;

import javax.swing.JOptionPane;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressFormatException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import resources.Icons;

public class ExportFunctionReferencesAction extends DockingAction {
    private static final int MAX_REFERENCES_PER_DIRECTION = 10;
    private static final DateTimeFormatter TIMESTAMP =
        DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss");

    private final StringSniperComponentProvider provider;

    public ExportFunctionReferencesAction(StringSniperComponentProvider provider, String owner) {
        super("Export Function References", owner);
        this.provider = provider;
        setToolBarData(new ToolBarData(Icons.REFRESH_ICON));
        setDescription("Export incoming/outgoing function references and write their decompilations.");
    }

    @Override
    public void actionPerformed(ActionContext context) {
        ComponentProvider componentProvider = context.getComponentProvider();
        if (!(componentProvider instanceof StringSniperComponentProvider)) {
            return;
        }

        Program program = provider.getProgram();
        if (program == null) {
            Msg.showError(this, null, "No Program", "No program is currently open.");
            return;
        }

        String addressText = JOptionPane.showInputDialog(
            null,
            "Enter the target function address:",
            "Export Function References",
            JOptionPane.QUESTION_MESSAGE
        );
        if (addressText == null || addressText.trim().isEmpty()) {
            return;
        }

        Address address = parseAddress(program, addressText.trim());
        if (address == null) {
            Msg.showError(this, null, "Invalid Address",
                "Could not parse address: " + addressText.trim());
            return;
        }

        Function targetFunction = program.getFunctionManager().getFunctionContaining(address);
        if (targetFunction == null) {
            Msg.showError(this, null, "No Function",
                "No function contains address " + address.toString() + ".");
            return;
        }

        Path projectDir = provider.getProjectDir();
        if (projectDir == null) {
            Msg.showError(this, null, "No Project", "No project is currently open.");
            return;
        }

        Path outputRoot = projectDir.resolve("gss_function_refs");
        Path exportDir = outputRoot.resolve(buildExportDirectoryName(program, targetFunction));
        Task task = new Task("Export Function References", true, true, true) {
            @Override
            public void run(TaskMonitor monitor) {
                try {
                    exportReferences(program, targetFunction, exportDir, monitor);
                    Msg.showInfo(this, null, "Export Complete",
                        "Wrote function reference decompilations to:\n" + exportDir);
                }
                catch (Exception e) {
                    Msg.showError(this, null, "Export Failed", e.getMessage(), e);
                }
            }
        };
        new TaskLauncher(task, provider.getComponent());
    }

    @Override
    public boolean isEnabledForContext(ActionContext context) {
        return context != null && context.getComponentProvider() instanceof StringSniperComponentProvider;
    }

    private Address parseAddress(Program program, String input) {
        AddressFactory factory = program.getAddressFactory();
        Address address = factory.getAddress(input);
        if (address != null) {
            return address;
        }

        String normalized = input.startsWith("0x") || input.startsWith("0X")
            ? input.substring(2)
            : input;

        for (AddressSpace space : factory.getAddressSpaces()) {
            try {
                return space.getAddress(normalized);
            }
            catch (AddressFormatException ignored) {
                // Try the next space.
            }
        }
        return null;
    }

    private void exportReferences(Program program, Function targetFunction, Path exportDir,
            TaskMonitor monitor) throws Exception {
        Files.createDirectories(exportDir);
        Path incomingDir = exportDir.resolve("incoming");
        Path outgoingDir = exportDir.resolve("outgoing");
        Files.createDirectories(incomingDir);
        Files.createDirectories(outgoingDir);

        monitor.setMessage("Collecting function references...");
        Set<Function> incomingSet = targetFunction.getCallingFunctions(monitor);
        Set<Function> outgoingSet = targetFunction.getCalledFunctions(monitor);

        List<Function> incoming = limitFunctions(sortFunctions(incomingSet));
        List<Function> outgoing = limitFunctions(sortFunctions(outgoingSet));

        DecompInterface decompiler = createDecompiler(program);
        try {
            int totalWork = Math.max(1, incoming.size() + outgoing.size());
            int completed = 0;

            StringBuilder manifest = new StringBuilder();
            manifest.append("Target Function: ").append(describeFunction(targetFunction)).append('\n');
            manifest.append("Program: ").append(program.getName()).append('\n');
            manifest.append("Reference limit per direction: ")
                .append(MAX_REFERENCES_PER_DIRECTION)
                .append('\n');
            manifest.append("Generated: ")
                .append(LocalDateTime.now().format(TIMESTAMP))
                .append('\n')
                .append('\n');

            manifest.append("[Incoming]\n");
            if (incomingSet.size() > incoming.size()) {
                manifest.append("Truncated from ")
                    .append(incomingSet.size())
                    .append(" to ")
                    .append(incoming.size())
                    .append(" references.\n");
            }
            for (int i = 0; i < incoming.size(); i++) {
                Function function = incoming.get(i);
                monitor.checkCancelled();
                monitor.setMessage("Exporting incoming function " + (i + 1) + " of " + incoming.size());
                Path filePath = incomingDir.resolve(buildFunctionFileName("incoming", i + 1, function));
                Files.writeString(filePath, buildDecompilationFileContents(function, decompiler, monitor),
                    StandardCharsets.UTF_8);
                manifest.append(filePath.getFileName())
                    .append(" -> ")
                    .append(describeFunction(function))
                    .append('\n');
                completed++;
                monitor.setProgress((completed * 100L) / totalWork);
            }

            manifest.append('\n').append("[Outgoing]\n");
            if (outgoingSet.size() > outgoing.size()) {
                manifest.append("Truncated from ")
                    .append(outgoingSet.size())
                    .append(" to ")
                    .append(outgoing.size())
                    .append(" references.\n");
            }
            for (int i = 0; i < outgoing.size(); i++) {
                Function function = outgoing.get(i);
                monitor.checkCancelled();
                monitor.setMessage("Exporting outgoing function " + (i + 1) + " of " + outgoing.size());
                Path filePath = outgoingDir.resolve(buildFunctionFileName("outgoing", i + 1, function));
                Files.writeString(filePath, buildDecompilationFileContents(function, decompiler, monitor),
                    StandardCharsets.UTF_8);
                manifest.append(filePath.getFileName())
                    .append(" -> ")
                    .append(describeFunction(function))
                    .append('\n');
                completed++;
                monitor.setProgress((completed * 100L) / totalWork);
            }

            Files.writeString(exportDir.resolve("manifest.txt"), manifest.toString(), StandardCharsets.UTF_8);
        }
        finally {
            decompiler.dispose();
        }
    }

    private DecompInterface createDecompiler(Program program) throws IOException {
        DecompInterface decompiler = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        decompiler.setOptions(options);
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        if (!decompiler.openProgram(program)) {
            throw new IOException("Failed to initialize decompiler for program " + program.getName());
        }
        return decompiler;
    }

    private List<Function> sortFunctions(Set<Function> functions) {
        List<Function> sorted = new ArrayList<>(functions);
        sorted.sort(Comparator.comparing(Function::getEntryPoint));
        return sorted;
    }

    private List<Function> limitFunctions(List<Function> functions) {
        if (functions.size() <= MAX_REFERENCES_PER_DIRECTION) {
            return functions;
        }
        return new ArrayList<>(functions.subList(0, MAX_REFERENCES_PER_DIRECTION));
    }

    private String buildDecompilationFileContents(Function function, DecompInterface decompiler,
            TaskMonitor monitor) {
        StringBuilder builder = new StringBuilder();
        builder.append("/*\n");
        builder.append("Function: ").append(describeFunction(function)).append('\n');
        builder.append("External: ").append(function.isExternal()).append('\n');
        builder.append("Thunk: ").append(function.isThunk()).append('\n');
        builder.append("*/\n\n");

        if (function.isExternal()) {
            builder.append("/* No decompilation available for external function. */\n");
            return builder.toString();
        }

        DecompileResults results = decompiler.decompileFunction(function, 30, monitor);
        if (results == null || !results.decompileCompleted() ||
            results.getDecompiledFunction() == null) {
            builder.append("/* Decompilation failed");
            if (results != null && results.getErrorMessage() != null &&
                !results.getErrorMessage().isBlank()) {
                builder.append(": ").append(results.getErrorMessage().trim());
            }
            builder.append(" */\n");
            return builder.toString();
        }

        builder.append(results.getDecompiledFunction().getC());
        builder.append('\n');
        return builder.toString();
    }

    private String buildExportDirectoryName(Program program, Function targetFunction) {
        return sanitize(program.getName()) + "_" +
            sanitize(targetFunction.getName()) + "_" +
            targetFunction.getEntryPoint().toString().replace(':', '_') + "_" +
            LocalDateTime.now().format(TIMESTAMP);
    }

    private String buildFunctionFileName(String prefix, int index, Function function) {
        return String.format("%s_%03d_%s_%s.c",
            prefix,
            index,
            sanitize(function.getName()),
            function.getEntryPoint().toString().replace(':', '_'));
    }

    private String describeFunction(Function function) {
        return function.getName() + " @ " + function.getEntryPoint();
    }

    private String sanitize(String value) {
        if (value == null || value.isBlank()) {
            return "unknown";
        }
        return value.replaceAll("[^A-Za-z0-9._-]", "_");
    }
}
