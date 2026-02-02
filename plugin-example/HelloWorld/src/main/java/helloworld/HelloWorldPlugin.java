package helloworld;

import java.io.InputStream;

import javax.swing.JLabel;
import javax.swing.JPanel;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.DialogComponentProvider;
import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;

import org.python.core.PyObject;
import org.python.util.PythonInterpreter;

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "HelloWorld",
    category = "Examples",
    shortDescription = "Hello World sample extension",
    description = "Displays a Hello World dialog and calls a bundled Python script that returns a string."
)
public class HelloWorldPlugin extends Plugin {

    private DockingAction action;

    public HelloWorldPlugin(PluginTool tool) {
        super(tool);

        action = new DockingAction("Hello Ghidra", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                String message = callHelloWorldPython();
                tool.showDialog(new HelloDialog(message));
            }
        };

        action.setMenuBarData(new MenuData(new String[] { "Tools", "Hello Ghidra" }));
        tool.addAction(action);
    }

    private String callHelloWorldPython() {
        try {
            ResourceFile scriptFile = Application.getModuleDataFile("scripts/hello_world.py");

            try (InputStream in = scriptFile.getInputStream()) {
                PythonInterpreter py = new PythonInterpreter();

                // load script into interpreters namespace
                py.execfile(in, scriptFile.getName());

                // get and call hello()
                PyObject helloFn = py.get("hello");
                if (helloFn == null) {
                    return "Loaded script, but hello() was not found.";
                }

                PyObject result = helloFn.__call__();
                return result != null ? result.toString() : "<null>";
            }
        }
        catch (Exception e) {
            Msg.showError(this, tool.getToolFrame(), "HelloWorld Error",
                "Failed to call hello_world.py: " + e.getMessage(), e);
            return "Error (see console/log).";
        }
    }

    private static class HelloDialog extends DialogComponentProvider {
        HelloDialog(String text) {
            super("Hello World", false);

            JPanel panel = new JPanel();
            panel.add(new JLabel(text));
            addWorkPanel(panel);

            addDismissButton();
        }
    }
}
