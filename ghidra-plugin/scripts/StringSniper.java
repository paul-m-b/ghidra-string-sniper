import java.io.*;
import java.util.*;

import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.app.script.GhidraScript;

public class StringSniper extends GhidraScript {
	public void run() throws Exception {
		String string = askString("Dialog Box", "Enter string");

		println("Hello Ghidra Java Script, string: " + string);
	}
}
