# @runtime Jython

from java.lang import System

print("=== HELLO FROM GHIDRA POST-SCRIPT ===")

if currentProgram is None:
    print("currentProgram is None")
else:
    print("Program name: " + currentProgram.getName())
    print("Executable path: " + str(currentProgram.getExecutablePath()))
    print("Language: " + currentProgram.getLanguageID().toString())

args = getScriptArgs()
print("Script args count: " + str(len(args)))
for i in range(len(args)):
    print("arg[%d] = %s" % (i, args[i]))

System.out.println("=== JAVA STDOUT FROM JYTHON SCRIPT ===")
