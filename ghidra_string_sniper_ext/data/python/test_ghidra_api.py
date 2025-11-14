import pyhidra
from pathlib import Path

# Initialize pyhidra
pyhidra.start()

# Get absolute paths
binary_path = Path("test.o").resolve()
project_location = binary_path.parent
project_name = f"{binary_path.name}_ghidra"

# Import the Ghidra project classes
from ghidra.base.project import GhidraProject
from java.io import File

# Create a new project (this will create the directory and .gpr file)
project = GhidraProject.createProject(
    str(project_location),
    project_name,
    False  # not temporary
)

# Import the binary into the project
program = project.importProgram(File(str(binary_path)))

# Analyze the program
from ghidra.program.util import GhidraProgramUtilities
from ghidra.app.script import GhidraScriptUtil

if program is not None:
    program.startTransaction("Analysis")
    # Run auto-analysis
    from ghidra.program.flatapi import FlatProgramAPI
    flat_api = FlatProgramAPI(program)
    
    listing = program.getListing()
    print(listing)
    
    from ghidra.app.decompiler.flatapi import FlatDecompilerAPI
    decomp_api = FlatDecompilerAPI(flat_api)
    
    program.endTransaction(0, True)
    project.save(program)
    project.close()
