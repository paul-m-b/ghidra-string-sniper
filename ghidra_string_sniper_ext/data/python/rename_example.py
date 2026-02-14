#TODO write a description for this script
#@author 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 
#@runtime Jython

from ghidra.program.model.symbol import SourceType
import traceback

def find_function_by_name(program, function_name):
    """Helper function to find a function by name."""
    function_manager = program.getFunctionManager()
    functions = function_manager.getFunctions(True)
    
    for func in functions:
        if func.getName() == function_name:
            return func
    return None

def rename_variable(function_name, old_var_name, new_var_name):
    """
    Simpler implementation using Ghidra's built-in functionality.
    This may not work for all cases but is easier to understand.
    """
    program = getCurrentProgram()
    if program is None:
        return "No program loaded"
    
    # Find the function
    func = find_function_by_name(program, function_name)
    if func is None:
        return "Function not found"
    
    # Get all variables in the function
    variables = func.getAllVariables()
    
    # Find the variable to rename
    target_var = None
    for var in variables:
        if var.getName() == old_var_name:
            target_var = var
        if var.getName() == new_var_name:
            return "Error: Variable name already exists"
    
    if target_var is None:
        return "Variable not found"
    
    # Rename the variable
    transaction_id = program.startTransaction("Rename variable")
    try:
        target_var.setName(new_var_name, SourceType.USER_DEFINED)
        program.endTransaction(transaction_id, True)
        return "Variable renamed"
    except Exception as e:
        program.endTransaction(transaction_id, False)
        return "Failed to rename variable: " + str(e)

def main():
    # Hardcode test values
    function_name = "main"
    old_var_name = "local_var1"
    new_var_name = "new_var_name"
    
    result = rename_variable(function_name, new_var_name, old_var_name)
    print(result)

if __name__ == "__main__":
    main()
