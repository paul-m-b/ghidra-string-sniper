#TODO write a description for this script
#@author 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 
#@runtime Jython

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import DataType, DataTypeConflictHandler
import traceback

def find_function_by_name(program, function_name):
    function_manager = program.getFunctionManager()
    functions = function_manager.getFunctions(True)
    
    for func in functions:
        if func.getName() == function_name:
            return func
    return None

def get_data_type_by_name(program, type_name):
    """Find a data type by name in the program's data type manager"""
    data_type_manager = program.getDataTypeManager()
    
    # Try to find the type by name
    data_type = data_type_manager.getDataType("/" + type_name)
    if data_type is None:
        # Try without the leading slash
        data_type = data_type_manager.getDataType(type_name)
    
    return data_type

def retype_variable(function_name, var_name, new_type_name):
    program = getCurrentProgram()
    if program is None:
        return "No program loaded"
    
    # Find the function
    func = find_function_by_name(program, function_name)
    if func is None:
        return "Function not found"
    
    # Find the data type
    new_type = get_data_type_by_name(program, new_type_name)
    if new_type is None:
        return "Data type not found: " + new_type_name
    
    # Get all variables in the function
    variables = func.getAllVariables()
    
    # Find the variable to retype
    target_var = None
    for var in variables:
        if var.getName() == var_name:
            target_var = var
            break
    
    if target_var is None:
        return "Variable not found: " + var_name
    
    # Check if the variable is already of this type
    current_type = target_var.getDataType()
    if current_type and current_type.getName() == new_type_name:
        return "Variable already has this type"
    
    # Retype the variable
    transaction_id = program.startTransaction("Retype variable")
    try:
        # Set the new data type
        target_var.setDataType(new_type, SourceType.USER_DEFINED)
        program.endTransaction(transaction_id, True)
        return "Variable retyped from " + (current_type.getName() if current_type else "unknown") + " to " + new_type_name
    except Exception as e:
        program.endTransaction(transaction_id, False)
        return "Failed to retype variable: " + str(e)

def main():
    # Hardcode test values
    function_name = "main"
    var_name = "local_var1"
    new_type_name = "int"
    
    result = retype_variable(function_name, var_name, new_type_name)
    print(result)

if __name__ == "__main__":
    main()
