#TODO write a description for this script
#@author 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 
#@runtime PyGhidra

import json
import re
from pathlib import Path
from ghidra.program.model.listing import Function
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import DataType
from ghidra.program.model.data import IntegerDataType
from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from ghidra.app.util.parser import FunctionSignatureParser
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.listing import FunctionManager
from ghidra.program.model.symbol import SymbolType

class FEATURE_APPLIER:
    def __init__(self):
        self.monitor = ConsoleTaskMonitor()
        self.current_program = getCurrentProgram()
        self.listing = self.current_program.getListing()
        
    def parse_feature_line(self, line: str):
        """
        Parse a feature extraction line into components
        Format: <original> --> <proposed> (<change types>)
        """
        pattern = r'(.*?) --> (.*?) \((.*?)\)'
        match = re.match(pattern, line.strip())
        if match:
            return {
                'original': match.group(1).strip(),
                'proposed': match.group(2).strip(),
                'change_types': [t.strip() for t in match.group(3).split(',')]
            }
        return None

    def extract_var_info(self, var_decl: str):
        """
        Extract variable name and type
        Examples: "undefined4 uVar1;" -> ("uVar1", "undefined4")
                 "int count;" -> ("count", "int")
        """
        # Remove semicolon and split
        clean = var_decl.rstrip(';').strip()
        parts = clean.split()
        if len(parts) >= 2:
            var_type = ' '.join(parts[:-1])
            var_name = parts[-1]
            return var_name, var_type
        return None, None
    
    def parse_function_signature(self, signature: str):
        """
        Parse a function signature into components
        Example: "undefined4 FUN_1234()" -> ("FUN_1234", "undefined4", [])
                "char* get_string(int param_1)" -> ("get_string", "char*", ["int param_1"])
        """
        # Remove semicolon
        signature = signature.rstrip(';').strip()
        
        # Extract function name and parameters
        name_match = re.match(r'(.*?)\s+(\w+)\s*\((.*)\)', signature)
        if name_match:
            return_type = name_match.group(1).strip()
            func_name = name_match.group(2).strip()
            params_str = name_match.group(3).strip()
            
            # Parse parameters if any
            params = []
            if params_str:
                # Split parameters by comma
                param_parts = []
                current = ""
                in_star = False
                for char in params_str:
                    if char == ',' and not in_star:
                        param_parts.append(current.strip())
                        current = ""
                    else:
                        current += char
                        if char == '*':
                            in_star = True
                        elif char.isspace() and in_star:
                            in_star = False
                if current:
                    param_parts.append(current.strip())
                
                params = param_parts
            
            return {
                'name': func_name,
                'return_type': return_type,
                'parameters': params
            }
        return None

    def find_function(self, func_name: str):
        """Find a function by name in the current program"""
        for function in self.listing.getFunctions(True):
            if function.getName() == func_name:
                return function
        return None
    
    def find_variable_in_function(self, function: Function, var_name: str):
        """Find a variable in a function by name"""
        # Check local variables
        for var in function.getAllVariables():
            if var.getName() == var_name:
                return var
        
        # Check parameters
        for param in function.getParameters():
            if param.getName() == var_name:
                return param
        
        return None

    def apply_rename(self, func_name: str, old_name: str, new_name: str):
        """Apply variable/function rename operation"""
        function = self.find_function(func_name)
        if not function:
            print(f"Function {func_name} not found")
            return False
        
        # Check if it's a function rename
        if old_name == func_name:
            function.setName(new_name, SourceType.USER_DEFINED)
            print(f"Renamed function {old_name} -> {new_name}")
            return True
        
        # Otherwise it's a variable rename
        var = self.find_variable_in_function(function, old_name)
        if var:
            var.setName(new_name, SourceType.USER_DEFINED)
            print(f"Renamed {old_name} -> {new_name} in function {func_name}")
            return True
        else:
            print(f"Variable {old_name} not found in function {func_name}")
            return False

    def apply_retype(self, func_name: str, var_name: str, new_type: str):
        """Apply variable/parameter retype operation"""

        dtm = self.current_program.getDataTypeManager()
        function = self.find_function(func_name)
        if not function:
            print(f"Function {func_name} not found")
            return False
        
        # Check if it's a return type
        if var_name == "return":
            # This is a function return type change
            function.setReturnType(dtm.getDataType("/"+new_type), SourceType.USER_DEFINED)
            print(f"Return type change to {new_type} for {func_name} - not sure how to do that yet lmao")
            return False
        
        var = self.find_variable_in_function(function, var_name)
        if var:
            # Get the data type from the new type string
            data_type = self.get_data_type(new_type)
            if data_type:
                var.setDataType(data_type, SourceType.USER_DEFINED)
                print(f"Retyped {var_name} -> {new_type} in function {func_name}")
                return True
        else:
            print(f"Variable {var_name} not found in function {func_name}")
            return False
        
        return False