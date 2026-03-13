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