#TODO write a description for this script
#@author 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 
#@runtime PyGhidra

import json
import re
import logging
from datetime import datetime
from pathlib import Path
from ghidra.program.model.listing import Function
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import DataType
from ghidra.program.model.data import IntegerDataType
from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import HighFunctionDBUtil
from ghidra.app.util.parser import FunctionSignatureParser
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.listing import FunctionManager
from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.data import StructureDataType, DataTypeConflictHandler, CategoryPath
from ghidra.program.model.data import PointerDataType

class FeatureLogger:
    """Custom logger for tracking feature application operations"""
    
    def __init__(self, log_dir=None):
        if log_dir is None:
            script_path = Path(__file__).parent if '__file__' in globals() else Path.cwd()
            log_dir = script_path / "GSS_Logs"
        
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        self.session_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Setup main log file
        self.main_log_file = self.log_dir / f"gss_application_{self.session_timestamp}.log"
        self.error_log_file = self.log_dir / f"gss_errors_{self.session_timestamp}.log"
        self.summary_file = self.log_dir / f"gss_summary_{self.session_timestamp}.txt"
        
        self.logger = logging.getLogger("GSS_Feature_Applier")
        self.logger.setLevel(logging.DEBUG)
        
        self.logger.handlers.clear()
        
        file_handler = logging.FileHandler(self.main_log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        
        error_handler = logging.FileHandler(self.error_log_file, encoding='utf-8')
        error_handler.setLevel(logging.ERROR)
        
        # Console handler for important messages
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        error_handler.setFormatter(formatter)
        
        console_formatter = logging.Formatter('%(message)s')
        console_handler.setFormatter(console_formatter)
        
        self.logger.addHandler(file_handler)
        self.logger.addHandler(error_handler)
        self.logger.addHandler(console_handler)
        
        # Track statistics
        self.stats = {
            'functions_processed': 0,
            'signature_changes': {'attempted': 0, 'successful': 0, 'failed': 0},
            'renames': {'attempted': 0, 'successful': 0, 'failed': 0},
            'retypes': {'attempted': 0, 'successful': 0, 'failed': 0},
            'pcode_renames': {'attempted': 0, 'successful': 0, 'failed': 0},
            'errors': []
        }
        
        self.logger.info("="*80)
        self.logger.info(f"GSS Feature Applier Session Started: {self.session_timestamp}")
        self.logger.info(f"Log Directory: {self.log_dir}")
        self.logger.info("="*80)
        
    def log_rename_attempt(self, function_name, old_name, new_name, success, details=None):
        """Log rename operation"""
        self.stats['renames']['attempted'] += 1
        if success:
            self.stats['renames']['successful'] += 1
            self.logger.info(f"RENAME SUCCESS: {function_name} - {old_name} -> {new_name}")
        else:
            self.stats['renames']['failed'] += 1
            error_msg = f"RENAME FAILED: {function_name} - {old_name} -> {new_name}"
            if details:
                error_msg += f" - {details}"
            self.logger.error(error_msg)
            
    def log_pcode_rename_attempt(self, function_name, old_name, new_name, success, details=None):
        """Log pcode rename operation"""
        self.stats['pcode_renames']['attempted'] += 1
        if success:
            self.stats['pcode_renames']['successful'] += 1
            self.logger.info(f"PCODE RENAME SUCCESS: {function_name} - {old_name} -> {new_name}")
        else:
            self.stats['pcode_renames']['failed'] += 1
            error_msg = f"PCODE RENAME FAILED: {function_name} - {old_name} -> {new_name}"
            if details:
                error_msg += f" - {details}"
            self.logger.error(error_msg)
            
    def log_retype_attempt(self, function_name, var_name, old_type, new_type, success, details=None):
        """Log retype operation"""
        self.stats['retypes']['attempted'] += 1
        if success:
            self.stats['retypes']['successful'] += 1
            self.logger.info(f"RETYPE SUCCESS: {function_name} - {var_name}: {old_type} -> {new_type}")
        else:
            self.stats['retypes']['failed'] += 1
            error_msg = f"RETYPE FAILED: {function_name} - {var_name}: {old_type} -> {new_type}"
            if details:
                error_msg += f" - {details}"
            self.logger.error(error_msg)
            
    def log_signature_attempt(self, function_name, old_sig, new_sig, success, details=None):
        """Log signature change operation"""
        self.stats['signature_changes']['attempted'] += 1
        if success:
            self.stats['signature_changes']['successful'] += 1
            self.logger.info(f"SIGNATURE SUCCESS: {function_name}")
            self.logger.debug(f"  Old: {old_sig}")
            self.logger.debug(f"  New: {new_sig}")
        else:
            self.stats['signature_changes']['failed'] += 1
            error_msg = f"SIGNATURE FAILED: {function_name}"
            if details:
                error_msg += f" - {details}"
            self.logger.error(error_msg)
            self.logger.error(f"  Old: {old_sig}")
            self.logger.error(f"  New: {new_sig}")
            
    def log_error(self, error_type, message, exception=None):
        """Log general errors"""
        self.stats['errors'].append({
            'type': error_type,
            'message': message,
            'timestamp': datetime.now().isoformat()
        })
        
        if exception:
            self.logger.error(f"{error_type}: {message}", exc_info=True)
        else:
            self.logger.error(f"{error_type}: {message}")
            
    def log_function_start(self, function_name, file_path):
        """Log start of processing a function"""
        self.stats['functions_processed'] += 1
        self.logger.info("")
        self.logger.info("-"*60)
        self.logger.info(f"Processing Function: {function_name}")
        self.logger.info(f"Source File: {file_path}")
        self.logger.info("-"*60)
        
    def log_function_complete(self, function_name):
        """Log completion of function processing"""
        self.logger.info(f"Completed processing: {function_name}")
        
    def generate_summary(self):
        """Generate a summary report of all operations"""
        with open(self.summary_file, 'w', encoding='utf-8') as f:
            f.write("="*80 + "\n")
            f.write(f"GSS FEATURE APPLIER SUMMARY REPORT\n")
            f.write(f"Session: {self.session_timestamp}\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*80 + "\n\n")
            
            f.write(f"Functions Processed: {self.stats['functions_processed']}\n\n")
            
            f.write("OPERATION STATISTICS:\n")
            f.write("-"*40 + "\n")
            
            # Signature changes
            sig = self.stats['signature_changes']
            f.write(f"Function Signature Changes:\n")
            f.write(f"  Attempted: {sig['attempted']}\n")
            f.write(f"  Successful: {sig['successful']}\n")
            f.write(f"  Failed: {sig['failed']}\n")
            if sig['attempted'] > 0:
                f.write(f"  Success Rate: {sig['successful']/sig['attempted']*100:.1f}%\n")
            f.write("\n")
            
            # Renames
            ren = self.stats['renames']
            f.write(f"Variable/Function Renames:\n")
            f.write(f"  Attempted: {ren['attempted']}\n")
            f.write(f"  Successful: {ren['successful']}\n")
            f.write(f"  Failed: {ren['failed']}\n")
            if ren['attempted'] > 0:
                f.write(f"  Success Rate: {ren['successful']/ren['attempted']*100:.1f}%\n")
            f.write("\n")
            
            # Pcode renames
            pcode = self.stats['pcode_renames']
            f.write(f"Pcode-Level Renames:\n")
            f.write(f"  Attempted: {pcode['attempted']}\n")
            f.write(f"  Successful: {pcode['successful']}\n")
            f.write(f"  Failed: {pcode['failed']}\n")
            if pcode['attempted'] > 0:
                f.write(f"  Success Rate: {pcode['successful']/pcode['attempted']*100:.1f}%\n")
            f.write("\n")
            
            # Retypes
            ret = self.stats['retypes']
            f.write(f"Variable Retypes:\n")
            f.write(f"  Attempted: {ret['attempted']}\n")
            f.write(f"  Successful: {ret['successful']}\n")
            f.write(f"  Failed: {ret['failed']}\n")
            if ret['attempted'] > 0:
                f.write(f"  Success Rate: {ret['successful']/ret['attempted']*100:.1f}%\n")
            f.write("\n")
            
            # Error summary
            f.write("ERROR SUMMARY:\n")
            f.write("-"*40 + "\n")
            if self.stats['errors']:
                f.write(f"Total Errors: {len(self.stats['errors'])}\n\n")
                for i, error in enumerate(self.stats['errors'], 1):
                    f.write(f"{i}. [{error['type']}] {error['message']}\n")
                    f.write(f"   Time: {error['timestamp']}\n\n")
            else:
                f.write("No errors recorded.\n")
            
            f.write("\n" + "="*80 + "\n")
            f.write(f"Log files:\n")
            f.write(f"  Main log: {self.main_log_file}\n")
            f.write(f"  Error log: {self.error_log_file}\n")
            f.write(f"  Summary report: {self.summary_file}\n")
            f.write("="*80 + "\n")
        
        # Print summary to console
        print("\n" + "="*60)
        print("OPERATION SUMMARY")
        print("="*60)
        print(f"Functions Processed: {self.stats['functions_processed']}")
        print(f"Signature Changes: {self.stats['signature_changes']['successful']}/{self.stats['signature_changes']['attempted']}")
        print(f"Renames: {self.stats['renames']['successful']}/{self.stats['renames']['attempted']}")
        print(f"Pcode Renames: {self.stats['pcode_renames']['successful']}/{self.stats['pcode_renames']['attempted']}")
        print(f"Retypes: {self.stats['retypes']['successful']}/{self.stats['retypes']['attempted']}")
        print(f"Errors: {len(self.stats['errors'])}")
        print(f"\nLogs saved to: {self.log_dir}")
        print(f"Summary report: {self.summary_file}")
        print("="*60)
        
        self.logger.info("Session completed - summary report generated")
        
    def close(self):
        """Close the logger"""
        for handler in self.logger.handlers:
            handler.close()
            
class FEATURE_APPLIER:
    def __init__(self, logger=None):
        self.monitor = ConsoleTaskMonitor()
        self.current_program = getCurrentProgram()
        self.listing = self.current_program.getListing()
        self.dtm = self.current_program.getDataTypeManager()
        self.logger = logger if logger else FeatureLogger()
        
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
        signature = signature.rstrip(';').strip()
        
        # Extract function name and parameters - allow optional whitespace between return type and function name
        name_match = re.match(r'(.*?)\s*(\w+)\s*\((.*)\)', signature)
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
                paren_depth = 0  # Track parentheses nesting for complex types
                in_angle_brackets = 0  # For templates if needed
                
                for char in params_str:
                    if char == '(':
                        paren_depth += 1
                    elif char == ')':
                        paren_depth -= 1
                    elif char == '<':
                        in_angle_brackets += 1
                    elif char == '>':
                        in_angle_brackets -= 1
                    elif char == ',' and paren_depth == 0 and in_angle_brackets == 0:
                        param_parts.append(current.strip())
                        current = ""
                        continue
                    
                    current += char
                
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
            self.logger.log_error("RENAME", f"Function {func_name} not found")
            self.logger.log_rename_attempt(func_name, old_name, new_name, False, "Function not found")
            return False
        
        # Check if it's a function rename
        if old_name == func_name:
            try:
                function.setName(new_name, SourceType.USER_DEFINED)
                self.logger.log_rename_attempt(func_name, old_name, new_name, True)
                print(f"    - Renamed function {old_name} -> {new_name}")
                return True
            except Exception as e:
                self.logger.log_error("RENAME", f"Failed to rename function {old_name} -> {new_name}", e)
                self.logger.log_rename_attempt(func_name, old_name, new_name, False, str(e))
                return False
        
        # Otherwise it's a variable rename
        var = self.find_variable_in_function(function, old_name)
        if var:
            try:
                var.setName(new_name, SourceType.USER_DEFINED)
                self.logger.log_rename_attempt(func_name, old_name, new_name, True)
                print(f"    - Renamed {old_name} -> {new_name} in function {func_name}")
                return True
            except Exception as e:
                self.logger.log_error("RENAME", f"Failed to rename variable {old_name} -> {new_name} in {func_name}", e)
                self.logger.log_rename_attempt(func_name, old_name, new_name, False, str(e))
                return False
        else:
            msg = f"Variable {old_name} not found in function {func_name}"
            self.logger.log_rename_attempt(func_name, old_name, new_name, False, msg)
            print(f"    - {msg}")
            return False
        
    def apply_rename_at_pcode_level(self, func_name: str, old_name: str, new_name: str):
        """Rename variables at the pcode level, which works for decompiler-generated variables"""
        print ("    - Attempting to rename at pcode level...")

        function = self.find_function(func_name)
        if not function:
            print(f"    - Function {func_name} not found")
            return False

        # Get the high function (decompiler's representation)
        decompiler = DecompInterface()
        decompiler.openProgram(self.current_program)
        
        # Get decompiled function
        decompiled_func = decompiler.decompileFunction(function, 0, self.monitor)
        if not decompiled_func.decompileCompleted():
            print(f"    - Failed to decompile function {func_name}")
            return False
        
        high_function = decompiled_func.getHighFunction()
        if not high_function:
            return False
        
        # Get local variables
        local_symbol_map = high_function.getLocalSymbolMap()
        
        # Find variable by name
        for symbol in local_symbol_map.getSymbols():
            if symbol.getName() == old_name:
                HighFunctionDBUtil.updateDBVariable(symbol, new_name, None, SourceType.USER_DEFINED)
                print(f"    - Renamed pcode variable {old_name} -> {new_name} in {func_name}")
                return True
        
        # Also check parameters
        #param_symbol_map = high_function.getParamSymbolMap()
        #for symbol in param_symbol_map.getSymbols():
        #    if symbol.getName() == old_name:
        #        symbol.setName(new_name, SourceType.USER_DEFINED)
        #        print(f"Renamed parameter {old_name} -> {new_name} in {function.getName()}")
        #        return True
    
        print(f"    - Variable {old_name} not found in pcode representation")
        return False

    def apply_retype(self, func_name: str, var_name: str, new_type: str):
        """Apply variable/parameter retype operation"""
        
        function = self.find_function(func_name)
        if not function:
            print(f"    - Function {func_name} not found")
            return False
        
        # Ensure the type exists before attempting to apply
        data_type = self.ensure_data_type_exists(new_type)
        if data_type is None:
            print(f"    - Warning: Could not resolve type '{new_type}' for '{var_name}', skipping")
            return False
        
        # Check if it's a return type
        if var_name == "return":
            function.setReturnType(data_type, SourceType.USER_DEFINED)
            print(f"    - Changed return type to {new_type} for {func_name}")
            return True
        
        var = self.find_variable_in_function(function, var_name)
        if var:
            var.setDataType(data_type, SourceType.USER_DEFINED)
            print(f"    - Retyped {var_name} -> {new_type} in function {func_name}")
            return True
        else:
            print(f"    - Variable {var_name} not found in function {func_name}")
            return False

    def get_data_type(self, type_str: str):
        """Convert type string to Ghidra data type"""
        # Handle common types
        type_mappings = {
            'int': 'int',
            'char': 'char',
            'char*': 'char *',
            'void': 'void',
            'undefined': 'undefined',
            'undefined1': 'undefined1',
            'undefined2': 'undefined2',
            'undefined4': 'undefined4',
            'undefined8': 'undefined8',
            'bool': 'bool',
            'size_t': 'size_t',
            'uint32_t': 'uint32_t',
            'uint64_t': 'uint64_t'
        }
        
        gh_type = type_mappings.get(type_str, type_str)
        return self.dtm.findDataType(f"/{gh_type}")
    
    def get_function_address(self, func_name: str):
        """Get function address by its name"""

        func_addr = None
        symbolTable = self.current_program.getSymbolTable()

        symbols = list(symbolTable.getSymbols(func_name))

        if not symbols:
            print (f"    - Function {func_name} not found")
        else:
            for symbol in symbols:
                if symbol.getSymbolType() == SymbolType.FUNCTION:
                    func_addr = symbol.getAddress()
                    break

        return func_addr
    
    def ensure_data_type_exists(self, type_str: str):
        """
        Create missing data type if it doesn't exist.
        Returns the DataType object or None if creation fails.
        """
        
        # Clean the type string
        type_str = type_str.strip()
        is_pointer = type_str.endswith('*')
        base_type = type_str[:-1].strip() if is_pointer else type_str
        
        # List of known Ghidra base types to avoid recreating
        known_base_types = {
            'void', 'char', 'short', 'int', 'long', 'long long',
            'float', 'double', 'size_t', 'ssize_t', 'uint8_t', 'uint16_t',
            'uint32_t', 'uint64_t', 'int8_t', 'int16_t', 'int32_t', 'int64_t',
            'uchar', 'ushort', 'uint', 'ulong', 'ulonglong',
            'bool', '_Bool', 'wchar_t', 'char16_t', 'char32_t',
            'undefined', 'undefined1', 'undefined2', 'undefined4', 'undefined8',
            'FILE', 'fpos_t', 'time_t', 'off_t'
        }
        
        # Check if this is a known base type
        if base_type in known_base_types:
            # For pointer types, we need to ensure the base type exists
            data_type = self.dtm.findDataType(f"/{base_type}")
            if data_type and is_pointer:
                return self.dtm.getPointer(data_type)
            return data_type
        
        # Try to find existing type in program (search globally)
        data_type = self.dtm.findDataType(type_str)
        if data_type:
            return data_type
        
        # For pointer types, try to find/create the base type
        if is_pointer:
            base_dt = self.ensure_data_type_exists(base_type)
            if base_dt:
                return self.dtm.getPointer(base_dt)
            return None
        
        # Check if it's a primitive type with different name
        common_variations = {
            'uint32': 'uint32_t',
            'uint64': 'uint64_t',
            'int32': 'int32_t',
            'int64': 'int64_t',
        }
        
        if base_type in common_variations:
            mapped_type = common_variations[base_type]
            if mapped_type in known_base_types:
                return self.dtm.findDataType(f"/{mapped_type}")
        
        # If we get here, it's a custom type that needs to be created
        # Create category path for custom types
        category_path = CategoryPath("/GSS_CustomTypes")
        
        # Check if type already exists under custom category
        existing_type = self.dtm.findDataType(f"{category_path}/{type_str}")
        if existing_type:
            return existing_type
        
        # Create a stub structure for the unknown type
        print(f"    - Creating stub structure for custom type: {type_str}")
        
        try:
            # Ensure category exists by getting or creating it
            category = self.dtm.getCategory(category_path)
            if category is None:
                category = self.dtm.createCategory(category_path)
            
            # Create new structure
            my_struct = StructureDataType(category_path, type_str, 0, self.dtm)
            
            # Add some placeholder fields based on naming conventions
            # Get common base types
            uint32_t = self.dtm.findDataType("/uint32_t")
            if uint32_t is None:
                uint32_t = self.dtm.findDataType("/int")
            
            char_ptr = self.dtm.findDataType("/char*")
            if char_ptr is None:
                char_ptr = self.dtm.getPointer(self.dtm.findDataType("/char"))
            
            void_ptr = self.dtm.getPointer(self.dtm.findDataType("/void"))
            
            # Generic struct
            #my_struct.add(void_ptr, "data", "Placeholder data")
            #my_struct.add(uint32_t, "size", "Placeholder size")
            
            # Add a comment indicating this is a stub
            my_struct.setDescription(f"Stub structure for {type_str} (auto-created by GSS feature applier)")
            
            # Commit to data type manager
            resolved_struct = self.dtm.addDataType(my_struct, DataTypeConflictHandler.DEFAULT_HANDLER)
            print(f"    - Created structure: {resolved_struct.getName()} (length: {resolved_struct.getLength()} bytes)")
            
            return resolved_struct
            
        except Exception as e:
            print(f"    - Error creating structure for {type_str}: {e}")
            # Fallback to void* if structure creation fails
            void_ptr = self.dtm.getPointer(self.dtm.findDataType("/void"))
            if void_ptr:
                return void_ptr
            return None

    def apply_function_signature(self, old_sig: str, new_sig: str):
        """Apply full function signature change with type creation"""

        parser = FunctionSignatureParser(self.dtm, None)
        old_info = self.parse_function_signature(old_sig)
        new_info = self.parse_function_signature(new_sig)
        
        if not new_info:
            print(f"    - Failed to parse new signature: {new_sig}")
            return False
        
        if not old_info:
            print(f"    - Failed to parse old signature: {old_sig}")
            return False
        
        # Validate and ensure all types exist before attempting to parse
        # Check return type
        return_type = new_info['return_type']
        return_dt = self.ensure_data_type_exists(return_type)
        if return_dt is None:
            print(f"    - Warning: Could not resolve return type '{return_type}', using 'void'")
            return_type = 'void'
        
        # Check and fix parameter types
        modified_params = []
        params_valid = True
        
        for param in new_info['parameters']:
            # Parse parameter into type and name
            param_parts = param.strip().split()
            if len(param_parts) >= 2:
                param_type = ' '.join(param_parts[:-1])
                param_name = param_parts[-1]
                
                # Ensure type exists
                param_dt = self.ensure_data_type_exists(param_type)
                if param_dt is None:
                    print(f"    - Warning: Could not resolve parameter type '{param_type}' for '{param_name}'")
                    # Try to use void* as fallback for unknown types
                    void_ptr = self.dtm.getPointer(self.dtm.findDataType("/void"))
                    if void_ptr:
                        param_type = 'void*'
                        print(f"    - Using void* as fallback for '{param_name}'")
                        params_valid = True
                    else:
                        params_valid = False
                
                modified_params.append(f"{param_type} {param_name}")
            else:
                # If can't parse, keep original
                modified_params.append(param)
        
        if not params_valid:
            print("    - Skipping function signature change due to unresolvable types")
            return False
        
        # Build modified signature
        modified_sig = f"{return_type} {new_info['name']}({', '.join(modified_params)})"
        
        function = self.find_function(old_info['name'])
        if not function:
            print(f"    - Function {old_info['name']} not found")
            return False
        
        # Rename function if needed
        if old_info['name'] != new_info['name']:
            self.apply_rename(old_info['name'], old_info['name'], new_info['name'])
            function = self.find_function(new_info['name'])
        
        try:
            # Try to parse with our potentially modified types
            new_signature = parser.parse(None, modified_sig)
            if new_signature is None:
                print(f"    - Failed to parse function signature: {modified_sig}")
                return False
            
            func_addr = self.get_function_address(new_info['name'])
            cmd = ApplyFunctionSignatureCmd(func_addr, new_signature, SourceType.USER_DEFINED)
            runCommand(cmd)
            print(f"    - Applied signature: {modified_sig}")
            return True
        except Exception as e:
            print(f"    - Error applying signature: {e}")
            return False

    def apply_changes_from_file(self, features_file: str):
        """
        Apply all feature changes from a JSON features file
        """
        print(f"\nApplying features from: {features_file}")
        print("-" * 50)
        
        try:
            with open(features_file, 'r', encoding='utf-8') as f:
                features = json.load(f)
        except Exception as e:
            print(f"Error reading features file: {e}")
            return
        
        # Get the function name from the features
        function_name = features.get('function_name')
        
        if not function_name:
            print("Error: No function_name found in EXTRACTIONS.json file")
            return
        
        print(f"Target function: {function_name}")
        
        # Apply function signature change if present
        if 'function_signature' in features:
            sig = features['function_signature']
            if sig.get('original') and sig.get('proposed'):
                print(f"\nApplying function signature change...")
                if self.apply_function_signature(sig['original'], sig['proposed']) == False:
                    print ("    - Adding function signature comment")
                    addr = self.get_function_address(function_name)
                    comment = "GSS failed to apply: "+sig['proposed']

                    tx_id = self.current_program.startTransaction("Add Comment")

                    try:
                        cu = self.current_program.getListing().getCodeUnitAt(addr)
                        
                        if cu:
                            cu.setComment(CodeUnit.PRE_COMMENT, comment)
                            print("    - Comment added successfully at {}".format(addr))
                        else:
                            print("    - No code unit found at {}".format(addr))
                            
                        self.current_program.endTransaction(tx_id, True)
                    except:
                        self.current_program.endTransaction(tx_id, False)
                        print("    - Error adding comment: {}".format(e))


        
        # Apply variable changes
        if features.get('variables'):
            print(f"\nApplying variable changes ({len(features['variables'])} variables)...")
            
            for var_change in features['variables']:
                # Handle rename
                if var_change.get('proposed_name') and var_change['proposed_name'] != var_change.get('original_name'):
                    print(f"RENAMING: {var_change['original_name']} -> {var_change['proposed_name']}")
                    if self.apply_rename(
                        function_name,
                        var_change['original_name'],
                        var_change['proposed_name']
                    ) == False:
                        self.apply_rename_at_pcode_level(
                            function_name,
                            var_change['original_name'],
                            var_change['proposed_name']
                        )
                
                # Handle retype
                if var_change.get('proposed_type') and var_change['proposed_type'] != var_change.get('original_type'):
                    var_name = var_change.get('proposed_name', var_change['original_name'])
                    print(f"RETYPING: {var_name}: {var_change.get('original_type', 'unknown')} -> {var_change['proposed_type']}")
                    self.apply_retype(
                        function_name,
                        var_name,
                        var_change['proposed_type']
                    )
        
        # Apply function renames (if not already handled by signature)
        if features.get('function_renames') != None:
            print(f"\nApplying function renames...")
            for func_rename in features['function_renames']:
                if func_rename.get('original') and func_rename.get('proposed'):
                    # Only apply if it's for the current function
                    if func_rename['original'] == function_name:
                        print(f"    - Renaming function {func_rename['original']} -> {func_rename['proposed']}")
                        self.apply_rename(
                            function_name,
                            func_rename['original'],
                            func_rename['proposed']
                        )
        
        print(f"\nCompleted changes for {function_name}")

    def process_all_extractions(self, extractions_dir: str, pattern: str = "EXTRACTIONS.json"):
        """
        Process all JSON extraction files in hash subdirectories
        
        Args:
            extractions_dir: Root directory containing hash subdirectories
            pattern: Filename pattern to look for (default: EXTRACTIONS.json)
        """
        from pathlib import Path
        
        extractions_path = Path(extractions_dir)
        
        if not extractions_path.exists():
            print(f"Error: Directory {extractions_dir} does not exist")
            return
        
        # Find all JSON files matching pattern in immediate subdirectories
        # This will find: GSS_Results/*/EXTRACTIONS.json
        json_files = list(extractions_path.glob(f"*/{pattern}"))
        
        # Also look for JSON files with the pattern in the filename
        # e.g., EXTRACTIONS_52f555f6.json
        json_files.extend(list(extractions_path.glob(f"{pattern}_*")))
        
        # Remove duplicates if any
        json_files = list(set(json_files))
        
        if not json_files:
            print(f"No {pattern} files found in subdirectories of {extractions_dir}")
            
            # Also check for any JSON files that might be extraction results
            any_json = list(extractions_path.glob("*.json"))
            if any_json:
                print(f"Found {len(any_json)} JSON files in root directory.")
                print("Please specify the correct pattern or move files to hash subdirectories.")
                for jf in any_json[:5]:  # Show first 5
                    print(f"  - {jf.name}")
                if len(any_json) > 5:
                    print(f"  ... and {len(any_json) - 5} more")
            return
        
        print(f"Found {len(json_files)} extraction files")
        
        # Group by hash or just sort by filename
        results = []
        
        for i, json_file in enumerate(json_files, 1):
            # Try to extract hash from directory name or filename
            hash_dir = json_file.parent.name
            if hash_dir == str(extractions_path.name) or hash_dir == '.':
                # If file is directly in the root, try to extract hash from filename
                hash_dir = json_file.stem.replace(pattern.replace('.json', ''), '').strip('_')
                if not hash_dir:
                    hash_dir = f"file_{i}"
            
            print("\n" + "="*60)
            print(f"[{i}/{len(json_files)}] Processing: {hash_dir}")
            print(f"File: {json_file}")
            print("="*60)
            
            try:
                self.apply_changes_from_file(str(json_file))
                results.append((hash_dir, True, None))
            except Exception as e:
                print(f"Error processing {hash_dir}: {e}")
                import traceback
                traceback.print_exc()
                results.append((hash_dir, False, str(e)))

def main():
    """
    Usage: 
    Set the path to the GSS results directory containing hash subdirectories
    Each hash subdirectory should contain an EXTRACTIONS.json file
    """
    
    applier = FEATURE_APPLIER()
    
    decomps_dir = "C:/Users/Jack/Desktop/gss/ghidra_string_sniper_ext/data/python/GSS_decomps"

    # Process all extraction files in hash subdirectories
    applier.process_all_extractions(decomps_dir)

    
    print("\n" + "="*60)
    print("Feature application completed")
    print("="*60)

if __name__ == "__main__":
    main()