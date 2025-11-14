#!/usr/bin/env python3
"""
PyGhidra Binary Analysis Script
Demonstrates opening a binary, finding strings, decompiling functions, etc.
"""

import pyghidra

def analyze_binary(binary_path):
    """
    Open and analyze a binary file using pyghidra
    
    Args:
        binary_path: Path to the binary file to analyze
    """
    
    # Open the binary with pyghidra
    with pyghidra.open_program(binary_path, analyze=True) as flat_api:
        program = flat_api.getCurrentProgram()
        
        print(f"[*] Analyzing: {program.getName()}")
        print(f"[*] Language: {program.getLanguageID()}")
        print(f"[*] Compiler: {program.getCompilerSpec().getCompilerSpecID()}")
        print("-" * 60)
        
        # 1. Find all defined strings
        print("\n[+] Strings found in binary:")
        print("-" * 60)
        
        string_mgr = program.getListing().getDefinedData(True)
        string_count = 0
        
        for data in string_mgr:
            if data.hasStringValue():
                addr = data.getAddress()
                string_val = data.getValue()
                print(f"  {addr}: {string_val}")
                string_count += 1
                if string_count >= 20:  # Limit output
                    print(f"  ... (showing first 20 strings)")
                    break
        
        # 2. Get function listing
        print("\n[+] Functions in binary:")
        print("-" * 60)
        
        func_mgr = program.getFunctionManager()
        functions = func_mgr.getFunctions(True)
        
        func_list = []
        for func in functions:
            func_list.append(func)
            if len(func_list) <= 10:  # Show first 10
                print(f"  {func.getEntryPoint()}: {func.getName()}")
        
        print(f"  ... (total {len(func_list)} functions)")
        
        # 3. Decompile a specific function
        print("\n[+] Decompiling main function (if found):")
        print("-" * 60)
        
        main_func = func_mgr.getFunctionAt(
            program.getAddressFactory().getAddress("main")
        ) if program.getAddressFactory().getAddress("main") else None
        
        # Try to find main by name if address lookup fails
        if not main_func:
            for func in func_mgr.getFunctions(True):
                if func.getName() == "main":
                    main_func = func
                    break
        
        if main_func:
            decompile_function(flat_api, main_func)
        else:
            print("  main function not found, decompiling first function...")
            if func_list:
                decompile_function(flat_api, func_list[0])
        
        # 4. Find cross-references to an address
        print("\n[+] Cross-reference analysis:")
        print("-" * 60)
        
        if func_list:
            example_func = func_list[0]
            refs = flat_api.getReferencesTo(example_func.getEntryPoint())
            print(f"  References to {example_func.getName()}:")
            
            ref_count = 0
            for ref in refs:
                print(f"    From: {ref.getFromAddress()} (Type: {ref.getReferenceType()})")
                ref_count += 1
                if ref_count >= 5:
                    print(f"    ... (showing first 5 references)")
                    break
        
        # 5. Memory map information
        print("\n[+] Memory Blocks:")
        print("-" * 60)
        
        memory = program.getMemory()
        for block in memory.getBlocks():
            print(f"  {block.getName()}: {block.getStart()} - {block.getEnd()}")
            print(f"    Permissions: R={block.isRead()} W={block.isWrite()} X={block.isExecute()}")


def decompile_function(flat_api, function):
    """
    Decompile a specific function
    
    Args:
        flat_api: Ghidra FlatProgramAPI instance
        function: Function object to decompile
    """
    from ghidra.app.decompiler import DecompInterface
    
    decompiler = DecompInterface()
    decompiler.openProgram(flat_api.getCurrentProgram())
    
    result = decompiler.decompileFunction(function, 30, None)
    
    if result.decompileCompleted():
        print(f"  Function: {function.getName()} at {function.getEntryPoint()}")
        print(f"  Signature: {function.getSignature()}")
        print("\n  Decompiled code:")
        print("-" * 60)
        
        decomp_code = result.getDecompiledFunction().getC()
        # Print first 30 lines
        lines = decomp_code.split('\n')
        for i, line in enumerate(lines[:30]):
            print(f"  {line}")
        if len(lines) > 30:
            print(f"  ... ({len(lines) - 30} more lines)")
    else:
        print(f"  Decompilation failed: {result.getErrorMessage()}")


def get_decompiled_code_at_address(binary_path, address_str):
    """
    Get decompiled code at a specific address
    
    Args:
        binary_path: Path to binary
        address_str: Address as string (e.g., "0x401000")
    """
    with pyghidra.open_program(binary_path, analyze=True) as flat_api:
        program = flat_api.getCurrentProgram()
        
        # Parse address
        addr = program.getAddressFactory().getAddress(address_str)
        
        # Find function containing this address
        func_mgr = program.getFunctionManager()
        func = func_mgr.getFunctionContaining(addr)
        
        if func:
            print(f"[+] Found function at {address_str}: {func.getName()}")
            decompile_function(flat_api, func)
        else:
            print(f"[!] No function found at address {address_str}")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python script.py <binary_path> [address]")
        print("\nExamples:")
        print("  python script.py /path/to/binary")
        print("  python script.py /path/to/binary 0x401000")
        sys.exit(1)
    
    binary_path = sys.argv[1]
    
    if len(sys.argv) == 3:
        # Decompile at specific address
        address = sys.argv[2]
        get_decompiled_code_at_address(binary_path, address)
    else:
        # Full analysis
        analyze_binary(binary_path)
