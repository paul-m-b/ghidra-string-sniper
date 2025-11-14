from llm_interact import LLM_INTERACT
from collections import Counter
import subprocess
import logging
import json
import math
import re
import sys
import pyhidra

class STRING_PRIORITIZE:
    def __init__(self):
        self.MODEL = "openai/gpt-oss-20b:free"
        self.LLM = LLM_INTERACT()
        self.MAX_STRING_COUNT = 50

    '''
    Calculate the shannon entropy for a particular string.
    '''
    def shannon_entropy(self, s: str) -> float:
        if not s: return 0.0
        counts = Counter(s)
        n = len(s)
        return -sum((c/n) * math.log2(c/n) for c in counts.values())


    '''
    Calculate the structural entropy for a particular string.
    '''
    def structural_entropy(self, s: str) -> float:
        patterns = re.findall(r'(.{2,}?)\1+', s)
        pattern_score = sum(len(match[0]) * len(match[0]) for match in patterns) / len(s)

        char_classes = {
            'lower': len(re.findall(r'[a-z]', s)),
            'upper': len(re.findall(r'[A-Z]', s)), 
            'digit': len(re.findall(r'\d', s)),
            'special': len(re.findall(r'[^a-zA-Z0-9]', s))
        }

        diversity = sum(1 for count in char_classes.values() if count > 0) / 4.0

        return pattern_score * diversity


    '''
    Calculate the combined entropy score for a string
    '''
    def get_entropy_score(self, string: str) -> float:
        shannon = self.shannon_entropy(string) * 0.7
        structural = (1 - self.structural_entropy(string)) * 0.3

        score = shannon + structural

        return score


    '''
    Returns string list sorted by the combined entropy score of each string
    '''
    def get_entropy_list(self, string_list: list) -> list:
        entropy_dict = {}
        for string in string_list:
            score = self.get_entropy_score(string)

            entropy_dict[string] = score
        sorted_strings = sorted(entropy_dict, key=entropy_dict.get, reverse=True)

        return sorted_strings


    '''
    Returns list of strings containing common opensource signatures.
    Also removes the matched strings from the list.
    '''
    def get_opensource_strings(self, string_list: list) -> list:
        opensource_strings = {
            "openssl": ["SSL_", "TLS_", "RSA_", "EC_", "BIO_", "X509_","OPENSSL_", "EVP_", "MD5_", "SHA256_"],
            "zlib": ["zlib_version", "deflate", "inflate", "gz"],
            "libcurl": ["curl_", "CURLOPT_", "CURLINFO_"],
            "boost": ["boost::", "_bi_", "boost_"],
            "qt": ["QObject", "QString", "QtCore", "qMain"],
            "opengl": ["glEnable", "glVertex", "GL_", "glu"],
            "sqlite": ["sqlite3_", "SQLITE_"]
        }

        for catagory, patterns in opensource_strings.items():
            matches = []
            for string in string_list:
                for pattern in patterns:
                    if pattern.lower() in string.lower():
                        string_list.remove(string)
                        matches.append(string)
                        break

        return matches


    '''
    Returns true or false depending on whether or not a string should be removed depending on its catagory
    Chat this *may* be a bad idea
    '''
    def string_properties(self, string: str, catagory: str) -> bool:
        threshold: int = 4

        if (catagory == "system_libraries"):
            return True     # Always should be removed
        elif(catagory == "oop_strings"):
            threshold = 6   # Small threshold bec of short keywords like get and set 
        elif(catagory == "debugging_strings"):
            threshold = 16  # Longer to cover short nonspecific dbg strings
        elif(catagory == "error_strings"):
            threshold = 25  # Longer to cover short nonspecific error messages
        elif(catagory == "variable_type_strings"):
            threshold = 6   # Small threshold to weed out short variable and type names
        elif(catagory == "math_strings"):
            threshold = 6   # Small threshold to weed out math constants and operations
        elif(catagory == "misc"):
            return True # Always should be removed

        if (len(string) <= threshold):
            return True
        
        return False


    '''
    Removes common strings that will typically show up in binaries.
    These are strings that may return as high entropy, but we know are useless for our purposes.

    could this be turned into a map or something else for O(1)? `in` is a O(n) probably
    '''
    def remove_common_strings(self, string_list: list) -> list:
        comprehensive_list = {
            "system_libraries": [
                # system libraries
                "KERNEL32.dll", "USER32.dll", "ntdll.dll",
                "libstdc++.so", "libgcc_s.so", "libm.so"
            ],

            "oop_strings": [
                # OOP patterns
                "get", "set", "create", "destroy", "init", "cleanup",
                "free", "new", "delete", "open", "close", "read", "write", 
                "seek", "tell", "constructor", "destructor", "virtual", 
                "override", "public:", "private:", "protected:", "this->", 
                "Object", "Base", "Derived", "Impl", "Interface",
                "Manager", "Handler", "Factory", "Singleton"
            ],

            "debugging_strings": [
                # Common debug strings
                "DEBUG", "INFO", "WARN", "ERROR", "FATAL",
                "TRACE", "DBG", "[DEBUG]", "[ERROR]",
                "Entering", "Exiting", "Initializing", "Shutting down",
                "Loading", "Unloading", "Starting", "Stopping",
                "Assertion failed", "assert(", "ASSERT("
            ],

            "error_strings": [
                # Common error message stuff
                "%s", "%d", "%f", "%x", "%p", "%.*s",
                "%02x", "%04x", "%08x", "%016x",
                "Error", "Warning", "Success", "Failed",
                "Invalid", "NULL", "Null", "nil",
                "Not found", "No such file", "Permission denied",
                "Out of memory", "Buffer overflow",
                "stdin", "stdout", "stderr", "STDIN", "STDOUT", "STDERR"
            ],

            "variable_type_strings": [
                # Some common variable and type names
                "temp", "tmp", "buf", "buffer", "data", "ptr",
                "size", "length", "count", "index",
                "result", "status", "int", "char", 
                "float", "double", "void", "bool",
                "string", "String", "str", "wchar", "byte",
                "struct", "class", "enum", "typedef"
            ],

            "math_strings": [
                # Constants and operations
                "M_PI", "M_E", "infinity", "nan", "null",
                "true", "false", "YES", "NO",
                "sin", "cos", "tan", "log", "exp", "sqrt",
                "min", "max", "abs", "pow", "ceil", "floor"
            ],

            "misc": [
                "abcdefghijklmnopqrstuvwxyz",
                "123456789",
                "qwertyui",
                "zyxwvutsrqponmlkjihgfedcba",
                "987654321",
                "iuytrewq",
                "This program cannot be run in DOS mode."
            ]
        }

        modified_strings = list(string_list)

        for string in string_list:
            for catagory, common_strings in comprehensive_list.items():
                for common in common_strings:
                    if (string.lower() in common.lower() and self.string_properties(string, catagory)):
                        try:
                            modified_strings.remove(string)
                        except:
                            continue

        return modified_strings


    '''
    For now, uses strings for ease of development/testing.
    TODO: Connect with ghidra to get strings from it.
        - less dependancies. 
        - this is a ghidra extension ultimately, so why not use ghidra instead of strings

    Get strings, do non-LLM prioritization, then return a curated list of strings to pass to LLM
    '''
    def get_strings(self, binpath: str) -> list:
        cmd = ["strings","-a","-n","4",binpath]

        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        stdout = result.stdout
        string_list = stdout.split("\n")

        string_list = self.remove_common_strings(string_list)
        string_list = self.get_entropy_list(string_list)
        string_list = string_list[:self.MAX_STRING_COUNT]

        return string_list
    
    '''
    Get strings from stdin, do non-LLM prioritization, then return a curated list of strings to pass to LLM
    '''
    def get_strings_stdin(self) -> list:
        print("Enter strings:")
        string_list = [line.rstrip() for line in sys.stdin]

        string_list = self.remove_common_strings(string_list)
        string_list = self.get_entropy_list(string_list)
        string_list = string_list[:self.MAX_STRING_COUNT]

        return string_list
    

    '''
    Simply retrieve a text file's contents.
    '''
    def get_prompt(self, prompt_path: str) -> str:
        try:
            with open(prompt_path, "r") as f:
                return (f.read())
        except Exception as e:
            logging.critical(f"Getting prompt `{prompt_path}` failed.")
            raise e


    def prioritize_strings(self):
        system_prompt = self.get_prompt("cfg/strprioritize_system.txt")
        user_prompt = str(self.get_strings_stdin())
        response_format = json.loads(self.get_prompt("cfg/strprioritize_response.json"))

        messages = [
            {"role":"system","content":system_prompt},
            {"role":"user","content":user_prompt}
        ]

        response = self.LLM.query_LLM(self.MODEL, messages, [])
        content = response["choices"][0]["message"]["content"].split("\n")

        output = {}
        for string in content:
            output[string[:-2]] = { "confidence" : int(string[-2:]), "entropy" : self.get_entropy_score(string[:-2]) }
         
        print (output)
        
        with open('results.json', 'w') as f:
            json.dump(output, f, indent=2)

        return response

    def _get_strings_via_pyhidra(self, binpath: str) -> list[str]:
        """
        Preferred: open program in-process via pyhidra and enumerate defined string data.
        """
        # Start Ghidra env once; safe to call multiple times
        pyhidra.start()

        # Open the program; yields a FlatProgramAPI ("flat")
        with pyhidra.open_program(binpath, project_location="/tmp/pyhidra_proj", project_name="strings_proj") as flat:
            program = flat.getCurrentProgram() if hasattr(flat, "getCurrentProgram") else flat.program
            listing = program.getListing()
            data_iter = listing.getDefinedData(True)

            strings = []
            while data_iter.hasNext():
                data = data_iter.next()
                dt_name = data.getDataType().getName().lower()
                # Cover ASCII/UTF-16 strings Ghidra defines (e.g., "string", "unicode", "utf16")
                if "string" in dt_name or "unicode" in dt_name or "utf" in dt_name:
                    try:
                        val = data.getValue()
                        s = str(val) if val is not None else data.getDefaultValueRepresentation()
                        strings.append(s)
                    except Exception:
                        # Some datatypes may not convert cleanly; skip
                        continue
        print(strings)


a = STRING_PRIORITIZE()
b = a._get_strings_via_pyhidra("/home/paul/gss/ghidra-string-sniper/ghidra_string_sniper_ext/data/python/test.o")
