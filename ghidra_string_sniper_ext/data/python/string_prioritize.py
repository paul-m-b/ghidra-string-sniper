from llm_interact import LLM_INTERACT
from collections import Counter
from pathlib import Path
import subprocess
import logging
import json
import math
import re
import sys
import hashlib
import os
import re

import pyghidra

logging.basicConfig(level=logging.INFO)

class STRING_PRIORITIZE:
    def __init__(self):
        #self.MODEL = "openai/gpt-oss-20b:free"
        self.MODEL = "openai/gpt-4o-mini"
        self.LLM = LLM_INTERACT()
        self.MAX_STRING_COUNT = 10
        self.MAX_DEPTH = 4
        self.MAX_RETRIES = 2

    '''
    Calculate the shannon entropy for a particular string.
    '''
    def shannon_entropy(self, s: str):
        if not s: return 0.0
        counts = Counter(s)
        n = len(s)
        return -sum((c/n) * math.log2(c/n) for c in counts.values())

    '''
    Calculate the shannon entropy for each string and return its sorted form.
    '''
    def get_shannon_list(self, string_list: list) -> list:
        shannon_dict = {}
        for string in string_list:
            shannon_dict[string] = self.shannon_entropy(string)
        sorted_strings = sorted(shannon_dict, key=shannon_dict.get, reverse=True)

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
    Removes common strings that will typically show up in binaries.
    These are strings that may return as high entropy, but we know are useless for our purposes.

    could this be turned into a map or something else for O(1)? `in` is a O(n) probably
    '''
    def remove_common_strings(self, string_list: list) -> list:
        common_patterns = [
            "abcdefghijklmnopqrstuvwxyz",
            "qwertyuiop",
            "asdfghjkl",
            "zxcvbnm",
            "1234567890",
            "!@#$%^&*()",
            "zyxwvutsrqponmlkjihgfedcba",
            "0987654321",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        ]
        
        filtered = []
        for string in string_list:
            string_lower = string.lower()
            is_common = any(pattern in string_lower for pattern in common_patterns)
            
            if not is_common:
                filtered.append(string)
                
        return filtered
    
    '''
    Filter strings based on reasonable entropy ranges for meaningful text
    '''
    def filter_by_entropy(self, string_list: list, min_entropy=2.0, max_entropy=5.5) -> list:
        filtered = []
        for string in string_list:
            entropy = self.shannon_entropy(string)
            if min_entropy <= entropy <= max_entropy:
                filtered.append(string)
        return filtered

    '''
    Check if string has reasonable mix of character types
    '''
    def has_reasonable_character_distribution(self, string_list: list) -> list:
        filtered = []

        for string in string_list:
            alpha_count = sum(1 for c in string if c.isalpha())
            digit_count = sum(1 for c in string if c.isdigit())
            special_count = len(string) - alpha_count - digit_count
            
            # Reasonable strings should have decent alpha content
            # and not be dominated by special characters
            alpha_ratio = alpha_count / len(string)
            special_ratio = special_count / len(string)
            
            if alpha_ratio > 0.3 and special_ratio < 0.65:
                filtered.append(string)

        return filtered

    '''
    Filter out strings that match useless patterns
    '''
    def filter_patterns(self, string_list: list) -> list:
        patterns_to_filter = [
            r'^[a-z]+$',  # All lowercase sequential
            r'^[A-Z]+$',  # All uppercase sequential  
            r'^[0-9]+$',  # All digits
            r'^[!-~]+$',  # All printable ASCII in order
            r'^[A-Za-z0-9!-~]+$',  # All printable ASCII ranges
            r'^(.{1,3})\1+$',  # Repeated short sequences
        ]
        
        filtered = []
        for string in string_list:
            is_bad_pattern = any(re.match(pattern, string) for pattern in patterns_to_filter)
            
            if not is_bad_pattern:
                filtered.append(string)
                
        return filtered

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
        string_list = self.filter_patterns(string_list) 
        string_list = self.filter_by_entropy(string_list)
        string_list = [s for s in string_list if self.has_reasonable_character_distribution(s)]
        string_list = self.get_shannon_list(string_list)
        string_list = string_list[:self.MAX_STRING_COUNT]

        return string_list
    
    '''
    Get strings from stdin, do non-LLM prioritization, then return a curated list of strings to pass to LLM
    '''
    def get_strings_stdin(self) -> list:
        print("Enter strings:")
        string_list = [line.rstrip() for line in sys.stdin]

        string_list = self.remove_common_strings(string_list)
        string_list = self.filter_patterns(string_list) 
        string_list = self.filter_by_entropy(string_list)
        string_list = [s for s in string_list if self.has_reasonable_character_distribution(s)]
        string_list = self.get_shannon_list(string_list)
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


    '''
    Given a binary path, extract all strings from ghidra, perform non-LLM heuristics to 
    order them and then pass into an LLM query for final reordering.
    '''
    def prioritize_strings(self, binpath: str, lang: str=None, retries: int=0):
        system_prompt = self.get_prompt("cfg/strprioritize_system.txt")
        user_prompt = str(self.get_ghidra_strings(binpath, lang=lang))

        messages = [
            {"role":"system","content":system_prompt},
            {"role":"user","content":user_prompt}
        ]

        logging.info("Starting reordering LLM query...")

        response = self.LLM.query_LLM(self.MODEL, messages, [])
        try:
            content = response["choices"][0]["message"]["content"].split("\n")
        except:
            if (retries >= self.MAX_RETRIES):
                raise e
            else:
                logging.critical(f"LLM Failure. Restarting Prioritize Strings.\n\t{e}")

                tries = retries
                language = lang 
                self.prioritize_strings(binpath, lang=language, retries=tries+1)


        #TODO THIS SHOULD NOT BE USING STRING SPLICING. AT LEAST SPLIT THE STRING AND GRAB THE LAST PART OR SOMETHING
        # WILL FIX LATER

        output = {}
        logging.info(content)
        for string in content:
            string = string.split("--GSS_DELIM--")

            actual_string = string[0]
            actual_string = self.normalize_string(actual_string)
            folder_name = actual_string.encode("utf-8")
            md5_hash = hashlib.md5()
            md5_hash.update(folder_name)
            folder_name = str(md5_hash.hexdigest())
            
            try:
                confidence_value = int(string[1])
            except ValueError as e:
                if (retries >= self.MAX_RETRIES):
                    raise e
                else:
                    logging.critical(f"LLM Failure. Restarting Prioritize Strings.\n\t{e}")

                    tries = retries
                    language = lang 
                    self.prioritize_strings(binpath, lang=language, retries=tries+1)

            output[string[0]] = {
                    "confidence" : int(string[1]),
                    "entropy" : self.shannon_entropy(string[0]),
                    "hash": folder_name
            }
         
        with open('results.json', 'w') as f:
            json.dump(output, f, indent=2)

        return response

    '''
    Get strings using Pyghidra API.
    Also, run non-LLM heuristics on the strings.
    Once strings are ordered by said heuristics, extract decompiled code from Ghidra for each string
    '''
    def get_ghidra_strings(self, binary_path: str, lang: str=None) -> list[str]:
        logging.info("Loading binary into ghidra..")
        with pyghidra.open_program(binary_path, analyze=True, language=lang) as flat_api:
            from ghidra.app.decompiler import DecompInterface
            from ghidra.util.task import ConsoleTaskMonitor

            program = flat_api.getCurrentProgram()

            logging.info(f"Analyzing: {program.getName()}")
            logging.info(f"Language: {program.getLanguageID()}")

            logging.info(f"Getting all strings...")

            string_mgr = program.getListing().getDefinedData(True)
            string_count = 0

            string_list = []
            string_addrs = {}
            for data in string_mgr:
                if not data.hasStringValue():
                    continue
                addr = data.getAddress()
                string_val = data.getValue()
                string_addr = data.getAddress()

                string_list.append(string_val)
                string_addrs[string_val] = string_addr

            logging.info("Running non-LLM heuristics...")

            string_list = self.remove_common_strings(string_list)
            string_list = self.filter_patterns(string_list) 
            string_list = self.filter_by_entropy(string_list)
            string_list = self.has_reasonable_character_distribution(string_list)
            string_list = self.get_shannon_list(string_list)
            string_list = string_list[:self.MAX_STRING_COUNT]

            #get decomp for all the prioritized strings

            logging.info("Getting decomp for non-LLM ordered strings...")

            for string in string_list:
                str_addr = string_addrs[string]
                references = flat_api.getReferencesTo(str_addr)

                if (not references):
                    logging.critical(f"No references to '{string}' found.")
                    continue

                decompiler = DecompInterface()
                decompiler.openProgram(program)

                seen_functions = set()

                all_decomp = ""
                for ref in references:
                    from_addr = ref.getFromAddress()
                    function = flat_api.getFunctionContaining(from_addr)

                    #look for nested function references
                    if (not function):
                        logging.info("Calling recursive reference search.")
                        function = self.search_for_function(flat_api, from_addr, 0)
                    
                    if (not function or function in seen_functions):
                        continue

                    seen_functions.add(function)

                    logging.info(f"Found function: {function.getName()}")
                    logging.info(f"Decompiling {function.getName()}...")

                    result = decompiler.decompileFunction(function, 30, ConsoleTaskMonitor())

                    if result.decompileCompleted():
                        decomp_code = result.getDecompiledFunction().getC()
                        all_decomp += f"{decomp_code}\n\n"
                    else:
                        logging.info(f"Decomp failed for {function.getName()}")

                string = self.normalize_string(string)
                folder_name = string.encode("utf-8")
                md5_hash = hashlib.md5()
                md5_hash.update(folder_name)
                folder_name = str(md5_hash.hexdigest())
                os.makedirs(f"GSS_decomps/{folder_name}/", exist_ok=True)
                with open(f"GSS_decomps/{folder_name}/decomp.txt", "w") as file:
                    file.write(all_decomp)

            return string_list

    def search_for_function(self, flat_api, addr, ctr):
        if (ctr >= self.MAX_DEPTH):
            return None

        references = flat_api.getReferencesTo(addr)
        for ref in references:
            from_addr = ref.getFromAddress()
            function = flat_api.getFunctionContaining(from_addr)

            if (not function):
                return self.search_for_function(flat_api, from_addr, ctr+1)
            else:
                logging.info("Recursive search found function.")
                return function


    def normalize_string(self, s: str) -> str:
        s = s.replace("\\n","").replace("\\t","").replace("\\r","")
        return re.sub(r"\s+","",s)


"""
Since more changes to string_prioritize can easily decrease its effectiveness,
a comprehensive testing function will be helpful when comaring different versions
of string prioritize.
"""
def analyze_string_prioritization(binpath: str = None, use_stdin: bool = False) -> dict:
    
    analyzer = STRING_PRIORITIZE()
    results = {
        "class_configuration": {
            "model": analyzer.MODEL,
            "max_string_count": analyzer.MAX_STRING_COUNT,
            "max_depth": analyzer.MAX_DEPTH,
            "max_retries": analyzer.MAX_RETRIES
        },
        "processing_stages": {},
        "final_results": {},
        "metrics": {},
        "recommendations": []
    }
    
    # Stage 1: String Extraction
    print("=" * 80)
    print("STAGE 1: STRING EXTRACTION")
    print("=" * 80)
    
    if use_stdin:
        print("Reading strings from stdin...")
        raw_strings = analyzer.get_strings_stdin()
    elif binpath:
        print(f"Extracting strings from binary: {binpath}")
        raw_strings = analyzer.get_strings(binpath)
    else:
        print("No input source specified. Using Ghidra method.")
        if not binpath:
            print("ERROR: Binary path required for Ghidra analysis")
            return results
        raw_strings = analyzer.get_ghidra_strings(binpath)
    
    results["processing_stages"]["raw_extraction"] = {
        "count": len(raw_strings),
        "sample_strings": raw_strings[:10] if raw_strings else []
    }
    
    print(f"Extracted {len(raw_strings)} strings")
    if raw_strings:
        print(f"Sample: {raw_strings[:5]}")
    
    # Stage 2: Calculate Shannon Entropy
    print("\n" + "=" * 80)
    print("STAGE 2: SHANNON ENTROPY CALCULATION")
    print("=" * 80)
    
    entropy_dict = {}
    for string in raw_strings:
        entropy_dict[string] = analyzer.shannon_entropy(string)
    
    sorted_by_entropy = sorted(entropy_dict.items(), key=lambda x: x[1], reverse=True)
    
    results["processing_stages"]["entropy_analysis"] = {
        "entropy_range": {
            "min": min(entropy_dict.values()) if entropy_dict else 0,
            "max": max(entropy_dict.values()) if entropy_dict else 0,
            "average": sum(entropy_dict.values()) / len(entropy_dict) if entropy_dict else 0
        },
        "top_10_high_entropy": sorted_by_entropy[:10],
        "bottom_10_low_entropy": sorted_by_entropy[-10:] if len(sorted_by_entropy) > 10 else sorted_by_entropy
    }
    
    print(f"Entropy Range: {results['processing_stages']['entropy_analysis']['entropy_range']}")
    print("Top 5 High Entropy Strings:")
    for string, entropy in sorted_by_entropy[:5]:
        print(f"  {entropy:.3f}: '{string[:50]}...'")
    
    # Stage 3: Identify OpenSource Strings
    print("\n" + "=" * 80)
    print("STAGE 3: OPENSOURCE STRING DETECTION")
    print("=" * 80)
    
    test_strings = raw_strings.copy()
    opensource_matches = analyzer.get_opensource_strings(test_strings)
    
    results["processing_stages"]["opensource_detection"] = {
        "opensource_strings_found": opensource_matches,
        "count": len(opensource_matches),
        "remaining_strings": len(test_strings)
    }
    
    print(f"Found {len(opensource_matches)} opensource-related strings")
    for string in opensource_matches[:5]:
        print(f"  - {string}")
    if len(opensource_matches) > 5:
        print(f"  ... and {len(opensource_matches) - 5} more")
    
    # Stage 4: Common String Removal
    print("\n" + "=" * 80)
    print("STAGE 4: COMMON STRING FILTERING")
    print("=" * 80)
    
    after_common = analyzer.remove_common_strings(raw_strings)
    common_removed = len(raw_strings) - len(after_common)
    
    results["processing_stages"]["common_filtering"] = {
        "strings_removed": common_removed,
        "remaining_count": len(after_common),
        "removal_percentage": (common_removed / len(raw_strings) * 100) if raw_strings else 0
    }
    
    print(f"Removed {common_removed} common strings ({results['processing_stages']['common_filtering']['removal_percentage']:.1f}%)")
    # Stage 5: Entropy Filtering
    print("\n" + "=" * 80)
    print("STAGE 5: ENTROPY-BASED FILTERING")
    print("=" * 80)
    
    after_entropy_filter = analyzer.filter_by_entropy(after_common)
    entropy_filtered = len(after_common) - len(after_entropy_filter)
    
    results["processing_stages"]["entropy_filtering"] = {
        "strings_removed": entropy_filtered,
        "remaining_count": len(after_entropy_filter),
        "filter_range": "2.0 - 5.5",
        "filtered_strings_examples": [
            (s, analyzer.shannon_entropy(s)) 
            for s in set(after_common) - set(after_entropy_filter)
        ][:5]
    }
    
    print(f"Removed {entropy_filtered} strings outside entropy range 2.0-5.5")
    if results['processing_stages']['entropy_filtering']['filtered_strings_examples']:
        print("Examples of filtered strings:")
        for string, entropy in results['processing_stages']['entropy_filtering']['filtered_strings_examples']:
            print(f"  {entropy:.3f}: '{string[:30]}...'")
    
    # Stage 6: Character Distribution Analysis
    print("\n" + "=" * 80)
    print("STAGE 6: CHARACTER DISTRIBUTION FILTERING")
    print("=" * 80)
    
    after_char_dist = analyzer.has_reasonable_character_distribution(after_entropy_filter)
    char_filtered = len(after_entropy_filter) - len(after_char_dist)
    
    # Analyze character distributions
    char_stats = []
    for string in after_entropy_filter:
        alpha_count = sum(1 for c in string if c.isalpha())
        digit_count = sum(1 for c in string if c.isdigit())
        special_count = len(string) - alpha_count - digit_count
        alpha_ratio = alpha_count / len(string) if string else 0
        special_ratio = special_count / len(string) if string else 0
        char_stats.append({
            "string": string,
            "alpha_ratio": alpha_ratio,
            "special_ratio": special_ratio,
            "length": len(string)
        })
    
    results["processing_stages"]["character_distribution"] = {
        "strings_removed": char_filtered,
        "remaining_count": len(after_char_dist),
        "average_alpha_ratio": sum(s["alpha_ratio"] for s in char_stats) / len(char_stats) if char_stats else 0,
        "average_special_ratio": sum(s["special_ratio"] for s in char_stats) / len(char_stats) if char_stats else 0,
        "character_statistics": char_stats[:10]  # First 10 for analysis
    }
    
    print(f"Removed {char_filtered} strings with poor character distribution")
    print(f"Average alpha ratio: {results['processing_stages']['character_distribution']['average_alpha_ratio']:.3f}")
    print(f"Average special char ratio: {results['processing_stages']['character_distribution']['average_special_ratio']:.3f}")

    # Stage 7: Pattern Filtering
    print("\n" + "=" * 80)
    print("STAGE 7: PATTERN-BASED FILTERING")
    print("=" * 80)
    
    after_patterns = analyzer.filter_patterns(after_char_dist)
    pattern_filtered = len(after_char_dist) - len(after_patterns)
    
    results["processing_stages"]["pattern_filtering"] = {
        "strings_removed": pattern_filtered,
        "remaining_count": len(after_patterns),
        "patterns_applied": [
            "All lowercase sequential",
            "All uppercase sequential",
            "All digits",
            "All printable ASCII in order",
            "All printable ASCII ranges",
            "Repeated short sequences"
        ]
    }
    
    print(f"Removed {pattern_filtered} strings matching useless patterns")
    
    # Stage 8: Final Prioritization
    print("\n" + "=" * 80)
    print("STAGE 8: FINAL PRIORITIZATION")
    print("=" * 80)
    
    final_shannon_list = analyzer.get_shannon_list(after_patterns)
    final_strings = final_shannon_list[:analyzer.MAX_STRING_COUNT]
    
    results["processing_stages"]["final_prioritization"] = {
        "shannon_sorted_list": final_shannon_list,
        "top_strings_selected": final_strings,
        "entropy_values": {s: analyzer.shannon_entropy(s) for s in final_strings}
    }
    
    print(f"Selected top {len(final_strings)} strings by Shannon entropy:")
    for i, string in enumerate(final_strings, 1):
        entropy = analyzer.shannon_entropy(string)
        print(f"{i:2d}. [{entropy:.3f}] '{string[:60]}{'...' if len(string) > 60 else ''}'")
    
    # Calculate Overall Metrics
    results["metrics"] = {
        "total_processing_pipeline": {
            "input_strings": len(raw_strings),
            "output_strings": len(final_strings),
            "reduction_percentage": ((len(raw_strings) - len(final_strings)) / len(raw_strings) * 100) if raw_strings else 0,
            "stages_applied": len(results["processing_stages"])
        },
        "efficiency_metrics": {
            "strings_per_stage": [
                {"stage": stage, "count": data.get("remaining_count", data.get("count", 0))}
                for stage, data in results["processing_stages"].items()
            ]
        }
    }
    
    # Generate Recommendations
    recommendations = []
    
    # Check entropy filtering effectiveness
    entropy_range = results["processing_stages"]["entropy_analysis"]["entropy_range"]
    if entropy_range["min"] < 1.0 or entropy_range["max"] > 6.0:
        recommendations.append(
            "Consider adjusting entropy filter bounds based on observed range "
            f"(current: 2.0-5.5, observed: {entropy_range['min']:.2f}-{entropy_range['max']:.2f})"
        )
    
    # Check character distribution thresholds
    char_stats = results["processing_stages"]["character_distribution"]
    if char_stats["average_alpha_ratio"] < 0.2:
        recommendations.append(
            f"Low average alpha ratio ({char_stats['average_alpha_ratio']:.3f}). "
            "Consider relaxing alpha ratio threshold from 0.3 to 0.2"
        )
    
    # Check for potential opensource library detection improvements
    if len(results["processing_stages"]["opensource_detection"]["opensource_strings_found"]) > 0:
        recommendations.append(
            "Opensource strings detected. Consider adding opensource string analysis "
            "to the prioritization pipeline"
        )
    
    # Check pattern filtering efficiency
    pattern_filtered = results["processing_stages"]["pattern_filtering"]["strings_removed"]
    if pattern_filtered / len(raw_strings) > 0.3:
        recommendations.append(
            f"Pattern filtering removed {pattern_filtered} strings ({pattern_filtered/len(raw_strings)*100:.1f}%). "
            "Review patterns to ensure not filtering meaningful strings"
        )
    
    results["recommendations"] = recommendations
    
    print("\n" + "=" * 80)
    print("RECOMMENDATIONS FOR IMPROVEMENT")
    print("=" * 80)
    
    if recommendations:
        for i, rec in enumerate(recommendations, 1):
            print(f"{i}. {rec}")
    else:
        print("No specific recommendations. Current configuration appears optimal.")
    
    # Summary
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    
    metrics = results["metrics"]["total_processing_pipeline"]
    print(f"Input Strings: {metrics['input_strings']}")
    print(f"Output Strings: {metrics['output_strings']}")
    print(f"Reduction: {metrics['reduction_percentage']:.1f}%")
    print(f"Processing Stages: {metrics['stages_applied']}")
    
    return results