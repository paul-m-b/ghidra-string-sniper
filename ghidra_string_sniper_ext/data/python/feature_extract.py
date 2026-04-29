from llm_interact import LLM_INTERACT
from gss_paths import matches_json_path, decomps_dir
import logging
import json

logging.basicConfig(level=logging.INFO)

'''
The goal of this experimental class is to extract features such as function headers,
variable names, variable types, and other information from open source code to ultimately 
place into ghidra.

This feature extraction will happen between open source code and decompilation that has received
a certain confidence value during the function matching process.
'''

class FEATURE_EXTRACT:
    def __init__(self):
        self.MODEL="openai/gpt-4o-mini"
        self.LLM = LLM_INTERACT()
        self.CONFIDENCE_THRESHOLD = 6.5

    def open_file(self, path: str, mode: str) -> str:
        try:
            with open(path, mode, encoding="utf-8", errors="replace") as f:
                return f.read()
        except Exception as e:
            logging.critical(f"Error opeing `{path}`.")
            return "NO FILE CONTENT REPORTED. ASSUME NO CODE"

    def extract_features(self, str_hash: str, decomp_func_path: str, source_func_path: str):
        decomp_func = self.open_file(decomp_func_path, "r")
        source_func = self.open_file(source_func_path, "r")
        
        # Extract function name from decompiled function
        function_name = self.extract_function_name(decomp_func)
        
        system_prompt = self.open_file("cfg/featext_system.txt", "r")
        
        # Update system prompt to include function name in output
        json_system_prompt = system_prompt + """
        
        IMPORTANT: Output your results as a JSON object with the following structure:
        {
            "function_name": "name_of_the_function",
            "function_signature": {
                "original": "original signature",
                "proposed": "proposed signature"
            },
            "variables": [
                {
                    "original_name": "uVar1",
                    "proposed_name": "count",
                    "original_type": "undefined4",
                    "proposed_type": "int"
                }
            ],
            "function_renames": [
                {
                    "original": "FUN_1234",
                    "proposed": "get_string"
                }
            ]
        }
        
        CRITICAL CONSISTENCY RULES:
        1. The "function_name" field MUST reflect the FINAL function name after applying any renames
        2. If you propose a function rename in "function_signature.proposed", the "function_name" field MUST use the new name
        3. ALL variable renames and retypes MUST use the FINAL function name from the "function_name" field
        4. DO NOT include variables within the function signature inside the "variables" field
        5. Do NOT include a separate "function_renames" array - handle all function renames through the signature change
        """
        
        user_prompt = f"Analyze these functions:\nDECOMPILATION:\n{decomp_func}\n---\nOPEN-SOURCE CODE:\n{source_func}\n---"
        
        messages = [
            {"role": "system", "content": json_system_prompt},
            {"role": "user", "content": user_prompt}
        ]
        
        response = self.LLM.query_LLM(self.MODEL, messages)
        content = response["choices"][0]["message"]["content"]
        
        # Clean the response
        content = self.clean_json_response(content)
        
        # Parse and validate JSON
        try:
            features = json.loads(content)
            
            # Ensure function_name is present
            if 'function_name' not in features:
                features['function_name'] = function_name
                
            # Write JSON file
            fpath = decomps_dir() / str_hash / "EXTRACTIONS.json"
            with open(fpath, "w", encoding="utf-8") as f:
                json.dump(features, f, indent=2)
                logging.info(f"Wrote feature proposals to {fpath}")
                
        except json.JSONDecodeError as e:
            logging.error(f"Failed to parse LLM response as JSON: {e}")
            logging.error(f"Raw response: {content}")

    def extract_function_name(self, decomp_func: str) -> str:
        """Extract function name from decompiled function text"""
        import re
        
        # Look for function signature patterns
        # Common patterns: void FUN_00123456(...) or int main(...)
        patterns = [
            r'(\w+)\s+([A-Za-z_][A-Za-z0-9_]+)\s*\(',
            r'([A-Za-z_][A-Za-z0-9_]+)\s*\(',
        ]
        
        lines = decomp_func.split('\n')
        for line in lines:
            for pattern in patterns:
                match = re.search(pattern, line)
                if match:
                    # If pattern has two groups, take the second (function name)
                    if len(match.groups()) > 1:
                        return match.group(2)
                    else:
                        return match.group(1)
        
        return "unknown_function"

    def clean_json_response(self, content: str) -> str:
        """Clean LLM response to extract JSON"""
        content = content.strip()
        
        # Remove markdown code blocks
        if content.startswith('```json'):
            content = content[7:]
        elif content.startswith('```'):
            content = content[3:]
        
        if content.endswith('```'):
            content = content[:-3]
        
        content = content.strip()
        
        # If no JSON object found, try to extract it
        if not (content.startswith('{') and content.endswith('}')):
            import re
            json_match = re.search(r'\{.*\}', content, re.DOTALL)
            if json_match:
                content = json_match.group(0)
        
        return content

    '''
    Iterate through function matching results and run suitable matches through feature extraction.
    '''
    def iterate_results(self):
        logging.info("Starting feature extraction...")

        match_file_content = self.open_file(str(matches_json_path()), "r")
        matches = json.loads(match_file_content)

        for str_hash in matches:
            source_path, confidence = matches[str_hash]

            if (confidence < self.CONFIDENCE_THRESHOLD):
                continue

            decomp_path = str(decomps_dir() / str_hash / "decomp.txt")

            logging.info(f"Analyzing {source_path}")
            self.extract_features(str_hash, decomp_path, source_path)
