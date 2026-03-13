import json
from pathlib import Path
from ghidra.script import GhidraScript

class BATCH_FEATURE_APPLIER(GhidraScript):
    def run(self):
        matches_file = "/path/to/matches.json"
        decomps_dir = "/path/to/decomps"
        
        with open(matches_file, 'r') as f:
            matches = json.load(f)
        
        applier = FEATURE_APPLIER()
        
        # Process each function
        for str_hash, (source_path, confidence) in matches.items():
            if confidence >= 8:  # Confidence threshold
                features_path = Path(decomps_dir) / str_hash / "EXTRACTIONS.txt"
                
                if features_path.exists():
                    # Get function name from decomp or source
                    # TODO: make this work
                    func_name = f"FUNC_{str_hash}"
                    
                    print(f"\nProcessing function {func_name} (hash: {str_hash})")
                    applier.apply_changes(func_name, str(features_path))
                else:
                    print(f"No features file for {str_hash}")
        
        print("\nBatch processing complete")