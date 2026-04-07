from llm_interact import LLM_INTERACT
import logging
import json

logging.basicConfig(level=logging.INFO)

class ANALYZE_VT:
  def __init__(self):
    self.MODEL = "openai/gpt-4o-mini"
    self.LLM = LLM_INTERACT()
    self.MAX_RETRIES = 3

  def open_file(self, path: str, mode: str) -> str:
    try:
      with open(path, mode, encoding="utf-8") as f:
        return f.read()
    except Exception as e:
      logging.critical(f"Error opening `{path}`.")
      return "NO FILE CONTENT REPORTED. ASSUME NO CODE"

  # Returns true if match should be accepted, false if not
  def analyze(self, json_filepath: str) -> bool:
    system_prompt = self.open_file("cfg/vtanalyze_system.txt","r")
    with open(json_filepath) as f: 
      match_info = json.load(f)
      src_decomp = self.open_file(match_info["src_file_path"],"r")
      dst_decomp = self.open_file(match_info["dst_file_path"],"r")

      user_prompt = f"Analyze the potential match proposed via Ghidra Version Tracking:\nSOURCE DECOMP:{src_decomp}\nDST DECOMP:{dst_decomp}"

      messages = [
          {"role":"system","content":system_prompt},
          {"role":"user","content":user_prompt}
      ] 

      response = self.LLM.query_LLM(self.MODEL, messages)

      try: 
        should_apply = response["choices"][0]["message"]["content"]

        if ("true" in should_apply.lower()):
          print("true")
          return True
        elif ("false" in should_apply.lower()):
          print("false")
          return False
        else:
          logging.critical("Unexpected response. Returning false")
          return False
      except Exception as e:
        logging.critical(f"Exception: {e}")
        return False

      return False
      
