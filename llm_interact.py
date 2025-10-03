import requests
import json
import logging

class LLM_INTERACT:
    def __init__(self, 
             path: str = "TOKEN",
             endpoint: str = "https://openrouter.ai/api/v1/chat/completions"):

        self.KEY = self.read_key(path)
        self.ENDPOINT = endpoint

    def read_key(self, path: str) -> str:
        with open(path, "r") as f:
            try:
                return f.read().strip()
            except:
                raise KeyError
        return

    def query_LLM(self, _model: str, _messages: list, _tools: list) -> object:
        response = requests.post(
                url=self.ENDPOINT,
                headers={
                    "Authorization":f"Bearer {self.KEY}",
                    "Content-Type":"application/json",
                },
                data=json.dumps({
                    "model":_model,
                    "messages":_messages,
                    "tools":_tools
                }))
        return response.json()
