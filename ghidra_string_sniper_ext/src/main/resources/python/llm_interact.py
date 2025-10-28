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

    def query_LLM(self, _model: str, _messages: list, _tools: list=[], _response_format: dict={}) -> object:
        data={
            "model":_model,
            "messages":_messages,
        }

        if (_tools):
            data["tools"] = _tools
        if (_response_format):
            data["response_format"] = _response_format

        data = json.dumps(data)

        response = requests.post(
                url=self.ENDPOINT,
                headers={
                    "Authorization":f"Bearer {self.KEY}",
                    "Content-Type":"application/json",
                },
                data = data)
        return response.json()
