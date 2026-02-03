import json
import logging
import os
from pathlib import Path

import requests

class LLM_INTERACT:
    def __init__(self, 
             path: str = "TOKEN",
             endpoint: str = "https://openrouter.ai/api/v1/chat/completions"):
        self.KEY = self.read_key(path)
        self.ENDPOINT = endpoint

    def read_key(self, path: str) -> str:
        env_token = os.environ.get("GSS_TOKEN", "").strip()
        if env_token:
            env_path = Path(env_token)
            if env_path.exists():
                return env_path.read_text().strip()
            return env_token

        with open(path, "r") as f:
            try:
                return f.read().strip()
            except Exception:
                raise KeyError

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
