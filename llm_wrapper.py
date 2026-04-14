"""
LLM Wrapper for Ollama
Provides interface to local LLM for threat analysis
"""
import asyncio
import json
import re
import ollama
from typing import Dict, Any, Optional, List
import config


class LLMWrapper:
    """Wrapper for Ollama LLM interactions"""

    def __init__(self, model: str = None, host: str = None):
        self.model = model or config.OLLAMA_MODEL
        self.host = host or config.OLLAMA_HOST
        self.client = ollama.Client(
            host=self.host,
            timeout=config.LLM_TIMEOUT
        )

    def is_available(self) -> bool:
        """Check if LLM is available"""
        try:
            self.client.list()
            return True
        except Exception:
            return False

    def list_models(self) -> List[str]:
        """List available models"""
        try:
            response = self.client.list()
            # ollama >= 0.4 returns objects with .models attribute
            models = response.models if hasattr(response, 'models') else response.get('models', [])
            return [m.model if hasattr(m, 'model') else m.get('name', '') for m in models]
        except Exception:
            return []

    def pull_model(self) -> bool:
        """Pull model if not available"""
        try:
            print(f"Pulling model {self.model}... (this may take a few minutes)")
            self.client.pull(self.model)
            print(f"Model {self.model} ready!")
            return True
        except Exception as e:
            print(f"Failed to pull model: {e}")
            return False

    def ensure_model(self) -> bool:
        """Ensure model is pulled"""
        try:
            models = self.list_models()
            if self.model not in models and f"{self.model}:latest" not in models:
                return self.pull_model()
            return True
        except Exception as e:
            print(f"Error ensuring model: {e}")
            return False

    def generate(self, prompt: str, system_prompt: Optional[str] = None,
                 temperature: float = 0.7, json_mode: bool = False) -> Optional[str]:
        """Generate text from prompt"""
        try:
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

            kwargs = {
                "model": self.model,
                "messages": messages,
                "options": {"temperature": temperature},
            }
            # format is a top-level param in ollama >= 0.4, not inside options
            if json_mode:
                kwargs["format"] = "json"

            response = self.client.chat(**kwargs)

            # Handle both dict and object response formats
            msg = response.message if hasattr(response, 'message') else response.get('message', {})
            return msg.content if hasattr(msg, 'content') else msg.get('content', '')

        except Exception as e:
            print(f"LLM generation error: {e}")
            return None

    def generate_json(self, prompt: str, system_prompt: Optional[str] = None) -> Optional[Dict[Any, Any]]:
        """Generate response and parse as JSON"""
        response = self.generate(prompt, system_prompt, json_mode=True)
        if not response:
            return None

        return self.extract_json(response)

    async def agenerate(self, prompt: str, system_prompt: Optional[str] = None,
                        temperature: float = 0.7, json_mode: bool = False) -> Optional[str]:
        """Async wrapper - runs blocking generate in a thread pool"""
        return await asyncio.to_thread(self.generate, prompt, system_prompt, temperature, json_mode)

    async def agenerate_json(self, prompt: str, system_prompt: Optional[str] = None) -> Optional[Dict[Any, Any]]:
        """Async wrapper - runs blocking generate_json in a thread pool"""
        return await asyncio.to_thread(self.generate_json, prompt, system_prompt)

    def extract_json(self, text: str) -> Optional[Dict[str, Any]]:
        """Extract JSON from LLM response text"""
        # Try direct parse
        try:
            return json.loads(text)
        except (json.JSONDecodeError, TypeError):
            pass

        # Try to find JSON in markdown code blocks
        matches = re.findall(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
        if matches:
            try:
                return json.loads(matches[0])
            except (json.JSONDecodeError, TypeError):
                pass

        # Try to find raw JSON object
        matches = re.findall(r'\{.*\}', text, re.DOTALL)
        if matches:
            try:
                return json.loads(matches[0])
            except (json.JSONDecodeError, TypeError):
                pass

        return None
