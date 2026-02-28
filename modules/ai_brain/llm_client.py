#!/usr/bin/env python3
"""
REDHAVEN AI — Multi-Provider LLM Client
=========================================
Unified interface for Ollama, Gemini, OpenAI, and DeepSeek.
Supports automatic fallback on failure and response sanitization.

Usage:
    from ai_brain.llm_client import LLMClient
    from ai_brain.config import load_config
    
    config = load_config()
    client = LLMClient(config)
    response = client.analyze("Analyze these XSS findings: ...")
"""

import json
import re
import sys
import time
from typing import Optional, Dict, Any

from .config import AIConfig

# ============================================================================
# ANSI Colors (matching RedHaven standard)
# ============================================================================

class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    CYAN = '\033[0;36m'
    DIM = '\033[2m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

# ============================================================================
# Provider Implementations
# ============================================================================

class OllamaProvider:
    """Local LLM via Ollama API."""

    def __init__(self, config: AIConfig):
        self.host = config.ollama.host.rstrip('/')
        self.model = config.get_model("ollama")
        self.max_tokens = config.max_tokens
        self.temperature = config.temperature

    def generate(self, prompt: str, system_prompt: str = "", messages: list = None, tools: list = None) -> Any:
        import requests

        if messages is not None:
            url = f"{self.host}/api/chat"
            
            # Ensure system prompt is first if not already
            chat_msgs = messages.copy()
            if system_prompt and not any(m.get("role") == "system" for m in chat_msgs):
                chat_msgs.insert(0, {"role": "system", "content": system_prompt})
                
            payload = {
                "model": self.model,
                "messages": chat_msgs,
                "stream": False,
                "options": {
                    "temperature": self.temperature,
                    "num_predict": self.max_tokens,
                }
            }
            if tools:
                payload["tools"] = tools

            try:
                resp = requests.post(url, json=payload, timeout=300)
                resp.raise_for_status()
                response_data = resp.json()
                msg = response_data.get("message", {})
                
                if "tool_calls" in msg and msg.get("tool_calls"):
                    return {
                        "content": msg.get("content", ""),
                        "tool_calls": msg["tool_calls"]
                    }
                return msg.get("content", "")
            except requests.exceptions.ConnectionError:
                raise ConnectionError(f"Cannot connect to Ollama at {self.host}.")
            except Exception as e:
                raise RuntimeError(f"Ollama chat error: {e}")
                
        else:
            url = f"{self.host}/api/generate"
            payload = {
                "model": self.model,
                "prompt": prompt,
                "system": system_prompt,
                "stream": False,
                "options": {
                    "temperature": self.temperature,
                    "num_predict": self.max_tokens,
                }
            }

            try:
                resp = requests.post(url, json=payload, timeout=300)
                resp.raise_for_status()
                return resp.json().get("response", "")
            except requests.exceptions.ConnectionError:
                raise ConnectionError(
                    f"Cannot connect to Ollama at {self.host}. "
                    "Make sure Ollama is running: 'ollama serve'"
                )
            except Exception as e:
                raise RuntimeError(f"Ollama error: {e}")

    def is_available(self) -> bool:
        import requests
        try:
            resp = requests.get(f"{self.host}/api/tags", timeout=5)
            return resp.status_code == 200
        except Exception:
            return False


class GeminiProvider:
    """Google Gemini API."""

    def __init__(self, config: AIConfig):
        self.api_key = config.get_api_key("gemini")
        self.model = config.get_model("gemini")
        self.max_tokens = config.max_tokens
        self.temperature = config.temperature

    def generate(self, prompt: str, system_prompt: str = "", messages: list = None, tools: list = None) -> Any:
        try:
            from google import genai
            from google.genai.types import HarmCategory, HarmBlockThreshold, SafetySetting
            from google.genai.types import Tool as GeminiTool, FunctionDeclaration
        except ImportError:
            raise ImportError("Install google-genai: pip install google-genai")

        client = genai.Client(api_key=self.api_key)

        # Extract system text
        sys_text = system_prompt
        chat_contents = []

        if messages:
            for msg in messages:
                if msg.get("role") == "system":
                    sys_text = msg.get("content", "")
                else:
                    # Gemini roles are typically "user" or "model" instead of "assistant"
                    g_role = "model" if msg.get("role") == "assistant" else "user"
                    chat_contents.append({"role": g_role, "parts": [{"text": msg.get("content", "")}]})
        else:
            chat_contents.append({"role": "user", "parts": [{"text": prompt}]})

        # Map OpenAI-style schema to Gemini Tool models
        gemini_tools = None
        if tools:
            func_decls = []
            for t in tools:
                if t.get("type") == "function":
                    func = t["function"]
                    
                    # Gemini expects simple dict for schema translation or building natively. 
                    # genai.types handles standard dict schema mapping mostly fine natively.
                    decl = FunctionDeclaration(
                        name=func["name"],
                        description=func["description"],
                        parameters=func.get("parameters", {})
                    )
                    func_decls.append(decl)
            
            if func_decls:
                gemini_tools = [GeminiTool(function_declarations=func_decls)]

        config_args = {
            "system_instruction": sys_text if sys_text else None,
            "temperature": self.temperature,
            "max_output_tokens": self.max_tokens,
            "safety_settings": [
                SafetySetting(category=HarmCategory.HARM_CATEGORY_HATE_SPEECH, threshold=HarmBlockThreshold.BLOCK_NONE),
                SafetySetting(category=HarmCategory.HARM_CATEGORY_HARASSMENT, threshold=HarmBlockThreshold.BLOCK_NONE),
                SafetySetting(category=HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT, threshold=HarmBlockThreshold.BLOCK_NONE),
                SafetySetting(category=HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT, threshold=HarmBlockThreshold.BLOCK_NONE),
            ]
        }
        if gemini_tools:
            config_args["tools"] = gemini_tools

        response = client.models.generate_content(
            model=self.model,
            contents=chat_contents,
            config=genai.types.GenerateContentConfig(**config_args)
        )
        
        # Check if model returned function calls
        if response.function_calls:
            # We map this back to the OpenAI-style format our Chat UI expects
            tc_list = []
            import uuid
            import json
            for fc in response.function_calls:
                tc_list.append({
                    "id": f"call_{uuid.uuid4().hex[:8]}",
                    "type": "function",
                    "function": {
                        "name": fc.name,
                        "arguments": json.dumps(fc.args) if fc.args else "{}"
                    }
                })
            
            return {
                "content": response.text if response.text else "Executing tools...",
                "tool_calls": tc_list
            }

        return response.text if response.text else ""

    def is_available(self) -> bool:
        return bool(self.api_key)


class OpenAIProvider:
    """OpenAI / DeepSeek API (compatible endpoints)."""

    def __init__(self, config: AIConfig, provider_name: str = "openai"):
        self.provider = provider_name
        self.api_key = config.get_api_key(provider_name)
        self.model = config.get_model(provider_name)
        self.max_tokens = config.max_tokens
        self.temperature = config.temperature

        # DeepSeek uses OpenAI-compatible API
        self.base_url = {
            "openai": "https://api.openai.com/v1",
            "deepseek": "https://api.deepseek.com/v1",
        }.get(provider_name, "https://api.openai.com/v1")

    def generate(self, prompt: str, system_prompt: str = "", messages: list = None, tools: list = None) -> Any:
        import requests

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        if messages is None:
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        
        if tools:
            payload["tools"] = tools

        resp = requests.post(
            f"{self.base_url}/chat/completions",
            headers=headers,
            json=payload,
            timeout=120,
        )
        resp.raise_for_status()
        
        response_data = resp.json()
        msg = response_data["choices"][0]["message"]
        
        if "tool_calls" in msg and msg["tool_calls"]:
            return {
                "content": msg.get("content", ""),
                "tool_calls": msg["tool_calls"]
            }
            
        return msg.get("content", "")
    def is_available(self) -> bool:
        return bool(self.api_key)


# ============================================================================
# Unified LLM Client
# ============================================================================

PROVIDER_MAP = {
    "ollama": OllamaProvider,
    "gemini": GeminiProvider,
    "openai": OpenAIProvider,
    "deepseek": lambda cfg: OpenAIProvider(cfg, "deepseek"),
}


class LLMClient:
    """
    Multi-provider LLM client with automatic fallback.
    
    Usage:
        client = LLMClient(config)
        result = client.analyze("Analyze these findings...")
    """

    def __init__(self, config: AIConfig):
        self.config = config
        self.primary = self._init_provider(config.provider)
        self.fallback = None
        self.active_provider = config.provider

        if config.fallback_provider and not config.local_only:
            try:
                self.fallback = self._init_provider(config.fallback_provider)
            except Exception:
                pass

    def _init_provider(self, provider_name: str):
        """Initialize a specific provider."""
        factory = PROVIDER_MAP.get(provider_name)
        if not factory:
            raise ValueError(f"Unknown provider: {provider_name}. Options: {list(PROVIDER_MAP.keys())}")
        
        if provider_name == "deepseek":
            return factory(self.config)
        return factory(self.config)

    def generate(self, prompt: str, system_prompt: str = "", messages: list = None, tools: list = None, retries: int = 2) -> Any:
        """
        Send a prompt with messages/tools to the LLM and return the response.
        Automatically falls back to secondary provider on failure.
        """
        if not self.config.enabled:
            return "[AI DISABLED] AI analysis is disabled in config."

        # Sanitize target info if needed
        if self.config.sanitize_targets and self.active_provider != "ollama":
            prompt = self._sanitize(prompt)
            # Not fully sanitizing full message history for payload brevity here

        # Try primary
        for attempt in range(retries + 1):
            try:
                if hasattr(self.primary, 'generate'):
                    import inspect
                    sig = inspect.signature(self.primary.generate)
                    kwargs = {}
                    if 'messages' in sig.parameters: kwargs['messages'] = messages
                    if 'tools' in sig.parameters: kwargs['tools'] = tools
                    
                    return self.primary.generate(prompt, system_prompt, **kwargs)
                return "[AI ERROR] Primary provider missing generate method"

            except Exception as e:
                print(f"{Colors.YELLOW}  ⚠ AI [{self.config.provider}] attempt {attempt+1} failed: {e}{Colors.RESET}",
                      file=sys.stderr)
                if attempt < retries:
                    time.sleep(2 ** attempt)

        # Try fallback
        if self.fallback and not self.config.local_only:
            try:
                print(f"{Colors.BLUE}  ↻ Falling back to {self.config.fallback_provider}...{Colors.RESET}",
                      file=sys.stderr)
                self.active_provider = self.config.fallback_provider
                
                if hasattr(self.fallback, 'generate'):
                    import inspect
                    sig = inspect.signature(self.fallback.generate)
                    kwargs = {}
                    if 'messages' in sig.parameters: kwargs['messages'] = messages
                    if 'tools' in sig.parameters: kwargs['tools'] = tools
                    
                    result = self.fallback.generate(prompt, system_prompt, **kwargs)
                    self.active_provider = self.config.provider
                    return result
            except Exception as e:
                print(f"{Colors.RED}  ✘ Fallback also failed: {e}{Colors.RESET}",
                      file=sys.stderr)

        return "[AI ERROR] All providers failed. Analysis unavailable."

    def analyze(self, prompt: str, system_prompt: str = "", retries: int = 2) -> str:
        """
        Backward compatible string-based analyze method. 
        """
        result = self.generate(prompt, system_prompt, retries=retries)
        if isinstance(result, dict):
            return result.get("content", "")
        return str(result)

    def is_available(self) -> bool:
        """Check if at least one provider is reachable."""
        try:
            if self.primary.is_available():
                return True
        except Exception:
            pass

        if self.fallback:
            try:
                return self.fallback.is_available()
            except Exception:
                pass

        return False

    def _sanitize(self, text: str) -> str:
        """Replace real IPs and internal domains with placeholders for cloud providers."""
        # Replace private IPs
        text = re.sub(r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', '[INTERNAL_IP]', text)
        text = re.sub(r'\b(192\.168\.\d{1,3}\.\d{1,3})\b', '[INTERNAL_IP]', text)
        text = re.sub(r'\b(172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3})\b', '[INTERNAL_IP]', text)
        return text

    def _log_debug(self, label: str, content: str):
        """Log prompts/responses for debugging."""
        print(f"{Colors.DIM}  [AI DEBUG {label}] {content}...{Colors.RESET}", file=sys.stderr)

    def get_status(self) -> Dict[str, Any]:
        """Return status info about the AI client."""
        return {
            "enabled": self.config.enabled,
            "provider": self.config.provider,
            "model": self.config.model,
            "primary_available": self.primary.is_available() if self.primary else False,
            "fallback_provider": self.config.fallback_provider,
            "fallback_available": self.fallback.is_available() if self.fallback else False,
            "local_only": self.config.local_only,
        }


# ============================================================================
# CLI Test
# ============================================================================

if __name__ == "__main__":
    from .config import load_config

    config = load_config()
    client = LLMClient(config)

    print(f"\n{Colors.CYAN}[*] REDHAVEN AI — LLM Client Status{Colors.RESET}")
    status = client.get_status()
    for k, v in status.items():
        print(f"  {k}: {v}")

    if client.is_available():
        print(f"\n{Colors.GREEN}[+] Testing with prompt...{Colors.RESET}")
        result = client.analyze(
            "You are a penetration tester. Briefly describe what SSRF is and why it's critical.",
            system_prompt="You are an elite red team operator. Be concise and technical."
        )
        print(f"\n{Colors.BOLD}Response:{Colors.RESET}\n{result}")
    else:
        print(f"\n{Colors.RED}[!] No AI provider available.{Colors.RESET}")
