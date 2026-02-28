#!/usr/bin/env python3
"""
REDHAVEN AI — Configuration Manager
=====================================
Loads and validates AI configuration from ai_config.yaml.
Supports environment variable overrides for API keys.
"""

import os
import yaml
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class OllamaConfig:
    host: str = "http://localhost:11434"


@dataclass
class AIConfig:
    """Centralized AI configuration with env var overrides."""

    enabled: bool = True

    # Provider
    provider: str = "ollama"
    model: str = "llama3:8b"
    fallback_provider: str = "gemini"
    fallback_model: str = "gemini-2.0-flash"

    # API Keys
    gemini_api_key: str = ""
    openai_api_key: str = ""
    deepseek_api_key: str = ""

    # Ollama
    ollama: OllamaConfig = field(default_factory=OllamaConfig)

    # Generation
    max_tokens: int = 4096
    temperature: float = 0.3
    top_p: float = 0.9

    # Behavior
    analyze_after_phase: bool = True
    narrative_report: bool = True
    max_findings_per_prompt: int = 100

    # Privacy
    sanitize_targets: bool = True
    local_only: bool = False
    debug_logging: bool = False

    def get_api_key(self, provider: Optional[str] = None) -> str:
        """Get API key for the specified provider, checking env vars first."""
        p = provider or self.provider

        env_map = {
            "gemini": ("REDHAVEN_GEMINI_KEY", self.gemini_api_key),
            "openai": ("REDHAVEN_OPENAI_KEY", self.openai_api_key),
            "deepseek": ("REDHAVEN_DEEPSEEK_KEY", self.deepseek_api_key),
        }

        if p in env_map:
            env_var, config_val = env_map[p]
            return os.environ.get(env_var, config_val)
        return ""

    def get_model(self, provider: Optional[str] = None) -> str:
        """Get model name for the specified provider."""
        p = provider or self.provider
        if p == self.provider:
            return self.model
        return self.fallback_model


def load_config(config_path: Optional[str] = None) -> AIConfig:
    """
    Load AI configuration from YAML file.
    
    Search order:
    1. Explicit path
    2. /config/ai_config.yaml (inside Docker)
    3. ./config/ai_config.yaml (local dev)
    4. Default config
    """
    search_paths = [
        config_path,
        "/config/ai_config.yaml",
        str(Path(__file__).parent.parent.parent / "config" / "ai_config.yaml"),
    ]

    for path in search_paths:
        if path and Path(path).exists():
            try:
                with open(path, 'r') as f:
                    raw = yaml.safe_load(f)

                if not raw or 'ai' not in raw:
                    continue

                ai = raw['ai']
                config = AIConfig(
                    enabled=ai.get('enabled', True),
                    provider=ai.get('provider', 'ollama'),
                    model=ai.get('model', 'llama3:8b'),
                    fallback_provider=ai.get('fallback_provider', 'gemini'),
                    fallback_model=ai.get('fallback_model', 'gemini-2.0-flash'),
                    gemini_api_key=ai.get('gemini_api_key', ''),
                    openai_api_key=ai.get('openai_api_key', ''),
                    deepseek_api_key=ai.get('deepseek_api_key', ''),
                    ollama=OllamaConfig(
                        host=ai.get('ollama', {}).get('host', 'http://localhost:11434')
                    ),
                    max_tokens=ai.get('max_tokens', 4096),
                    temperature=ai.get('temperature', 0.3),
                    top_p=ai.get('top_p', 0.9),
                    analyze_after_phase=ai.get('analyze_after_phase', True),
                    narrative_report=ai.get('narrative_report', True),
                    max_findings_per_prompt=ai.get('max_findings_per_prompt', 100),
                    sanitize_targets=ai.get('sanitize_targets', True),
                    local_only=ai.get('local_only', False),
                    debug_logging=ai.get('debug_logging', False),
                )
                return config
            except Exception:
                continue

    # Return default config if no file found
    return AIConfig()


if __name__ == "__main__":
    config = load_config()
    print(f"Provider: {config.provider}")
    print(f"Model: {config.model}")
    print(f"Enabled: {config.enabled}")
    print(f"Local Only: {config.local_only}")
