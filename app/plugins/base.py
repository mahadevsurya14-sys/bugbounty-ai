"""
Extensible Plugin Architecture base classes.
Supports future plug-in components: ReconPlugin, ScannerPlugin, AnalyzerPlugin,
ReporterPlugin, EvidencePlugin, and AIProviderPlugin.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from app.core.config import ProgramConfig


class BasePlugin(ABC):
    """Base class for all BugBounty-AI plugins."""

    @property
    @abstractmethod
    def plugin_id(self) -> str:
        """Unique plugin identifier."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name."""
        pass

    @property
    @abstractmethod
    def version(self) -> str:
        """Plugin version."""
        pass


class ReconPlugin(BasePlugin):
    """Passive or active reconnaissance plugin interface."""

    @abstractmethod
    def execute(self, target: str, program: ProgramConfig) -> Dict[str, Any]:
        pass


class ScannerPlugin(BasePlugin):
    """Scanner plugin interface."""

    @abstractmethod
    def scan(self, target: str, program: ProgramConfig) -> List[Dict[str, Any]]:
        pass


class AIProviderPlugin(BasePlugin):
    """AI engine provider interface (e.g. Local LLM, Gemini, OpenAI)."""

    @abstractmethod
    def complete(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        pass
