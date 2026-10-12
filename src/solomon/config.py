import os
import tomllib
from pathlib import Path
from typing import Any

from .core.exceptions import ConfigurationError


def get_default_config_dir() -> Path:
    """Returns the default configuration directory depending on the platform."""
    if os.name == "nt":
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / "Solomon"
        return Path.home() / "AppData" / "Roaming" / "Solomon"
    else:
        # Assume Linux/macOS
        return Path.home() / ".config" / "solomon"


class ConfigManager:
    def __init__(self, config_dir: Path | None = None):
        self.config_dir = config_dir or get_default_config_dir()
        self.config_file = self.config_dir / "config.toml"
        self._config: dict[str, Any] = {}

    def load(self) -> None:
        if not self.config_file.exists():
            # Return empty config if it does not exist
            return

        try:
            with open(self.config_file, "rb") as f:
                self._config = tomllib.load(f)
        except Exception as e:
            raise ConfigurationError(f"Failed to parse configuration file {self.config_file}: {e}")

    def get(self, key: str, default: Any = None) -> Any:
        keys = key.split(".")
        current = self._config
        for k in keys:
            if isinstance(current, dict) and k in current:
                current = current[k]
            else:
                return default
        return current
