"""Import built-in rules for CLI, TUI and library use alike."""

from . import linux_rules, windows_rules

__all__ = ["linux_rules", "windows_rules"]
