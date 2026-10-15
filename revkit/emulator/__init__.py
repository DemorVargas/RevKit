"""x86 / x86-64 emulation for revkit.

Runs raw shellcode and CTF-style stubs in pure Python. There is no loader and no
import resolution; you hand it bytes and it executes them.
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.1.0"
