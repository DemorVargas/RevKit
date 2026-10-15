"""Errors raised by the emulator."""

from __future__ import annotations


class EmulatorError(Exception):
    """Base class for everything the emulator raises."""


class MemError(EmulatorError):
    """Bad address, bad size, or a read past the end of mapped memory."""


class DecodeError(EmulatorError):
    """Bytes that do not form a valid instruction for the current mode."""


class ExecuteError(EmulatorError):
    """The machine hit something it will not do: a bad syscall, an
    unimplemented instruction, or one that was explicitly blocked."""

    def __init__(self, message: str, *, pc: int | None = None):
        super().__init__(message)
        self.pc = pc

