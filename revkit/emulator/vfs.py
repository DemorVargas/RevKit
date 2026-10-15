"""A virtual filesystem for the emulator.

The emulator must never touch the host. A sample that opens /etc/shadow should get
a plausible answer back, not your actual shadow file, and a sample that goes
looking for a sandbox should find something it believes. Everything the guest can
see lives in this dict, in memory, and the analyst decides what goes in it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# A believable Linux root. Deliberately small: enough that a sample checking
# whether it is running somewhere real takes its normal path, and nothing in here
# is copied from the machine you are sitting at.
DEFAULT_FILES = {
    "/etc/passwd": (
        b"root:x:0:0:root:/root:/bin/sh\n"
        b"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        b"nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
    ),
    "/etc/hostname": b"localhost\n",
    "/etc/hosts": b"127.0.0.1\tlocalhost\n::1\tlocalhost\n",
    "/etc/resolv.conf": b"nameserver 10.0.2.3\n",
    "/proc/self/status": b"Name:\tstub\nState:\tR (running)\nPid:\t1234\nPPid:\t1000\n",
    "/proc/self/cmdline": b"stub\x00",
    "/proc/self/maps": b"00400000-00401000 r-xp 00000000 00:00 0\n",
}


@dataclass
class Vfs:
    """Paths to bytes, plus the directories they imply.

    No inodes, no permissions, no symlinks. If a sample needs those, it needs a
    real filesystem in a real sandbox, and that is not what this is for.
    """

    files: dict[str, bytes] = field(default_factory=dict)
    dirs: set[str] = field(default_factory=set)

    def __post_init__(self):
        if not self.dirs:
            self.dirs = {"/", "/etc", "/proc", "/proc/self", "/tmp"}
        for path in self.files:
            self.dirs.add(path.rsplit("/", 1)[0] or "/")

    def add(self, path: str, data: bytes) -> None:
        self.files[path] = data
        self.dirs.add(path.rsplit("/", 1)[0] or "/")

    def exists(self, path: str) -> bool:
        return path in self.files or path in self.dirs

    def is_dir(self, path: str) -> bool:
        return path in self.dirs and path not in self.files

    def read(self, path: str, count: int, offset: int = 0) -> bytes:
        return self.files.get(path, b"")[offset : offset + count]

    def write(self, path: str, data: bytes, append: bool = False) -> int:
        if append and path in self.files:
            self.files[path] += data
        else:
            self.add(path, data)
        return len(data)

    def size(self, path: str) -> int:
        return len(self.files.get(path, b""))

    def paths(self) -> list[str]:
        return sorted(self.files)

    @classmethod
    def default(cls) -> "Vfs":
        """A VFS holding the fake root above."""
        return cls(files=dict(DEFAULT_FILES))
