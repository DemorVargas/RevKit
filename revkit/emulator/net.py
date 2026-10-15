"""A sinkhole network for the emulator.

Nothing here opens a socket. `connect` always succeeds and every byte the sample
sends is recorded, so a beacon believes it phoned home while you collect the URL,
the headers and the exfil format with no packet leaving the machine.

DNS is not modelled. Real shellcode resolves names through libc and this emulator
only ever sees syscalls, so a sample that wants a name does its own resolution
over sendto to port 53. That traffic is captured like any other, which is where
you read the domain out of.
"""

from __future__ import annotations

from dataclasses import dataclass, field

AF_INET = 2
AF_INET6 = 10


def parse_sockaddr(mem, addr: int, length: int) -> str:
    """Render a sockaddr as ip:port, or a marker if it is not one we model."""
    if not addr or length < 8:
        return "?"
    family = int.from_bytes(mem.read(addr, 2), "little")
    port = int.from_bytes(mem.read(addr + 2, 2), "big")
    if family == AF_INET:
        ip = ".".join(str(b) for b in mem.read(addr + 4, 4))
        return f"{ip}:{port}"
    if family == AF_INET6:
        raw = mem.read(addr + 8, 16)
        groups = [f"{raw[i] << 8 | raw[i + 1]:x}" for i in range(0, 16, 2)]
        return "[" + ":".join(groups) + f"]:{port}"
    return f"family {family}:{port}"


@dataclass
class NetFlow:
    """One chunk of traffic the guest tried to put on the wire."""

    fd: int
    peer: str
    data: bytes


@dataclass
class Network:
    """A sinkhole: sockets work, connects succeed, sends pile up in here."""

    flows: list[NetFlow] = field(default_factory=list)
    peers: dict[int, str] = field(default_factory=dict)

    def connect(self, fd: int, peer: str) -> int:
        self.peers[fd] = peer
        return 0

    def send(self, fd: int, data: bytes) -> int:
        if data:
            self.flows.append(NetFlow(fd=fd, peer=self.peers.get(fd, "?"), data=data))
        return len(data)
