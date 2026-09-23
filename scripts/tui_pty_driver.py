#!/usr/bin/env python3
"""Drive the actual interactive `catmos` TUI through a pseudo-terminal.

Fixture-only qualification helper. The parent test sends one JSON command per
stdin line and receives one JSON result per stdout line, so it can sample its
transport counter between keystrokes:

  {"op": "expect", "text": "...", "timeout": 30}  -> {"found": bool}
  {"op": "keys", "data": "..."}                     -> {"ok": true}
  {"op": "exit", "timeout": 30}                     -> {"code": int|null}

`expect` searches the current screen, reconstructed from the terminal output
with a minimal cursor-addressed grid. Ratatui redraws only changed cells, so
the raw byte stream cannot be searched for rendered phrases. Keystrokes are
raw bytes (for example "\\u0012" for Ctrl-R). No terminal text is written to
stdout; the parent receives only match booleans.
"""
import codecs
import fcntl
import json
import os
import pty
import select
import signal
import struct
import sys
import termios
import time

ROWS, COLS = 60, 240


class Screen:
    def __init__(self) -> None:
        self.grid = [[" "] * COLS for _ in range(ROWS)]
        self.row = self.col = 0
        self.decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        self.pending = ""

    def text(self) -> str:
        return "\n".join("".join(row).rstrip() for row in self.grid)

    def clear(self, rows: range) -> None:
        for r in rows:
            self.grid[r] = [" "] * COLS

    def feed(self, data: bytes) -> None:
        stream = self.pending + self.decoder.decode(data)
        self.pending = ""
        i = 0
        while i < len(stream):
            ch = stream[i]
            if ch == "\x1b":
                if i + 1 >= len(stream):
                    self.pending = stream[i:]
                    return
                kind = stream[i + 1]
                if kind == "[":
                    j = i + 2
                    while j < len(stream) and not ("@" <= stream[j] <= "~"):
                        j += 1
                    if j >= len(stream):
                        self.pending = stream[i:]
                        return
                    self.csi(stream[i + 2:j], stream[j])
                    i = j + 1
                elif kind == "]":
                    j = i + 2
                    while j < len(stream) and stream[j] != "\x07" and stream[j:j + 2] != "\x1b\\":
                        j += 1
                    if j >= len(stream):
                        self.pending = stream[i:]
                        return
                    i = j + (1 if stream[j] == "\x07" else 2)
                elif kind in "()":
                    i += 3
                else:
                    i += 2
            elif ch == "\r":
                self.col = 0
                i += 1
            elif ch == "\n":
                self.row = min(ROWS - 1, self.row + 1)
                i += 1
            elif ch == "\b":
                self.col = max(0, self.col - 1)
                i += 1
            elif ch < " " or ch == "\x7f":
                i += 1
            else:
                if self.row < ROWS and self.col < COLS:
                    self.grid[self.row][self.col] = ch
                self.col += 1
                i += 1

    def csi(self, params: str, final: str) -> None:
        values = [int(p) if p.isdigit() else 0 for p in params.lstrip("?").split(";")]
        first = values[0] if values else 0
        if final in "Hf":
            row = values[0] if len(values) > 0 and values[0] else 1
            col = values[1] if len(values) > 1 and values[1] else 1
            self.row, self.col = min(ROWS, row) - 1, min(COLS, col) - 1
        elif final == "J":
            if first == 0:
                self.grid[self.row][self.col:] = [" "] * (COLS - self.col)
                self.clear(range(self.row + 1, ROWS))
            else:
                self.clear(range(ROWS))
        elif final == "K":
            self.grid[self.row][self.col:] = [" "] * (COLS - self.col)
        elif final == "A":
            self.row = max(0, self.row - (first or 1))
        elif final == "B":
            self.row = min(ROWS - 1, self.row + (first or 1))
        elif final == "C":
            self.col = min(COLS - 1, self.col + (first or 1))
        elif final == "D":
            self.col = max(0, self.col - (first or 1))
        elif final == "G":
            self.col = min(COLS, first or 1) - 1


def main() -> None:
    binary, profile, transport = sys.argv[1:4]
    pid, fd = pty.fork()
    if pid == 0:
        env = dict(os.environ)
        env.update(
            TERM="xterm-256color",
            CATMOS_LOCAL_RUNTIME_TRANSPORT=transport,
            RUST_LOG="error",
        )
        env.pop("CATMOS_TEST_KEYCHAIN_FALLBACK", None)
        env.pop("CATMOS_TEST_SHARED_KEYCHAIN_FALLBACK", None)
        os.execve(binary, [binary, "--profile", profile], env)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))
    screen = Screen()
    exited = None

    def reap() -> None:
        nonlocal exited
        if exited is None:
            done, status = os.waitpid(pid, os.WNOHANG)
            if done:
                exited = os.waitstatus_to_exitcode(status)

    def pump(deadline: float) -> None:
        while time.monotonic() < deadline:
            ready, _, _ = select.select([fd], [], [], max(0.0, min(0.2, deadline - time.monotonic())))
            if not ready:
                return
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                chunk = b""
            if not chunk:
                reap()
                return
            screen.feed(chunk)

    def reply(value: dict) -> None:
        sys.stdout.write(json.dumps(value) + "\n")
        sys.stdout.flush()

    for line in sys.stdin:
        command = json.loads(line)
        op = command["op"]
        if op == "expect":
            deadline = time.monotonic() + command.get("timeout", 30)
            found = command["text"] in screen.text()
            while not found and time.monotonic() < deadline:
                pump(min(deadline, time.monotonic() + 0.5))
                found = command["text"] in screen.text()
            reply({"found": found})
        elif op == "keys":
            for byte in command["data"].encode():
                os.write(fd, bytes([byte]))
                time.sleep(0.02)
            pump(time.monotonic() + 0.3)
            reply({"ok": True})
        elif op == "exit":
            deadline = time.monotonic() + command.get("timeout", 30)
            while exited is None and time.monotonic() < deadline:
                pump(time.monotonic() + 0.3)
                reap()
            if exited is None:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            reply({"code": exited})
            return
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


if __name__ == "__main__":
    main()
