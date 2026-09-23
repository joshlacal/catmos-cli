#!/usr/bin/env python3
"""Drive the actual interactive `catmos` TUI through a pseudo-terminal.

Fixture-only qualification helper. The parent test sends one JSON command per
stdin line and receives one JSON result per stdout line, so it can sample its
transport counter between keystrokes:

  {"op": "expect", "text": "...", "timeout": 30}  -> {"found": bool}
  {"op": "keys", "data": "..."}                     -> {"ok": true}
  {"op": "exit", "timeout": 30}                     -> {"code": int|null}

`expect` matches against terminal output with escape sequences removed,
accumulated since the previous successful `expect`. Keystrokes are raw bytes
(for example "\\u0012" for Ctrl-R). No terminal text is written to stdout; the
parent receives only match booleans, so rendered drafts never enter evidence.
"""
import fcntl
import json
import os
import pty
import re
import select
import signal
import struct
import sys
import termios
import time

ESCAPES = re.compile(rb"\x1b(\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(\x07|\x1b\\)|[()][0-9A-Za-z]|[=>78])")


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
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 60, 240, 0, 0))
    screen = b""
    exited = None

    def pump(deadline: float) -> None:
        nonlocal screen, exited
        while time.monotonic() < deadline:
            ready, _, _ = select.select([fd], [], [], max(0.0, min(0.2, deadline - time.monotonic())))
            if ready:
                try:
                    chunk = os.read(fd, 65536)
                except OSError:
                    chunk = b""
                if not chunk:
                    break
                screen += ESCAPES.sub(b"", chunk)
            else:
                return
            if exited is None:
                done, status = os.waitpid(pid, os.WNOHANG)
                if done:
                    exited = os.waitstatus_to_exitcode(status)

    def reply(value: dict) -> None:
        sys.stdout.write(json.dumps(value) + "\n")
        sys.stdout.flush()

    for line in sys.stdin:
        command = json.loads(line)
        op = command["op"]
        if op == "expect":
            needle = command["text"].encode()
            deadline = time.monotonic() + command.get("timeout", 30)
            found = False
            while time.monotonic() < deadline:
                if needle in screen:
                    found = True
                    break
                pump(min(deadline, time.monotonic() + 0.5))
            if found:
                screen = b""
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
                if exited is None:
                    done, status = os.waitpid(pid, os.WNOHANG)
                    if done:
                        exited = os.waitstatus_to_exitcode(status)
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
