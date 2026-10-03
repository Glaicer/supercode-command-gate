import fcntl
import json
import os
import pty
import re
import select
import signal
import struct
import subprocess
import sys
import termios
import time

script, root = sys.argv[1:]
master, slave = pty.openpty()
fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))


def attach():
    os.setsid()
    fcntl.ioctl(slave, termios.TIOCSCTTY, 0)


child = subprocess.Popen(
    ["sh", script], stdin=slave, stdout=slave, stderr=slave, preexec_fn=attach
)
os.close(slave)
output = b""
view = b""
current = None
submitted = False
last_key = time.monotonic()
actions = []
try:
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if select.select([master], [], [], 0.1)[0]:
            try:
                chunk = os.read(master, 65536)
            except OSError:
                break
            output += chunk
            view += chunk
            for query, reply in [
                (b"\x1b]10;?", b"\x1b]10;rgb:ffff/ffff/ffff\x07"),
                (b"\x1b]11;?", b"\x1b]11;rgb:0000/0000/0000\x07"),
                (b"\x1b[6n", b"\x1b[1;1R"),
                (b"\x1b[c", b"\x1b[?1;2c"),
            ]:
                if query in chunk:
                    os.write(master, reply)
        try:
            with open(root + "/ui-progress.json") as file:
                progress = json.load(file)
        except (FileNotFoundError, json.JSONDecodeError):
            continue
        if progress["name"] == "human-deny" and progress["finished"]:
            break
        key = (progress["name"], progress["responses"])
        if key != current:
            current = key
            submitted = False
        if submitted or time.monotonic() - last_key < 0.5:
            continue
        text = re.sub(rb"\x1b\[[0-?]*[ -/]*[@-~]", b"", view)
        compact = b"".join(text.split())
        if b"Allowonce" in compact:
            down = {"human-once": 1, "human-session": 2, "human-deny": 0}[
                progress["name"]
            ]
            if b"Trustexactforsession" not in compact:
                raise RuntimeError("eligible trust action is absent from the real TUI")
            os.write(master, b"\x1b[B" * down + b"\r")
            actions.append(
                {
                    "name": progress["name"],
                    "response": progress["responses"],
                    "trust_visible": True,
                }
            )
            submitted = True
            view = b""
        elif b"CommandGate" in compact and b"summary" in compact:
            os.write(master, b"\r")
            view = b""
        last_key = time.monotonic()
    else:
        raise RuntimeError("automated TUI actions did not finish within 60 seconds")
finally:
    os.killpg(child.pid, signal.SIGTERM)
    try:
        child.wait(timeout=3)
    except subprocess.TimeoutExpired:
        os.killpg(child.pid, signal.SIGKILL)
        child.wait()
    os.close(master)
    with open(root + "/tui-actions.raw", "wb") as file:
        file.write(output)
    with open(root + "/tui-actions.json", "w") as file:
        json.dump(actions, file)
