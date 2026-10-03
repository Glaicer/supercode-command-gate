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

script, capture = sys.argv[1:]
master, slave = pty.openpty()
fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 64, 0, 0))


def attach():
    os.setsid()
    fcntl.ioctl(slave, termios.TIOCSCTTY, 0)


child = subprocess.Popen(
    ["sh", script], stdin=slave, stdout=slave, stderr=slave, preexec_fn=attach
)
os.close(slave)
output = b""
opened_details = False
details_start = 0
last_key = time.monotonic()
try:
    deadline = time.monotonic() + 14
    while time.monotonic() < deadline:
        if select.select([master], [], [], 0.1)[0]:
            try:
                chunk = os.read(master, 65536)
            except OSError:
                break
            output += chunk
            for query, reply in [
                (b"\x1b]10;?", b"\x1b]10;rgb:ffff/ffff/ffff\x07"),
                (b"\x1b]11;?", b"\x1b]11;rgb:0000/0000/0000\x07"),
                (b"\x1b[6n", b"\x1b[1;1R"),
                (b"\x1b[c", b"\x1b[?1;2c"),
            ]:
                if query in chunk:
                    os.write(master, reply)
        if time.monotonic() - last_key > 0.8 and b"Command Gate" in output:
            if b"Allow once" in output and not opened_details:
                os.write(master, b"\x1b[B\x1b[B\r")
                opened_details = True
                details_start = len(output)
            elif (
                opened_details
                and b"not supplied" in output[details_start:]
            ):
                os.write(master, b"\x1b")
                break
            else:
                os.write(master, b"\r")
            last_key = time.monotonic()
finally:
    os.killpg(child.pid, signal.SIGTERM)
    try:
        child.wait(timeout=3)
    except subprocess.TimeoutExpired:
        os.killpg(child.pid, signal.SIGKILL)
        child.wait()
    os.close(master)
    with open(capture + ".raw", "wb") as file:
        file.write(output)
    text = re.sub(rb"\x1b\[[0-?]*[ -/]*[@-~]", b"", output)
    compact = b"".join(text.split())
    with open(capture, "w") as file:
        json.dump(
            {
                key: value.encode().replace(b" ", b"") in compact
                for key, value in {
                    "deny": "Deny",
                    "once": "Allow once",
                    "details": "Full details",
                    "cwd": "cwd:",
                    "preview": "Preview:",
                    "masked": "[REDACTED]",
                    "assessment": "RiskAssessment",
                    "full_command": "demo-secret",
                }.items()
            } | {
                "opened_details": opened_details,
                "full_details_command": b"demo-secret" in output[details_start:],
                "word_wrap": b"API_TOKEN=[REDACTED]" in text,
            },
            file,
        )
