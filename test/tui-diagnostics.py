import fcntl
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
fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))


def attach():
    os.setsid()
    fcntl.ioctl(slave, termios.TIOCSCTTY, 0)


child = subprocess.Popen(
    ["sh", script], stdin=slave, stdout=slave, stderr=slave, preexec_fn=attach
)
os.close(slave)
output = b""
start = time.monotonic()
stage = 0
try:
    while time.monotonic() - start < 12:
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
        elapsed = time.monotonic() - start
        if stage == 0 and elapsed > 4:
            os.write(master, b"\x10")
            stage = 1
        elif stage == 1 and elapsed > 5:
            os.write(master, b"Command Gate: health")
            stage = 2
        elif stage == 2 and elapsed > 6:
            os.write(master, b"\r")
            stage = 3
        elif stage >= 3 and elapsed > stage + 4:
            os.write(master, b"\r")
            stage += 1
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
    with open(capture, "wb") as file:
        file.write(b"".join(text.split()))
