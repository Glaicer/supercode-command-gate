import fcntl
import os
import pty
import select
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
try:
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if select.select([master], [], [], 0.1)[0]:
            try:
                chunk = os.read(master, 65536)
                output += chunk
                for query, reply in [
                    (b"\x1b]10;?", b"\x1b]10;rgb:ffff/ffff/ffff\x07"),
                    (b"\x1b]11;?", b"\x1b]11;rgb:0000/0000/0000\x07"),
                    (b"\x1b[6n", b"\x1b[1;1R"),
                    (b"\x1b[c", b"\x1b[?1;2c"),
                ]:
                    if query in chunk:
                        os.write(master, reply)
            except OSError:
                break
finally:
    child.terminate()
    try:
        child.wait(timeout=3)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait()
    os.close(master)
    with open(capture, "wb") as file:
        file.write(output)
print(f"TUI capture: {capture}")
