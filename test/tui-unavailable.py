import fcntl
import json
import os
import pty
import select
import signal
import struct
import subprocess
import sys
import termios
import time

import pyte

script, root = sys.argv[1:]
master, slave = pty.openpty()
fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))


def attach():
    os.setsid()
    fcntl.ioctl(slave, termios.TIOCSCTTY, 0)


child = subprocess.Popen(["sh", script], stdin=slave, stdout=slave, stderr=slave, preexec_fn=attach)
os.close(slave)
screen = pyte.Screen(120, 40)
stream = pyte.Stream(screen)
output = b""
visible = False
dismissed = False
closed_at = None
try:
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if select.select([master], [], [], 0.1)[0]:
            chunk = os.read(master, 65536)
            output += chunk
            stream.feed(chunk.decode("utf-8", errors="replace"))
            for query, reply in [
                (b"\x1b]10;?", b"\x1b]10;rgb:ffff/ffff/ffff\x07"),
                (b"\x1b]11;?", b"\x1b]11;rgb:0000/0000/0000\x07"),
                (b"\x1b[6n", b"\x1b[1;1R"),
                (b"\x1b[c", b"\x1b[?1;2c"),
            ]:
                if query in chunk:
                    os.write(master, reply)
        text = "\n".join(screen.display)
        compact = "".join(text.split())
        if not visible and "CommandGateunavailable" in compact and "CommandRiskAssessorunavailable" in compact and "commandwasnotexecuted" in compact:
            visible = True
            with open(root + "/unavailable-visible.txt", "w") as file:
                file.write(text)
            os.write(master, b"\x1b")
            closed_at = time.monotonic()
        if visible and time.monotonic() - closed_at > 6:
            if "CommandRiskAssessorunavailable" in compact:
                raise RuntimeError("dismissed unavailable dialog reappeared")
            dismissed = True
            with open(root + "/unavailable-dismissed.txt", "w") as file:
                file.write(text)
            break
    if not visible or not dismissed:
        raise RuntimeError("real unavailable alert/dismiss was not observed")
finally:
    os.killpg(child.pid, signal.SIGTERM)
    try:
        child.wait(timeout=3)
    except subprocess.TimeoutExpired:
        os.killpg(child.pid, signal.SIGKILL)
        child.wait()
    os.close(master)
    with open(root + "/unavailable-ui.raw", "wb") as file:
        file.write(output)
    with open(root + "/unavailable-ui.json", "w") as file:
        json.dump({"visible": visible, "dismissed": dismissed}, file)
