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

import pyte

# OpenCode 2.1 renders the approval dialogs differently from 2.0: the summary is
# paginated at 64x24 and the option list is navigated through a focused search
# input. This driver walks the screens it can verify by content, and stops at the
# menu: reading a Full command page cannot be triggered reliably there. The
# 2.0 driver (tui-layout.py) still covers those pages.
script, capture, *mode = sys.argv[1:]
dismiss = mode == ["dismiss"]
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
screen = pyte.Screen(64, 24)
stream = pyte.ByteStream(screen)
observations = {}
details_done = False
menu_blurred = False
finished = False
last_key = time.monotonic()
snapshots = []
try:
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        if select.select([master], [], [], 0.1)[0]:
            try:
                chunk = os.read(master, 65536)
            except OSError:
                break
            output += chunk
            stream.feed(chunk)
            for query, reply in [
                (b"\x1b]10;?", b"\x1b]10;rgb:ffff/ffff/ffff\x07"),
                (b"\x1b]11;?", b"\x1b]11;rgb:0000/0000/0000\x07"),
                (b"\x1b[6n", b"\x1b[1;1R"),
                (b"\x1b[c", b"\x1b[?1;2c"),
            ]:
                if query in chunk:
                    os.write(master, reply)
        if time.monotonic() - last_key < 0.5 or output.rfind(
            b"\x1b[?2026h"
        ) > output.rfind(b"\x1b[?2026l"):
            continue
        text = "\n".join(screen.display)
        compact = "".join(text.split())
        key = None
        if finished:
            if (
                "—humanapproval" not in compact
                and "—commandneedsapproval" not in compact
            ):
                break
        elif "commandneedsapproval" in compact:
            observations["immediate_risk"] = observations.get(
                "immediate_risk", False
            ) or ("Severity:Critical" in compact and "Evidence:" in compact)
            observations["cwd"] = (
                observations.get("cwd", False) or "Workingdirectory:" in compact
            )
            observations["shortened_preview"] = (
                observations.get("shortened_preview", False)
                or "Commandpreview(shortened):" in compact
            )
            observations["masked"] = (
                observations.get("masked", False) or "[REDACTED]" in compact
            )
            key = b"\r"
        elif "humanapproval" in compact and "Allowonce" in compact:
            for label, value in {
                "deny": "Deny",
                "once": "Allowonce",
                "details": "Details",
                "command": "Fullcommand",
                "technical": "Diagnostics",
            }.items():
                observations[label] = value in compact
            if details_done:
                key = b"\x1b"
                finished = True
            elif menu_blurred:
                menu_blurred = False
                key = b"\r"
            else:
                current = next(
                    (
                        label
                        for row_index, line in enumerate(screen.display)
                        for label in [
                            "Deny",
                            "Allow once",
                            "Details",
                            "Full command",
                            "Diagnostics",
                        ]
                        if label in line
                        and any(cell.bold for cell in screen.buffer[row_index].values())
                    ),
                    None,
                )
                if current != "Details":
                    key = b"\x0e"
                else:
                    menu_blurred = True
                    key = b"\t"
        elif "Details—maycontainsecrets" in compact:
            observations["readable_assessment"] = (
                observations.get("readable_assessment", False) or "Risk1of2" in compact
            )
            observations["uncertainty"] = (
                observations.get("uncertainty", False)
                or "Deterministicfixtureuncertainty" in compact
            )
            observations["details_without_command"] = observations.get(
                "details_without_command", True
            ) and all(
                value not in compact
                for value in ["demo-secret", "FINAL_COMMAND_LINE", "constline19"]
            )
            page = re.search(r"Details.*?\((\d+)/(\d+)\)", compact)
            if dismiss and page and int(page[1]) == 2:
                observations["escape_on_later_page"] = True
                key = b"\x1b"
                finished = True
            else:
                if page and int(page[1]) == int(page[2]):
                    observations["returned_actions"] = True
                    details_done = True
                key = b"\r"
        if key:
            snapshots.append({"phase": "layout", "screen": text})
            marker = os.path.join(
                os.path.dirname(script), "project", "human-once.marker"
            )
            observations["no_execution_while_reading"] = observations.get(
                "no_execution_while_reading", True
            ) and not os.path.exists(marker)
            os.write(master, key)
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
    with open(capture + ".screens.json", "w") as file:
        json.dump(snapshots, file, ensure_ascii=False)
    with open(capture, "w") as file:
        json.dump(observations, file)
