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

script, capture, *mode = sys.argv[1:]
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
phase = "summary"
observations = {}
command_pages = set()
command_total = 0
resize_stage = None
original_total = 0
previous_stage = None
last_key = time.monotonic()
snapshots = []
try:
    deadline = time.monotonic() + 60
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
        if time.monotonic() - last_key < 0.7 or output.rfind(b"\x1b[?2026h") > output.rfind(b"\x1b[?2026l"):
            continue
        text = "\n".join(screen.display)
        compact = "".join(text.split())
        key = None
        if "commandneedsapproval" in compact:
            observations["immediate_risk"] = observations.get("immediate_risk", False) or (
                "Severity:Critical" in compact and "Evidence:" in compact
            )
            observations["cwd"] = observations.get("cwd", False) or "Workingdirectory:" in compact
            observations["shortened_preview"] = observations.get("shortened_preview", False) or "Commandpreview(shortened):" in compact
            observations["masked"] = observations.get("masked", False) or "[REDACTED]" in compact
            key = b"\r"
        elif "humanapproval" in compact and "Allowonce" in compact:
            for label, value in {
                "deny": "Deny", "once": "Allowonce", "details": "Details",
                "command": "Fullcommand", "technical": "Diagnostics",
            }.items():
                observations[label] = value in compact
            if phase == "summary":
                key = b"\x1b[B\x1b[B\r"
                phase = "details"
            elif phase == "details":
                key = b"\x1b[B\x1b[B\x1b[B\r"
                phase = "command"
            elif phase == "command":
                observations["returned_actions"] = True
                key = b"\r"
                phase = "denied"
        elif phase == "details" and "Details" in compact:
            observations["readable_assessment"] = observations.get("readable_assessment", False) or "Risk1of2" in compact
            observations["uncertainty"] = observations.get("uncertainty", False) or "Deterministicfixtureuncertainty" in compact
            observations["details_without_command"] = observations.get("details_without_command", True) and all(value not in compact for value in ["demo-secret", "FINAL_COMMAND_LINE", "constline19"])
            key = b"\r"
        elif phase == "command" and "Fullcommand" in compact:
            page = re.search(r"Fullcommand.*?\((\d+)/(\d+)\)", compact)
            if page:
                if mode == ["dismiss"] and int(page[1]) == 2:
                    observations["escape_on_later_page"] = True
                    key = b"\x1b"
                    phase = "denied"
                elif previous_stage is None and int(page[1]) == 2:
                    observations["previous_label"] = "Previous" in compact
                    previous_stage = "back"
                    os.write(master, b"\x1b[D\r")
                    last_key = time.monotonic()
                    continue
                elif previous_stage == "back":
                    if int(page[1]) != 1:
                        continue
                    observations["previous_returns_prior_page"] = True
                    previous_stage = "done"
                if phase == "denied":
                    os.write(master, key)
                    last_key = time.monotonic()
                    continue
                if resize_stage is None and int(page[1]) == 3:
                    original_total = int(page[2])
                    resize_stage = "grow"
                    fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 32, 96, 0, 0))
                    screen.resize(32, 96)
                    os.killpg(child.pid, signal.SIGWINCH)
                    last_key = time.monotonic()
                    continue
                if resize_stage == "grow":
                    if int(page[2]) >= original_total:
                        continue
                    observations["resize_repagination"] = True
                    resize_stage = "shrink"
                    fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 64, 0, 0))
                    screen.resize(24, 64)
                    os.killpg(child.pid, signal.SIGWINCH)
                    last_key = time.monotonic()
                    continue
                if resize_stage == "shrink":
                    if int(page[2]) != original_total or int(page[1]) != 3:
                        continue
                    observations["resize_preserves_position"] = True
                    resize_stage = "done"
                command_pages.add(int(page[1]))
                command_total = int(page[2])
                observations["secret_warning"] = "maycontainsecrets" in compact
                observations["unmasked_command"] = observations.get("unmasked_command", False) or "demo-secret" in compact
                observations["unicode"] = observations.get("unicode", False) or "界" in text
                observations["last_command_line"] = observations.get("last_command_line", False) or "FINAL_COMMAND_LINE" in compact
                key = b"\r"
        elif phase == "denied":
            break
        if key:
            snapshots.append({"phase": phase, "screen": text})
            marker = os.path.join(os.path.dirname(script), "project", "human-once.marker")
            observations["no_execution_while_reading"] = observations.get("no_execution_while_reading", True) and not os.path.exists(marker)
            os.write(master, key)
            last_key = time.monotonic()
    observations["all_command_pages"] = command_total > 1 and command_pages == set(range(1, command_total + 1))
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
