# Transcript surface probe

Diagnostic-only fixture for ticket 18. Register this directory in an **isolated** `cli.json` as `{ "package": "<absolute fixture directory>", "options": { "evidenceFile": "<temporary JSONL path>" } }`. Its parent must resolve the existing `@opencode/plugin` installation. Start an isolated OpenCode server with temporary XDG/config directories and open a session through `opencode --server <isolated server URL> --session <temporary session ID>`.

The fixture writes only public Interface keys, host version, route identity and slot input. It renders no UI, reads no credentials and runs no shell command. `app` is the positive render control. `session.message.tool` is deliberately an unsupported diagnostic anchor, not a production registration or a claimed public API. SDK `SlotMap` is authoritative for documented slot names.

2026-10-06 observation: host 2.0.23 loaded the fixture and rendered the app control in a session. UI keys were `dialog`, `toast`, `format`, `router`, `panel`, `tabs`, `model`, `slot`. No transcript anchor render occurred. Installed SDK 2.0.22 declares only app, home/footer, prompt/footer, session composer/panel and sidebar slots; it exposes no tool/transcript render registration. This is evidence of a missing supported seam, not a PASS of the requested approval label.
