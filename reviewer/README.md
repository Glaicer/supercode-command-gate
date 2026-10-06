# Command Reviewer (`aar`)

The Reviewer and V2 Command Gate share one repository. See the
[root README](../README.md) for installation, shell compatibility, command dump
results, parse-failure behavior, verification, and the complete
[Reviewer configuration reference](../README.md#reviewer-configuration).

`plugin/` contains the historical OpenCode V1 Gate; current V2 installation
and approval instructions are in the root README.

## Safe shell syntax

The complete program must satisfy the existing policy, including every pipeline
stage and every command after `;`, `&&`, or `||`. No new command families or read
scopes are introduced.

- `head -60` and `tail -20` accept decimal count shortcuts alongside existing
  `-n 60`, `-n60`, and `--lines=60` forms. Unknown flags fall back to the Assessor;
  this does not authorize follow mode.
- Output duplication between descriptors 1 and 2 is supported (`2>&1`, `1>&2`,
  `>&2`). Redirections retain source order. File writes still require the existing
  explicit safe target policy; duplication is not a file operand or safe stdin.
  Input duplication, other descriptors, closing and moving descriptors fall back.
- Unquoted path words support `*` and `?` in relative, nested and absolute paths.
  Pattern source characters are limited to ASCII letters, digits, `_`, `.`, `/`,
  `-`, `*`, `?` and supported braces. Matching filenames may contain other
  characters. Hidden names require an explicit leading dot in the component.
  Fully quoted words remain literal; mixed quoting, escapes, bracket patterns,
  `**`, extglob, tilde and `..` components in expansion words fall back.
- One numeric brace range per word supports `{1..8}` and `{8..1}`, including a
  range combined with a glob. Endpoints are nonnegative decimal integers without
  zero padding. Lists, letters, steps, nested or multiple ranges fall back.
  Plain brace expansion can name missing files, just like literal path operands.
  A glob with no matches always falls back, including inside a brace range.
- Expansion is limited to 256 resulting arguments per command (excluding the
  executable), 256 intermediate glob candidates, and 4096 inspected directory
  entries per glob pattern. Every result and every enumerated directory passes
  existing canonical path/protected path checks. Leading option-like results
  fall back. Patterns are inspected without executing a shell.

Expansion is available only for existing `cat`, `head`, `tail`, `ls`, `tree`,
`file`, `stat`, `du`, `wc`, `uniq`, `cut`, `tr`, `readlink`, `realpath`, `basename`,
`dirname`, `sort`, `diff`, `cmp`, `comm`, `grep`, `rg`, and `ripgrep` rules. Their
existing option and operand restrictions still apply. In particular,
`stat --format=...` still falls back; command-option coverage belongs to ticket 12.
Expansion does not authorize `rm`, custom executables, scripts, or exact configured
additions. Parameter/command/process substitution, loops and assignments retain
existing fallback. ShellIR retains dynamic glob/brace facts; only the policy
resolves this bounded subset.

Gate carries `BASHOPTS`, `SHELLOPTS`, `GLOBIGNORE`, `BASH_ENV`, and `ENV` from the
actual invocation environment. Any nonempty value makes expansion commands fall
back, since shell options or startup scripts can change expansion semantics.
This is Bash syntax policy, not support for arbitrary shells or containment of
filesystem changes between checking and execution.

Validation and fixed before/after fixtures are recorded in
[ticket 11 evidence](../../../.scratch/029-command-gate-v2/11-evidence.md).
