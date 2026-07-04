# claude-compound-bash

A Claude Code [PreToolUse hook](https://code.claude.com/docs/en/hooks) plugin that auto-approves Bash tool calls when every sub-command matches your existing permission rules or is a known-safe command.

See [anthropics/claude-code#16561](https://github.com/anthropics/claude-code/issues/16561) for the upstream feature request.

## The problem

Claude Code checks each `Bash` tool call against your permission rules before executing. It now splits compound commands on shell operators (`&&`, `||`, `;`, `|`, `|&`, `&`, newlines) and requires each top-level sub-command to match -- so a plain `git add -A && git commit -m 'fix'` is handled natively once both halves match.

What native's splitting does **not** reach is everything below the top level: commands hidden inside a command substitution (`$(...)`, `` `...` ``), process substitution, subshell, loop, `if`/`case` body, or function body, plus argument-level nuances like an `xargs` payload or a redirect target. Those are where this hook adds value -- it walks the full AST, classifies each extracted command, and either approves the whole call or gets out of the way.

## How it works

The plugin registers a PreToolUse hook that intercepts every Bash tool call. It parses the command using [`mvdan.cc/sh/v3`](https://pkg.go.dev/mvdan.cc/sh/v3) (the parser behind `shfmt`), walks the full AST to extract every sub-command, and checks each one against your allow/ask/deny patterns from settings files.

Rules are evaluated in the same order as Claude Code: **deny → ask → allow**. The first matching rule wins.

For each tool call, the hook returns one of four outcomes:

- **`allow`** -- every sub-command is either a known-safe command or matches an allow pattern. The command runs without prompting.
- **`deny`** -- a sub-command matches an explicit deny pattern. The tool call is cancelled outright and Claude receives feedback explaining why.
- **`ask`** -- a sub-command matches an ask pattern, or a redirect fails a safety check that Claude Code doesn't perform itself. The hook forces Claude Code's permission prompt.
- **defer** (no decision) -- the hook can't affirmatively approve a *top-level* command, but native's own splitting sees the same command, so the hook stays silent and lets Claude Code decide. Implemented the documented way: exit 0 with empty stdout.

Defer keeps the hook **additive** for top-level commands -- it only *upgrades* those to `allow`/`deny` and never adds a prompt native wouldn't have shown. But it defers only where native is known to see the same command. Where the hook detects a hazard native's own matching can't be trusted to enforce, it forces `ask` instead:

- a **nested** unapproved command (inside a substitution, subshell, loop, etc.) that native's operator-splitting can't see -- e.g. `echo "$(curl evil.com)"` prompts, because native would otherwise auto-approve the read-only `echo` without inspecting the `curl`;
- an **`xargs` payload** whose static form matches only an exact rule that doesn't cover the stdin args native strips-and-approves blind to;
- a **mutating `find` action** (`-delete`, `-fprintf`, `-ok`, ...) or an unreadable `find` payload that could otherwise ride a broad `Bash(find *)`.

### What gets checked

**Full AST walk** -- commands inside `$(...)`, `` `...` ``, `<(...)`, subshells, loops, if-branches, case statements, heredocs, and function bodies are all extracted and checked individually.

For example, `echo "there are $(ls | wc -l) files"` is parsed into three sub-commands: `echo` (safe builtin), `ls` (safe read-only command), and `wc` (safe read-only command). Each is checked independently.

**Dynamic command names** -- `$CMD args` cannot be statically resolved, so the hook can't approve it and defers to Claude Code's own handling.

**Deny rules always win** -- deny patterns from any scope (user or project settings) block approval, matching Claude Code's own semantics.

### Redirect validation

Output redirects (`>`, `>>`, `&>`, etc.) are validated to prevent writes outside allowed directories. This matches the built-in Claude Code Bash tool's behavior.

**Auto-allowed:**
- Redirects to files inside the current working directory
- Safe devices: `/dev/null`, `/dev/stdout`, `/dev/stderr`, `/dev/stdin`, `/dev/zero`, `/dev/random`, `/dev/urandom`
- FD-to-FD duplications: `2>&1`, `>&2`
- Heredocs and here-strings: `<<EOF`, `<<<`

**Requires confirmation:**
- Redirects outside the working directory (unless in `additionalDirectories`)
- Protected paths: `.git/` and `.claude/` directories at any nesting level
- Dynamic targets: `> $FILE`, `> ~/file`, `> *.log`, extglob patterns
- Relative redirects when `cd`, `pushd`, `popd`, or `ln` appear in the command (TOCTOU protection)

**Not checked:** Input redirects (`<`, `<<`) are not validated, matching the built-in Bash tool.

Symlinks are fully resolved before path checks to prevent escape attacks.

#### Additional output directories

To allow redirects to directories outside cwd (e.g., `/tmp`), add them to Claude Code's standard `additionalDirectories` setting:

```json
{
  "permissions": {
    "additionalDirectories": ["/tmp", "/var/log/myapp"]
  }
}
```

This is the same key Claude Code uses to extend its workspace, so no separate configuration is needed. On macOS, `/tmp` automatically includes `/private/tmp` and `$TMPDIR`. Paths must be absolute.

### Command safety tiers

Commands are classified into tiers to minimize how many explicit allow rules you need:

**Always safe** -- auto-approved regardless of arguments. These are read-only commands that cannot cause side effects:
- Shell builtins: `true`, `false`, `:`, `test`, `[`, `[[`
- Read-only commands: `ls`, `cat`, `head`, `tail`, `wc`, `uniq`, `date`, `whoami`, `basename`, `dirname`, `realpath`, `readlink`, `which`, `file`, `stat`, `uname`, `id`, `hostname`, `tr`, `cut`, `rev`, `seq`, `sleep`, `diff`, `comm`, `printenv`

**Safe builtins** -- shell builtins that are auto-approved because any commands embedded in their arguments via `$(...)` or `<(...)` are extracted and checked separately:
- `echo`, `printf`, `cd`, `pwd`, `exit`, `return`, `shift`, `unset`, `read`, `pushd`, `popd`, `dirs`, `hash`, `type`, `umask`, `wait`, `times`, `ulimit`, `break`, `continue`, `getopts`

**Require explicit allow pattern** -- these can execute arbitrary code or mutate shell behavior:
- `source`, `.`, `eval`, `exec`, `set`, `trap`, `builtin`, `alias`, `unalias`, `let`

**Everything else** (external commands like `git`, `npm`, `curl`, `sed`, etc.) requires a matching allow pattern in your settings.

### Command wrappers

Some commands reveal nothing by their own name -- the danger (or safety) lives in
the command they forward to. These are unwrapped and the *inner* command is checked
against the same rules:

- `xargs [opts] CMD ...`
- `find ... -exec CMD ... {} \;` and `find ... -execdir CMD ... {} +`
- Exec-prefix wrappers: `timeout [opts] DURATION CMD ...`, `nice [opts] CMD ...`,
  `nohup CMD ...`, `stdbuf [opts] CMD ...`

So `rg --files | xargs grep -l Foo`, `find . -name '*.go' -exec grep -l Foo {} \;`,
and `timeout 30 npm test` are as quiet as the inner command alone (assuming it's
allowed), while `xargs rm`, `find . -exec rm {} \;`, and `nice rm -rf /` still
prompt. A wrapper whose payload can't be read fails closed (asks), and a deny rule
on the inner command wins through any depth of wrapping. This means you should
*not* add a blanket `Bash(find * -exec *)` ask rule -- it would shadow the
per-payload check; keep narrower action rules like `Bash(find * -delete*)` instead.
Because the wrapper is transparent, an allow rule on the wrapper name itself (e.g.
`Bash(timeout *)`) does *not* approve its payload -- the inner command must match.

**`xargs` appends stdin arguments.** Plain `xargs foo` runs `foo` with tokens read
from stdin tacked onto the end, so the payload we can see (`foo`) is only a *prefix*
of what actually runs. To avoid approving more than a rule intends, an `xargs`
payload is auto-approved only by a rule that tolerates arbitrary trailing arguments
-- a trailing wildcard like `Bash(rm *)` or `Bash(rm /tmp/x*)`. An *exact* rule such
as `Bash(rm /tmp/x)` does **not** approve `... | xargs rm /tmp/x` (which really runs
`rm /tmp/x <stdin>`) -- and because native strips a bare `xargs` and *would* approve
on that same exact rule (it doesn't model the appended tokens), the hook forces a
prompt here rather than deferring. Replace mode (`xargs -I{} CMD {}`) substitutes at
the visible `{}` placeholder instead of appending, so it is matched as written, the
same as `find -exec`.

This matches Claude Code's built-in wrapper stripping, with two intentional
differences: this hook also unwraps `xargs` when it carries flags (`xargs -n1
grep`) and `find -exec`, both of which Claude Code leaves as prompts. bash's `time`
keyword needs no special handling -- the parser already treats `time CMD` as `CMD`.

## Install

### Plugin (recommended)

No Go toolchain required. Add the marketplace and install the plugin:

```
/plugin marketplace add gwatts/claude
/plugin install compound-bash@gwatts
```

The plugin automatically downloads a pre-built binary for your platform (macOS, Linux, Windows via WSL/Git Bash) on first use.

### Go install (alternative)

If you have Go 1.26+ installed:

```sh
go install github.com/gwatts/claude-compound-bash/cmd/claude-compound-bash@latest
```

Then add the hook to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": ["claude-compound-bash"]
      }
    ]
  }
}
```

## Pattern format

The hook reads allow, ask, and deny patterns from your Claude Code settings files:
- `~/.claude/settings.json` and `~/.claude/settings.local.json`
- `<project>/.claude/settings.json` and `<project>/.claude/settings.local.json`

Patterns use the same [`Bash(...)` format](https://code.claude.com/docs/en/permissions#wildcard-patterns) as Claude Code:

| Pattern              | Matches                                     |
| -------------------- | ------------------------------------------- |
| `Bash` or `Bash(*)` | Any command                                 |
| `Bash(git *)`        | `git` with any arguments                    |
| `Bash(git add *)`    | `git add` with any arguments                |
| `Bash(jq)`           | Exactly `jq` with no arguments              |
| `Bash(* --version)`  | Any command ending with `--version`          |
| `Bash(git * main)`   | `git` commands with `main` at the end        |
| `Bash(ls *)`         | `ls` with args (`ls -la` yes, `lsof` no)    |
| `Bash(ls*)`          | Anything starting with `ls` (including `lsof`) |

The space before `*` matters for word boundaries: `Bash(ls *)` requires a space after `ls`, while `Bash(ls*)` does not.

The legacy colon-delimited form (`Bash(git:*)`) is also supported.

## Logging

The hook logs decisions to `~/.claude/logs/compound-bash.log` with version-tagged entries showing exactly which sub-commands were checked and why:

```
2026-03-16T21:15:14-05:00 [0.9.9] loaded 3 allow, 0 ask, 1 deny patterns from [~/.claude/settings.json]
2026-03-16T21:15:14-05:00 [0.9.9] evaluating: git add -A && git commit -m "fix"
2026-03-16T21:15:14-05:00 [0.9.9] parsed 2 sub-command(s)
2026-03-16T21:15:14-05:00 [0.9.9]   ok [git add -A]: matched allow pattern for "git add -A"
2026-03-16T21:15:14-05:00 [0.9.9]   ok [git commit -m "fix"]: matched allow pattern for "git commit -m fix"
2026-03-16T21:15:14-05:00 [0.9.9] ALLOW: all 2 sub-command(s) matched
```

When a command can't be approved, the log shows exactly which sub-command was the problem. The hook defers (emits no decision) and lets Claude Code's own permission flow handle it:

```
2026-03-16T21:15:14-05:00 [0.9.9] evaluating: git status && curl example.com
2026-03-16T21:15:14-05:00 [0.9.9] parsed 2 sub-command(s)
2026-03-16T21:15:14-05:00 [0.9.9]   ok [git status]: matched allow pattern for "git status"
2026-03-16T21:15:14-05:00 [0.9.9] DEFER [curl example.com]: not in allow list: "curl example.com"
```

Set `CLAUDE_COMPOUND_LOG` to override the log path, or use `claude --debug` to see hook output in the transcript.

## Troubleshooting

**Hook not firing**: Run `/hooks` in Claude Code to confirm the hook is registered. Check `~/.claude/logs/compound-bash.log` for output.

**Commands not auto-approving**: Check the log to see which sub-command isn't matched. Add the appropriate `Bash(...)` pattern to your settings, or check that your settings file is being found (the log shows which files were loaded).

**"no allow patterns configured"**: The hook couldn't find any allow patterns in your settings files. Check that `permissions.allow` exists in `~/.claude/settings.json` or project settings.
