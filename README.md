# claude-compound-bash

A Claude Code [PreToolUse hook](https://code.claude.com/docs/en/hooks) that auto-approves a Bash tool call when every command inside it -- including the ones Claude Code's own permission check doesn't look at -- is already covered by your rules or is known-safe. Fewer prompts on compound and wrapped commands, without loosening a single rule.

## What Claude Code already does -- and what this adds

Recent Claude Code versions handle much of this natively. This hook is designed to *complement* that, not duplicate it:

**Native already covers** (so this hook stays out of the way -- it emits no decision and lets native handle it):
- **Compound splitting** -- `git add -A && git commit -m 'fix'` is approved when both halves match. Native splits on `&&`, `||`, `;`, `|`, `|&`, `&`, and newlines. (This is [anthropics/claude-code#16561](https://github.com/anthropics/claude-code/issues/16561), now shipped -- the original reason this plugin existed.)
- **A read-only allowlist** -- `ls`, `cat`, `grep`, `find`, `wc`, read-only `git`, etc. run without a prompt.
- **Process-wrapper stripping** -- a rule for the inner command also matches `timeout`, `time`, `nice`, `nohup`, `stdbuf`, and *bare* `xargs`.

**This hook adds** what native's operator-splitting and name-matching don't reach:
- **Commands nested where native can't see them** -- inside `$(...)`, `` `...` ``, `<(...)`, subshells, loops, `if`/`case` bodies, and function bodies. `echo "$(curl evil.com)"` gets its inner `curl` checked instead of being auto-approved as a read-only `echo`.
- **More wrapper coverage** -- `find -exec`/`-execdir CMD` and `xargs` *with flags* (`xargs -n1 grep`), both of which native leaves as a prompt.
- **Argument-level hazards native's matching misses** -- an `xargs` payload's appended stdin args, and mutating `find` actions (`-delete`, `-fprintf`, `-ok`).
- **Redirect-target checks** -- writes outside the working directory or into `.git`/`.claude`.

The guiding rule: only ever *upgrade* a call to allow/deny, or force a prompt for a hazard native can't catch -- never add a prompt native wouldn't have shown on its own. It's a convenience-and-triage layer that shaves prompts off the safe common cases and flags the ones worth a look, not a hard security boundary (see [Limitations](#limitations)).

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

Output redirects (`>`, `>>`, `&>`, etc.) are validated to prevent writes outside allowed directories -- a check native permission *rules* don't perform on a redirect target. When a redirect fails this check the hook forces a prompt (it doesn't defer), so it holds even where native would otherwise auto-approve the command.

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

Commands are classified into tiers to minimize how many explicit allow rules you need. This set overlaps Claude Code's own read-only allowlist but isn't identical -- where the hook doesn't treat a command as safe but native does (e.g. `grep`, plain `find`), the call simply defers and native's read-only handling approves it, so you don't get an extra prompt either way:

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
allowed), while `xargs rm`, `find . -exec rm {} \;`, and `nice rm -rf /` don't
auto-approve. A deny rule on the inner command wins through any depth of wrapping.
A wrapper whose payload can't be read never auto-approves: a `find` whose action
can't be validated (e.g. `find . -ok CMD`) forces a prompt, since native might
approve it under a broad `Bash(find *)`; other unreadable wrappers defer to native.
This means you should *not* add a blanket `Bash(find * -exec *)` ask rule -- it
would shadow the per-payload check; keep narrower action rules like
`Bash(find * -delete*)` instead. Because the wrapper is transparent, an allow rule
on the wrapper name itself (e.g. `Bash(timeout *)`) does *not* approve its payload
-- the inner command must match.

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

**Commands not auto-approving**: Check the log to see which sub-command isn't matched. Add the appropriate `Bash(...)` pattern to your settings, or check that your settings file is being found (the log shows which files were loaded). Remember the hook only *adds* approvals -- if it can't approve a command it stays silent and Claude Code prompts as usual; adding the missing rule is what removes the prompt.

**No patterns loaded**: The log line `loaded 0 allow, 0 ask, 0 deny patterns` means the hook found no rules in any settings file. It still runs (so nested-command and redirect hazards are prompted, and read-only commands auto-approve), but it can't approve anything rule-based -- add `permissions.allow` entries to `~/.claude/settings.json` or project settings to reduce prompts.

## Limitations

This is a convenience-and-triage layer, not a security boundary -- treat it the way Claude Code treats its own permission rules, which its [docs](https://code.claude.com/docs/en/permissions) note are fragile for constraining arguments.

- **Deny-through-wrappers is best-effort.** The hook reimplements enough of `xargs`/`find` option parsing to find the inner command in the common forms, but exotic option spellings can still slip the parser. When that happens the payload isn't hidden into an *approval* -- it defers, so Claude Code still evaluates and typically prompts. For a hard guarantee, pair it with a native `deny` rule and/or the [sandbox](https://code.claude.com/docs/en/sandboxing).
- **It only sees what it can parse statically.** Dynamic command names (`$CMD`), and anything whose behavior depends on runtime values, can't be classified and are never auto-approved.
- **It never overrides a `deny` or `ask` rule to allow.** Claude Code evaluates its own deny/ask rules regardless of what the hook returns, so the hook can only ever be more cautious than your rules, not less.
