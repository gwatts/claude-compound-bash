# claude-compound-bash

A Claude Code [PreToolUse hook](https://code.claude.com/docs/en/hooks) plugin that auto-approves Bash tool calls when every sub-command matches your existing permission rules or is a known-safe command.

See [anthropics/claude-code#16561](https://github.com/anthropics/claude-code/issues/16561) for the upstream feature request.

## The problem

Claude Code checks each `Bash` tool call against your permission rules before executing. Single commands like `git status` match fine, but compound commands like `git add -A && git commit -m 'fix'` are treated as a single opaque string that doesn't match any individual rule -- so you get prompted every time.

## How it works

The plugin registers a PreToolUse hook that intercepts every Bash tool call. It parses the command using [`mvdan.cc/sh/v3`](https://pkg.go.dev/mvdan.cc/sh/v3) (the parser behind `shfmt`), walks the full AST to extract every sub-command, and checks each one against your allow/ask/deny patterns from settings files.

Rules are evaluated in the same order as Claude Code: **deny → ask → allow**. The first matching rule wins.

For each tool call, the hook returns one of three decisions:

- **`allow`** -- every sub-command is either a known-safe command or matches an allow pattern. The command runs without prompting.
- **`ask`** -- at least one sub-command matches an ask pattern or isn't in the allow list. Claude Code shows its normal permission prompt.
- **`deny`** -- a sub-command matches an explicit deny pattern. The tool call is cancelled outright and Claude receives feedback explaining why.

### What gets checked

**Full AST walk** -- commands inside `$(...)`, `` `...` ``, `<(...)`, subshells, loops, if-branches, case statements, heredocs, and function bodies are all extracted and checked individually.

For example, `echo "there are $(ls | wc -l) files"` is parsed into three sub-commands: `echo` (safe builtin), `ls` (safe read-only command), and `wc` (safe read-only command). Each is checked independently.

**Dynamic command names rejected** -- `$CMD args` cannot be statically resolved, so it always defers to the prompt.

**Deny rules always win** -- deny patterns from any scope (user or project settings) block approval, matching Claude Code's own semantics.

### Command safety tiers

Commands are classified into tiers to minimize how many explicit allow rules you need:

**Always safe** -- auto-approved regardless of arguments. These are read-only commands that cannot cause side effects:
- Shell builtins: `true`, `false`, `:`, `test`, `[`, `[[`
- Read-only commands: `ls`, `cat`, `head`, `tail`, `wc`, `sort`, `uniq`, `date`, `whoami`, `basename`, `dirname`, `realpath`, `readlink`, `which`, `file`, `stat`, `uname`, `id`, `hostname`, `tr`, `cut`, `rev`, `seq`, `diff`, `comm`, `printenv`

**Safe builtins** -- shell builtins that are auto-approved because any commands embedded in their arguments via `$(...)` or `<(...)` are extracted and checked separately:
- `echo`, `printf`, `cd`, `pwd`, `exit`, `return`, `shift`, `unset`, `read`, `pushd`, `popd`, `dirs`, `hash`, `type`, `umask`, `wait`, `times`, `ulimit`, `break`, `continue`, `getopts`

**Require explicit allow pattern** -- these can execute arbitrary code or mutate shell behavior:
- `source`, `.`, `eval`, `exec`, `set`, `trap`, `builtin`, `alias`, `unalias`, `let`

**Everything else** (external commands like `git`, `npm`, `curl`, `sed`, etc.) requires a matching allow pattern in your settings.

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

When a command can't be approved, the log shows exactly which sub-command was the problem:

```
2026-03-16T21:15:14-05:00 [0.9.9] evaluating: echo "$(ls | wc -l | xargs)"
2026-03-16T21:15:14-05:00 [0.9.9] parsed 4 sub-command(s)
2026-03-16T21:15:14-05:00 [0.9.9]   ok [echo "$(ls | wc -l | xargs)"]: "echo" is inert builtin
2026-03-16T21:15:14-05:00 [0.9.9]   ok [ls]: "ls" is always-inert builtin
2026-03-16T21:15:14-05:00 [0.9.9]   ok [wc -l]: "wc" is always-inert builtin
2026-03-16T21:15:14-05:00 [0.9.9] ASK [xargs]: not in allow list: "xargs"
```

Set `CLAUDE_COMPOUND_LOG` to override the log path, or use `claude --debug` to see hook output in the transcript.

## Troubleshooting

**Hook not firing**: Run `/hooks` in Claude Code to confirm the hook is registered. Check `~/.claude/logs/compound-bash.log` for output.

**Commands not auto-approving**: Check the log to see which sub-command isn't matched. Add the appropriate `Bash(...)` pattern to your settings, or check that your settings file is being found (the log shows which files were loaded).

**"no allow patterns configured"**: The hook couldn't find any allow patterns in your settings files. Check that `permissions.allow` exists in `~/.claude/settings.json` or project settings.
