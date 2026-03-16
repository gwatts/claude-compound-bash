# claude-compound-bash

A Claude Code [PreToolUse hook](https://docs.anthropic.com/en/docs/claude-code/hooks) that auto-approves compound bash commands when every sub-command individually matches your allow rules.

## The problem

Claude Code checks each `Bash` tool call against your permission rules before executing.
Single commands like `git status` match fine, but compound commands like `git add -A && git commit -m 'fix'` are treated as a single opaque string that doesn't match any individual rule -- so you get prompted every time.

## What this does

Parses compound commands using [`mvdan.cc/sh/v3`](https://pkg.go.dev/mvdan.cc/sh/v3) (the parser behind `shfmt`), walks the full AST to extract every command that will execute, and checks each against your `~/.claude/settings.json` allow patterns.

**Key behaviors:**

- **Fail closed** -- if the parser can't handle the input, it defers to Claude Code's normal approval flow. No fallback parser.
- **Full AST walk** -- commands inside `$(...)`, `` `...` ``, `<(...)`, subshells, loops, if-branches, case statements, and function bodies are all extracted and checked.
- **Three-tier builtin classification:**
  - _Always inert_ (`true`, `false`, `test`, `[`, `[[`) -- auto-allowed regardless of arguments
  - _Inert if literal_ (`echo`, `cd`, `printf`, `read`, etc.) -- auto-allowed only when arguments contain no command or process substitutions
  - _Never auto-allow_ (`source`, `.`, `eval`, `exec`, `set`, `trap`, `builtin`) -- always require an explicit pattern match
- **Dynamic command names denied** -- `$CMD args` cannot be statically resolved, so it's never auto-approved.
- **Deny rules always win** -- reads `~/.claude/settings.json`, `~/.claude/settings.local.json`, and project-level `.claude/settings.json`/`.claude/settings.local.json`. Deny patterns from any scope block approval, matching Claude Code's own semantics.
- **Safe logging** -- writes to `~/.claude/logs/compound-bash.log` with 0600 permissions in a 0700 directory.

## What this does NOT do

- **It doesn't bypass Claude Code's permission system.** It only auto-approves commands that you've already allowed individually. If `curl` isn't in your allow list, `git status && curl evil.com` still prompts.
- **It doesn't handle non-Bash tools.** It ignores `Read`, `Write`, `Edit`, etc.
- **It doesn't auto-deny.** When it can't approve a command, it defers to Claude Code's normal flow rather than blocking outright. You'll see a system message noting which sub-command wasn't matched.

## Install

### Plugin (recommended)

No Go toolchain required. Install directly from the repo:

```
/install-plugin https://github.com/gwatts/claude-compound-bash.git
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

Patterns use the same `Bash(...)` format as Claude Code:

| Pattern           | Matches                                  |
| ----------------- | ---------------------------------------- |
| `Bash(*)`         | Any command                              |
| `Bash(git:*)`     | `git` with any arguments                 |
| `Bash(git add:*)` | `git add` with any arguments             |
| `Bash(jq)`        | Exactly `jq` with no arguments           |
| `Bash(sed *)`     | `sed` followed by anything (glob format) |

The colon-delimited form (`prefix:glob`) does literal prefix matching then globs the remainder. The no-colon form (`Bash(sed *)`) globs against the entire command string.
