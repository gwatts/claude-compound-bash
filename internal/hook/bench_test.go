package hook

import (
	"testing"

	"github.com/gwatts/claude-compound-bash/internal/logfile"
	"github.com/gwatts/claude-compound-bash/internal/matcher"
)

func BenchmarkProcessSimple(b *testing.B) {
	input := &HookInput{
		ToolName:  "Bash",
		ToolInput: ToolInput{Command: "git status"},
	}
	pats := matcher.ParsePatterns([]string{"Bash(git:*)"})
	log := logfile.NopLogger()

	for b.Loop() {
		Process(input, pats, nil, nil, log)
	}
}

func BenchmarkProcessCompound(b *testing.B) {
	input := &HookInput{
		ToolName:  "Bash",
		ToolInput: ToolInput{Command: "git add -A && git commit -m 'test' && git push origin main"},
	}
	pats := matcher.ParsePatterns([]string{"Bash(git:*)"})
	log := logfile.NopLogger()

	for b.Loop() {
		Process(input, pats, nil, nil, log)
	}
}

func BenchmarkProcessComplexPipeline(b *testing.B) {
	input := &HookInput{
		ToolName: "Bash",
		ToolInput: ToolInput{
			Command: `cat /etc/hosts | grep -v '^#' | awk '{print $2}' | sort -u | head -20`,
		},
	}
	pats := matcher.ParsePatterns([]string{
		"Bash(cat:*)", "Bash(grep:*)", "Bash(awk:*)", "Bash(sort:*)", "Bash(head:*)",
	})
	log := logfile.NopLogger()

	for b.Loop() {
		Process(input, pats, nil, nil, log)
	}
}

func BenchmarkProcessWithSubstitution(b *testing.B) {
	input := &HookInput{
		ToolName:  "Bash",
		ToolInput: ToolInput{Command: "echo $(git rev-parse HEAD) && git status"},
	}
	pats := matcher.ParsePatterns([]string{"Bash(git:*)", "Bash(echo:*)"})
	log := logfile.NopLogger()

	for b.Loop() {
		Process(input, pats, nil, nil, log)
	}
}
