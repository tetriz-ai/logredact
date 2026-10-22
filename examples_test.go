// Copyright 2026 The logredact Authors
// SPDX-License-Identifier: MIT

package logredact_test

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"strings"
	"testing"
)

const quickStartExample = "examples/mask-log-line/main.go"

// The quick start lives in three places: the README, examples/mask-log-line
// and ExampleRedact, which pkg.go.dev shows. These checks keep them one program.
func TestQuickStartIsOneProgram(t *testing.T) {
	example, err := os.ReadFile(quickStartExample)
	if err != nil {
		t.Fatal(err)
	}
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		check func(t *testing.T)
	}{
		{"README quick start equals the example byte for byte", func(t *testing.T) {
			block, err := quickStartBlock(string(readme))
			if err != nil {
				t.Fatal(err)
			}
			if block != string(example) {
				t.Errorf("README quick start and %s differ.\nREADME:\n%s\nexample:\n%s", quickStartExample, block, example)
			}
		}},
		{"ExampleRedact runs the same code as the example", func(t *testing.T) {
			want := funcBody(t, quickStartExample, "main")
			got := funcBody(t, "example_test.go", "ExampleRedact")
			if got != want {
				t.Errorf("ExampleRedact body and main in %s differ, ignoring comments.\nExampleRedact:\n%s\nmain:\n%s", quickStartExample, got, want)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, tt.check)
	}
}

// quickStartIndent is the indent of the quick-start code block, which sits
// under a numbered step in the README. It is four spaces, not the list's three,
// so that a Markdown renderer keeps each line's leading tab whole.
const quickStartIndent = "    "

// quickStartBlock returns the first ```go block after the README's
// "## Quick start" heading, with its list indent removed and its trailing
// newline. Every non-empty line must carry the indent.
func quickStartBlock(readme string) (string, error) {
	_, section, ok := strings.Cut(readme, "\n## Quick start\n")
	if !ok {
		return "", errors.New("README has no ## Quick start heading")
	}
	_, rest, ok := strings.Cut(section, "\n"+quickStartIndent+"```go\n")
	if !ok {
		return "", errors.New("README quick start has no indented ```go block")
	}
	block, _, ok := strings.Cut(rest, "\n"+quickStartIndent+"```\n")
	if !ok {
		return "", errors.New("README quick start ```go block is not closed")
	}
	lines := strings.Split(block, "\n")
	for i, line := range lines {
		if line == "" {
			continue
		}
		trimmed, ok := strings.CutPrefix(line, quickStartIndent)
		if !ok {
			return "", fmt.Errorf("README quick start line %d is not indented by %q: %q", i+1, quickStartIndent, line)
		}
		lines[i] = trimmed
	}
	return strings.Join(lines, "\n") + "\n", nil
}

// funcBody prints the body of the named function without its comments, so
// that ExampleRedact's "// Output:" line and main's plain comment compare equal.
func funcBody(t *testing.T, path, name string) string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != name {
			continue
		}
		var buf bytes.Buffer
		if err := printer.Fprint(&buf, fset, fn.Body); err != nil {
			t.Fatal(err)
		}
		return buf.String()
	}
	t.Fatalf("%s has no func %s", path, name)
	return ""
}
