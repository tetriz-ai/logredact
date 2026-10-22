---
name: add-token-format
description: Add a token format to Redact, from the first failing test to the changelog line. Use when a change adds an entry to tokenPatterns in redact.go.
---

# Adding a token format

Require a distinctive, documented prefix and a defined matching shape. Document expected
false positives in `docs/limitations.md`. An issue must have agreed to it first, as `CONTRIBUTING.md` says.

1. **Test first.** Add a case with a made-up token to `redactCases` in `redact_test.go`. Add a
   case to `redactEdgeCases` in `contract_test.go` showing that the prefix inside a word is
   left alone. Mark a fixture that looks real with `// gitleaks:allow`. Run
   `go test -race -count=1 ./...` and see the new cases fail.
2. **Pattern.** Add an entry to `tokenPatterns` in `redact.go`, with a comment naming the
   format. Build it with `prefixed`: the literal prefix first, then the rest of the pattern,
   usually `\S+`. `prefixed` puts `tokenStart` in front, so the prefix is not matched inside
   a word.
3. **Doc comment.** Add the prefix to the list in the doc comment on `Redact`.
4. **Checks.** Run `go test -race -count=1 ./...`. `TestRedactPrecheckIsTransparent` must
   pass. Then run `golangci-lint run` and `scripts/run-examples.sh`.
5. **Docs.** In `docs/reference.md`, add a row to the table under "Redact" and to its "Patterns"
   table. In `docs/performance.md`, update the count of passes `Redact` makes and the list of
   prefixes. Run `go test -bench . -benchmem` and update its table if the numbers moved.
6. **Changelog.** Add a line under Unreleased in `CHANGELOG.md`. A new format changes what is
   masked, so it is a breaking change and ships in a new minor version before v1.0.

No example lists the formats, so the `examples/` folder needs no change.
