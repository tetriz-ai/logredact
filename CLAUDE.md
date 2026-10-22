# CLAUDE.md

## What this is

logredact is a Go library of three functions that mask well-known tokens, email addresses and home-directory paths: `Redact` for text, `RedactStruct` for a protobuf `Struct`, and `VendorErrorDetail` for a third-party API's error body.
It has no configuration, no logger integration and no entropy detection, so anything not in the tables in `docs/reference.md` passes through unchanged.

## Layout

- `redact.go`: the whole library, including the token patterns, the PII keys and the vendor allowlist.
- `redact_test.go`: the basic table of cases for each function.
- `contract_test.go`: edge cases, the concurrency check, and one case for every item in `docs/limitations.md`.
- `vendor_error_test.go`: what `VendorErrorDetail` must drop.
- `example_test.go`: the `Example` functions that pkg.go.dev shows.
- `examples_test.go`: keeps the README quick start, `examples/mask-log-line` and `ExampleRedact` one program.
- `bench_test.go`: the benchmarks behind the table in `docs/performance.md`.
- `docs/`: `reference.md` (exact rules), `limitations.md` (design limits), `usage.md` and `performance.md`.
- `examples/`: one runnable `main` package per folder, indexed in `examples/README.md`.
- `scripts/run-examples.sh`: runs every example and compares its output with its README.
- `.github/workflows/ci.yml`: the checks below. `.golangci.yml`: the lint config.
- `.claude/`: `settings.json`, the allowed commands, and `skills/add-token-format`. `.agents/skills` is a symlink to `.claude/skills` so Codex finds the same skill.

## Commands

Go 1.23 is the floor, set in `go.mod`. CI tests 1.23, 1.26 and 1.27. These are CI's test steps:

```sh
go build ./...
go vet ./...
go test -race -count=1 ./...
```

Lint uses golangci-lint v2.11.4, the version CI pins, on Go 1.26 in CI:

```sh
golangci-lint run
```

The linter binary must be built with a Go at least as new as the one that runs it. An older build fails with "file requires newer Go version", and its result is not valid.

The Examples job runs:

```sh
scripts/run-examples.sh
```

The Vulnerability check job runs `go install golang.org/x/vuln/cmd/govulncheck@v1.8.0`, then
`govulncheck ./...`, on Go 1.27. It runs on pushes to `main` and weekly, never on a pull request.

## Contract to keep

- What each function masks is the public API. A change to a pattern, a mask shape, the PII key list or the vendor allowlist is a breaking change. Pinned by `redact_test.go` and `contract_test.go`.
- `docs/limitations.md` lists only design choices: a token format not in the table, a format with no fixed prefix, a Bearer credential on the next line, a token prefix glued to a letter, the address rule, the PII key list, map keys, the vendor allowlist checking shape rather than meaning, Bearer as a word, and the home-directory rule. Each is pinned by a case in `contract_test.go`: `TestRedactByDesign`, `TestRedactEdgeCases` (unknown formats, Bearer across a line break, a prefix glued to a letter), `TestRedactStructByDesign`, `TestRedactStructContract` (map keys) or `TestVendorErrorDetailEdgeCases` (allowlist checks shape, not meaning). A bug is fixed, never listed there.
- All three functions are safe for concurrent use. Pinned by `TestConcurrentUse` under `-race`.
- `VendorErrorDetail` is an allowlist. A message, prose or a malformed body never passes through, and it returns `""` when nothing is admitted. Pinned by `vendor_error_test.go` and `TestVendorErrorDetailEdgeCases` in `contract_test.go`.
- No function returns an error, and nil input never panics. Pinned by `TestRedactStructToleratesNilParts` and `TestVendorErrorDetailNilBody` in `contract_test.go`.
- The literal-prefix pre-check in `redactTokens` never changes output. Every prefixed pattern is built by `prefixed`, so each match contains its prefix. Pinned by `TestRedactPrecheckIsTransparent` in `contract_test.go`.
- The README quick start and `examples/mask-log-line/main.go` are the same bytes. Pinned by `examples_test.go`.

## Making a change

- Write the test first. A behaviour change needs a case that fails before the change and passes after it.
- Add `Redact` cases to the `redactCase` tables in `redact_test.go` or `contract_test.go`, so the pre-check test runs them too.
- A change to what is masked needs a `CHANGELOG.md` line under Unreleased and the tables in `docs/reference.md` updated.
- Do not silence a lint finding with an inline `//nolint`. Fix the code instead.
- CI runs every example and compares its output with the `text` block in that example's README. The output must be the same on every run. Drop timestamps, and print protobuf values with `encoding/json`, because `protojson` varies its spacing on purpose.
- A new example is a folder under `examples/` with `main.go` and `README.md`, plus a row in `examples/README.md`. Its `main.go` needs a package comment such as `// Command <name> ...`, or revive fails the lint.
- To add a token format, follow `.claude/skills/add-token-format/SKILL.md`.
- Commits use Conventional Commits.

## Do not

- Do not remove `gitleaks:allow` from the fake tokens in test files. They are fixtures, not secrets.
- Do not add a bug to `docs/limitations.md`. Fix it, with a test that fails before the fix.
- Do not raise `go 1.23` in `go.mod`. It is the supported floor and the protobuf dependency's own.
- Do not move the lint job to Go 1.27. golangci-lint v2.11 cannot read Go 1.27 export data.
- Do not edit the README quick start without making the same edit in `examples/mask-log-line/main.go` and `ExampleRedact`.
- Do not add a dependency or a second `go.mod` for an example. Examples share this module.
