# Contributing

Thank you for helping. The scope is deliberately small, as the README's "What it does not do"
says. Please open an issue before you start on a new pattern or a change to what the library
masks, so we can agree on it before you write the code.

## Run the checks

These are the checks CI runs on every pull request:

```sh
go build ./...
go vet ./...
go test -race -count=1 ./...
golangci-lint run   # golangci-lint v2.11.4 on Go 1.26, as CI pins; configuration in .golangci.yml
scripts/run-examples.sh
```

## Every change needs a test

A pull request without a test is not merged. Tests are table-driven, so follow the existing
files. A change to what a pattern matches or how a value is masked is a breaking change, as
[docs/reference.md](docs/reference.md#versioning-and-compatibility) says, so it also needs a
`CHANGELOG.md` entry.

## Adding a token format

A token format needs a distinctive, documented prefix and a defined matching shape.
Document expected false positives in `docs/limitations.md`. Formats without a fixed prefix
are out of scope. Open an issue first, with a public reference for the
format and made-up examples of text it should and should not match.

## Commit style

Use [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/): a short subject
such as `docs: clarify the email mask shape`, a blank line, then a body that
says why.

## Licensing of contributions

No sign-off line and no separately signed agreement are needed. By opening a pull request you
agree that your contribution is released under the project's [LICENSE](LICENSE).
