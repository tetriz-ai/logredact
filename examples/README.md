# Examples

| You want | Example |
|---|---|
| To mask one log line, the README's quick start | [mask-log-line](mask-log-line/) |
| To mask a secret format logredact does not know | [custom-rules](custom-rules/) |
| Every string a `log/slog` logger writes to be masked | [slog-handler](slog-handler/) |
| A safe error message from a third-party API's error body | [api-error-message](api-error-message/) |

Run each one with `go run ./examples/<name>` from the root of a clone of this repo, or run them
all and check every output against its README with `scripts/run-examples.sh`.
