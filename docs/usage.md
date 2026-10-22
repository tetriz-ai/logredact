# Usage

[examples/](../examples/README.md) has a complete program for each common case, and CI runs every
one. [pkg.go.dev](https://pkg.go.dev/github.com/tetriz-ai/logredact) has a runnable example for
each function. The exact rules are in [reference.md](reference.md).

## Run the quick start from a clone

The README's quick-start program is also [examples/mask-log-line](../examples/mask-log-line/).
To see its result before you write any code, run it from a clone of this repo:

```sh
git clone https://github.com/tetriz-ai/logredact && cd logredact && go run ./examples/mask-log-line
```

## Redact free text

Use `Redact` on any string you are about to log, wrap into an error or paste into a ticket.

```go
package main

import (
	"fmt"

	"github.com/tetriz-ai/logredact"
)

func main() {
	fmt.Println(logredact.Redact("GET /home/bob/app.log token=sk-abc user=bob@example.com"))
	// GET ~/app.log token=[REDACTED] user=b***@e***.com
}
```

It masks only the formats in [reference.md](reference.md#redact), and
[limitations.md](limitations.md#redact) lists what passes through.

## Notes on RedactStruct

- It edits the `Struct` in place, so clone it first with `proto.Clone` if you still need the original.
- Check field names against the [PII key list](reference.md#pii-keys), since a near-miss such as `user_password` is not masked by name.

## Notes on VendorErrorDetail

- It can return an empty string, so also log the HTTP status code, which is safe.

## Notes on the slog hook

The `ReplaceAttr` hook in [examples/slog-handler](../examples/slog-handler/) passes every string
value through `Redact`, without a call at each log site.

- The hook sees string values only, including strings inside a `slog.Group`.
- It does not look inside errors, slices or other non-string values.
- It does not mask by key, so `"password", "hunter2"` is logged as it is.
- To mask by key, build the hook on your own list of keys.
- This package's PII keys apply to `RedactStruct` only.
