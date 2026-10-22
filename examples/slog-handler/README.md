This example connects logredact to a `log/slog` logger, so every string attribute it writes is
masked. The hook is a `ReplaceAttr` function on the handler options, and it works with any
`slog` handler. The time attribute is dropped only so that the output below stays the same on
every run.

```sh
go run ./examples/slog-handler
```

```text
level=INFO msg="sync failed" user=a***@e***.com auth=[REDACTED]
```
