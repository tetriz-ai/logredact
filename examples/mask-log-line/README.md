This is the smallest use of logredact: one call to `Redact` on one log line. The line holds a
home directory, an email address and a Bearer credential, and each is masked in its own way.
It is the README's quick-start program, unchanged, and a test keeps the two identical.

```sh
go run ./examples/mask-log-line
```

```text
upload of ~/report.csv for a***@e***.com failed: 401 with [REDACTED]
```
