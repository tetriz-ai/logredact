# Performance

Go's `regexp` package runs in time linear in its input, so hostile input cannot cause
catastrophic backtracking. `Redact` makes up to twenty-four regular-expression passes. It skips
each token pattern whose literal prefix, such as `sk-`, `AIza`, `glpat-`, `npm_`, `-----BEGIN `, `gh`, `eyJ` or `AKIA`, is not in the
text, and skips the email pass when there is no `@`. Call it on log text, not on large request
bodies in a hot loop.

These numbers come from `go test -bench . -benchmem`, which runs
[bench_test.go](../bench_test.go), on an Apple M2 Pro with Go 1.26.0 and `GOMAXPROCS=2`.

| Benchmark | Input | Result |
|---|---|---|
| `BenchmarkRedact` | a 144-byte log line with one token, one address and one home directory | about 7 µs, 1.5 KB, 17 allocations |
| `BenchmarkRedactNoCandidates` | a 144-byte log line with no token prefix, address or home directory | about 2.5 µs, 0.9 KB, 9 allocations |
| `BenchmarkVendorErrorDetail` | a 183-byte error body | about 7.7 µs, 1.4 KB, 59 allocations |
