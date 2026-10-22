logredact has a fixed list of formats, and there is no way to register a new one. When your own
logs carry a secret it does not know, such as `password=hunter2`, run your own rule first and
then `Redact`. This example masks two `key=value` names and prints the line both ways, so you
can see what your rule adds.

```sh
go run ./examples/custom-rules
```

```text
login a***@e***.com password=hunter2 client_secret=s3cr3t
login a***@e***.com password=[REDACTED] client_secret=[REDACTED]
```
