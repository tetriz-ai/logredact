This example turns a failed response from someone else's API into an error that is safe to log.
The error body names a person, and `VendorErrorDetail` keeps only the status code and the short
identifiers. The API is a local `httptest` server started by the program, so no network call
leaves the machine.

```sh
go run ./examples/api-error-message
```

```text
HTTP 409 code=DUPLICATE requestId=req-7f3a status=error
```
