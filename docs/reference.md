# Reference

logredact has three functions. Their doc comments on
[pkg.go.dev](https://pkg.go.dev/github.com/tetriz-ai/logredact) carry these signatures.

| Function | Signature |
|---|---|
| `Redact` | `Redact(s string) string` |
| `RedactStruct` | `RedactStruct(s *structpb.Struct)` |
| `VendorErrorDetail` | `VendorErrorDetail(body []byte) string` |

All three functions are safe for concurrent use, need no configuration and never return an
error. `RedactStruct` edits the `Struct` in place, so do not share one `Struct` between goroutines
while `RedactStruct` runs. The other two are pure.

## Redact

`Redact` masks well-known access tokens, URL passwords, email addresses and home directories
in a string. Every match is replaced with `[REDACTED]`, except email addresses and home
directories, which are shortened.

| Class | Example | Result |
|---|---|---|
| Bearer credential, in any case | `auth: Bearer abc.def` | `auth: [REDACTED]` |
| Google OAuth token | `ya29.token-here` | `[REDACTED]` |
| GitHub classic personal token | `ghp_abc` | `[REDACTED]` |
| GitHub OAuth token | `gho_xxx` | `[REDACTED]` |
| GitHub server-to-server token | `ghs_yyy` | `[REDACTED]` |
| GitHub user-to-server token | `ghu_abc` | `[REDACTED]` |
| GitHub refresh token | `ghr_abc` | `[REDACTED]` |
| GitHub fine-grained personal token | `github_pat_11ABC` | `[REDACTED]` |
| `sk-` secret key, used by OpenAI and others | `key=sk-abc` | `key=[REDACTED]` |
| Google API key | `AIza` followed by 35 letters, digits, `_` or `-` | `[REDACTED]` |
| Stripe secret or restricted key | `sk_live_example`, `rk_test_example` | `[REDACTED]` |
| Stripe webhook signing secret | `whsec_example` | `[REDACTED]` |
| GitLab personal token | `glpat-example` | `[REDACTED]` |
| npm token | `npm_example` | `[REDACTED]` |
| SendGrid key | `SG.example.example` | `[REDACTED]` |
| Slack app token | `xapp-example` | `[REDACTED]` |
| Slack refresh, session or rotation token | `xoxr-example`, `xoxs-example`, `xoxe-example` | `[REDACTED]` |
| Slack incoming webhook | `https://hooks.slack.com/services/T/B/example` | `[REDACTED]` |
| PEM private-key block (PKCS#8, RSA, EC, DSA, OpenSSH, encrypted) | `-----BEGIN PRIVATE KEY-----` through its end marker, across lines | `[REDACTED]` | <!-- synthetic marker: gitleaks:allow -->
| Slack bot token | `xoxb-12345` | `[REDACTED]` |
| Slack user token | `xoxp-67890` | `[REDACTED]` |
| Slack legacy token | `xoxa-abcdef` | `[REDACTED]` |
| JSON Web Token, signed or unsecured | `eyJabc.eyJdef.signature123` | `[REDACTED]` |
| AWS access key ID, starting `AKIA`, `ASIA`, `ABIA` or `ACCA` | `AKIAIOSFODNN7EXAMPLE` | `[REDACTED]` |
| Password in a URL | `postgres://app:hunter2@db/main` | `postgres://app:[REDACTED]@db/main` |
| Email address | `alice@mail.example.co.uk` | `a***@m***.example.co.uk` |
| Home directory | `/home/bob/code/main.go` | `~/code/main.go` |

### Patterns

Where a pattern starts with a group in parentheses, the text that group matched is kept.

| Class | Go regexp |
|---|---|
| Bearer credential | `(?i)Bearer(?:[\t\v\f\p{Zs}]+Bearer)*[\t\v\f\p{Zs}]+\S+` |
| Google OAuth token | `(^\|[^A-Za-z]\|%(?:25)*[0-9A-Fa-f]{2})ya29\.\S+` |
| The five GitHub tokens above, from classic personal to refresh | `(^\|[^A-Za-z]\|%(?:25)*[0-9A-Fa-f]{2})gh[opsur]_\S+` |
| GitHub fine-grained personal token | `(^\|[^A-Za-z]\|%(?:25)*[0-9A-Fa-f]{2})github_pat_\S+` |
| `sk-` secret key | `(^\|[^A-Za-z]\|%(?:25)*[0-9A-Fa-f]{2})sk-\S+` |
| Slack xox tokens | `(^\|[^A-Za-z]\|%(?:25)*[0-9A-Fa-f]{2})xox[bpaers]-\S+` |
| Google API key | `(^\|[^A-Za-z]\|%(?:25)*[0-9A-Fa-f]{2})AIza[0-9A-Za-z_-]{35}` |
| Stripe secret key | `(^\|[^A-Za-z]\|%(?:25)*[0-9A-Fa-f]{2})sk_(?:live\|test)_\S+` |
| Stripe restricted key | `(^\|[^A-Za-z]\|%(?:25)*[0-9A-Fa-f]{2})rk_(?:live\|test)_\S+` |
| Stripe webhook secret | `(^\|[^A-Za-z]\|%(?:25)*[0-9A-Fa-f]{2})whsec_\S+` |
| GitLab | `(^\|[^A-Za-z]\|%(?:25)*[0-9A-Fa-f]{2})glpat-\S+` |
| npm | `(^\|[^A-Za-z]\|%(?:25)*[0-9A-Fa-f]{2})npm_\S+` |
| SendGrid | `(^\|[^A-Za-z]\|%(?:25)*[0-9A-Fa-f]{2})SG\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+` |
| Slack app | `(^\|[^A-Za-z]\|%(?:25)*[0-9A-Fa-f]{2})xapp-\S+` |
| Slack webhook | `(^\|[^A-Za-z]\|%(?:25)*[0-9A-Fa-f]{2})https://hooks\.slack\.com/services/\S+` |
| PEM private key | `(^\|[^A-Za-z]\|%(?:25)*[0-9A-Fa-f]{2})-----BEGIN (?:RSA \|EC \|DSA \|OPENSSH \|ENCRYPTED )?PRIVATE KEY-----(?s:.*?)-----END (?:RSA \|EC \|DSA \|OPENSSH \|ENCRYPTED )?PRIVATE KEY-----` |
| JSON Web Token | `(^\|[^A-Za-z]\|%(?:25)*[0-9A-Fa-f]{2})eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*` |
| AWS access key ID, long-term (`AKIA`) | `(^\|[^A-Za-z]\|%(?:25)*[0-9A-Fa-f]{2})AKIA[0-9A-Z]{16}` |
| AWS access key ID, temporary (`ASIA`) | `(^\|[^A-Za-z]\|%(?:25)*[0-9A-Fa-f]{2})ASIA[0-9A-Z]{16}` |
| AWS access key ID, STS service bearer token (`ABIA`) | `(^\|[^A-Za-z]\|%(?:25)*[0-9A-Fa-f]{2})ABIA[0-9A-Z]{16}` |
| AWS access key ID, context-specific credential (`ACCA`) | `(^\|[^A-Za-z]\|%(?:25)*[0-9A-Fa-f]{2})ACCA[0-9A-Z]{16}` |
| Password in a URL | `(://[^\s/:@]*:)[^\s/?#]+@` |
| Email address | `[\p{L}\p{N}._%+\-]+@[\p{L}\p{N}.\-]+\.\p{L}{2,}` |
| Home directory | `/(?:Users\|home)/[^/\s"'<>()\[\]{},;:\|&?#=\\]+` |

### How far a token match runs

Most token matches run to the next whitespace. Commas, quotes and query-string separators do
not stop them. In minified JSON or a URL, the rest of the text goes with the token. An AWS access
key ID, a Google API key, a SendGrid key and a JSON Web Token stop at their own shape.
PEM private-key blocks span lines through an end marker. An incomplete block without an end
marker is not matched.

| Input | Output |
|---|---|
| `{"token":"ghp_abc","user":"bob"}` | `{"token":"[REDACTED]` |
| `https://x.test/cb?access_token=ya29.abc&state=xyz` | `https://x.test/cb?access_token=[REDACTED]` |
| `token=ghp_abc,user=bob next` | `token=[REDACTED] next` |
| `?key=sk-abc&user=bob next` | `?key=[REDACTED] next` |

### Order of the rules

The rules run in four stages: tokens (PEM blocks before single-line credentials), URL passwords,
email addresses, then home directories. So an address that starts with a token prefix is redacted whole instead of
being masked as an address. A token inside a path takes the rest of the path with it.

| Input | Output |
|---|---|
| `sk-alice@example.com` | `[REDACTED]`, not `s***@e***.com` |
| `/Users/ghp_abc/x` | `/Users/[REDACTED]` |
| `/Users/alice@example.com/notes` | `~/notes`, because the address goes with the directory |

### Bearer

A repeated `Bearer` is skipped, so the credential after it is what gets masked.
`auth: Bearer Bearer abc.def` becomes `auth: [REDACTED]`. The credential must be on the same
line as the word.

### Where a token starts

A prefix counts at the start of the text, after any character that is not an ASCII letter, or
after a percent-escape such as `%3D` or `%253D`. So `key_sk-abc` and `cb?access_token%3Dya29.abc`
are masked. `task-list`, `disk-usage`, `xya29.abc` and `abceyJa.eyJb.c` stay as they are. Bearer
matches anywhere.

### AWS access key IDs

A key ID is `AKIA`, `ASIA`, `ABIA` or `ACCA` followed by exactly 16 upper-case letters or
digits. The match stops after those 20 characters, because the prefix alone can occur in
ordinary upper-case text. So `AKIAIOSFODNN7EXAMPLE` is masked, while `region=ASIA-PACIFIC` and a
bare `AKIA` stay as they are.

### Email mask

The mask keeps the first character of the local part and the first character of the first
domain label. It also keeps the rest of the domain from its first dot. Letters and digits from
any script count, so `jürgen@bücher.de` becomes `j***@b***.de`. A match whose first domain label
is empty, such as `x@.example.com`, becomes `[REDACTED]`.

### Home directories

The user name runs to the next slash, whitespace, quote, bracket or separator such as `,` or
`=`. So `/Users/alice` becomes `~`, and `path=/Users/alice, next` becomes `path=~, next`.

## RedactStruct

`RedactStruct` walks a protobuf `Struct` to any depth. Every string gets the `Redact` rules,
unless it sits under a PII key. A PII key is a field name that marks its value as sensitive.
Its value is masked whatever it contains.

### PII keys

There are two kinds of PII key.

| Kind | Keys |
|---|---|
| Identity keys | `email`, `name` |
| Secret keys | `token`, `secret`, `secrets`, `password`, `auth`, `authorization`, `credential`, `credentials`, `creds`, `session`, `session_token`, `access_token`, `refresh_token`, `api_key`, `x-api-key`, `client_secret`, `private_key`, `cookie`, `passwd`, `pwd`, `api_token`, `secret_key`, `access_key`, `aws_secret_access_key`, `set-cookie`, `private_key_id`, `dsn`, `connection_string`, `otp`, `pin` |

- **Spelling.** Case, underscores and hyphens are ignored. `apiKey`, `API_KEY` and `Api-Key` are all `api_key`.
- **Exact list.** Otherwise the name must match one on the list exactly.
- **Depth.** A PII key applies to every string beneath it, in lists and structs alike.
- **Nearest key.** A PII key lower down takes over from the one above it.

A name close to one on the list, such as `auth_method`, `credential_id` or `secret_name`,
gets only the `Redact` rules. So a secret with no token prefix
under that name is logged in full. Check your field names against the list, or mask those
fields yourself.

### How each value is masked

A secret value always keeps only its first character followed by `***`, whatever it contains.
An identity value does the same, unless it is one whole email address.

| Key | Value | Result |
|---|---|---|
| `email` | `alice@example.com` | `a***@e***.com` |
| `name` | `Alice Smith <alice@example.com>` | `A***` |
| `name` | `Alice Smith` | `A***` |
| `password` | `hunter2` | `h***` |
| `password` | `["hunter2"]` | `["h***"]` |
| `password` | `123456` as a number | `"1***"` |
| `token` | `{"value": "abc"}` | `{"value": "a***"}` |

Every other kind of value is handled like this.

| Value | Treatment |
|---|---|
| Empty or one-character value under any PII key | Unchanged |
| Any other string | `Redact` |
| Struct, including a struct inside a list | Walked with the same rules |
| Map key | Never changed |
| Number under a secret key | The string mask of its decimal form, such as `"1***"`. A one-digit number is unchanged. |
| Any other number, boolean or null | Unchanged |
| `nil` struct, or nil values anywhere inside | Ignored, with no panic |

## VendorErrorDetail

`VendorErrorDetail` turns a third-party API's error body into text you can put in an error or a
log line. It keeps only short values under a few known keys and drops the rest. That includes a
message that quotes the data you sent.

| Rule | Detail |
|---|---|
| Allowlisted keys | `category`, `code`, `correlationId`, `correlation_id`, `errorType`, `error_code`, `requestId`, `status` |
| Key match | Quoted JSON key, case-insensitive, at any depth |
| Output | `key=value` pairs separated by spaces, sorted by key and spelled as in the first row |
| Second layer | Each value is passed through `Redact` on its own. |
| No allowlisted key matched | Returns `""`. |
| Parsing | None. A byte scan, so a malformed body never fails and is never passed through. |

For each allowlisted key, the first occurrence whose value is a quoted string with no `"` or `\`
is used. Numbers and strings with escapes are skipped. That value must be 1 to 64 bytes of valid
UTF-8, with no whitespace of any script, no control character and no character that renders as
nothing, such as U+3164. If it fails, the key is dropped, and later occurrences are not tried.

## Versioning and compatibility

Releases follow [Semantic Versioning](https://semver.org). What the functions mask is part of
the contract. So a change to what a pattern matches, the shape of a mask, the PII key list or
the keys `VendorErrorDetail` keeps is a breaking change, even when no signature changes.

Before v1.0.0, such a change ships in a new minor version. Every release lists its changes in
[CHANGELOG.md](../CHANGELOG.md).

The minimum Go version is 1.23, set in `go.mod`. CI tests that version and the two newest Go
releases.
