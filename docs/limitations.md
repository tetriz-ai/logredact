# Limitations

Check these before shipping logredact on data that matters. It is a defence-in-depth pass, not
a data-loss-prevention system. Each item is a rule of the design, and each has a table-driven
case in `contract_test.go`. A bug of the code's own is fixed, never listed here.

The exact patterns and key lists are in [reference.md](reference.md).

## Redact

**Passes through unmasked (can leak)**

- A token format not in the [table](reference.md#redact), such as a vendor-specific token with an unknown prefix.
- Formats with no fixed prefix, such as `Authorization: Basic ...` credentials.
- `key=value` secrets in free text, such as `password=hunter2`, libpq `password=` or Go MySQL DSNs.
- URL passwords with unescaped `/`, `?` or `#`: these delimit URL components. Percent-encode them.
- Windows home paths such as `C:\Users\alice`; only Unix-style `/Users/` and `/home/` paths are recognised.
- A Bearer credential on the line after the word `Bearer`.
- A token prefix glued to a preceding ASCII letter, such as `xghp_abc`.
- The AWS secret access key, although the AWS access key ID is masked.
- An address with no literal `@`, or a domain the address rule does not accept.

The AWS secret access key is 40 characters with no prefix of its own. Matching it would need
entropy detection, which this library does not do. An address needs a dot in its
domain and a last label of two or more letters. So `alice%40example.com`, `alice@localhost` and `alice@example.c` are not matched.

To mask a format of your own, run your own rule before `Redact`, as
[examples/custom-rules](../examples/custom-rules/) shows.

**Masks more than it should (harmless)**

- `Bearer` is matched as an ordinary word.
- The home-directory rule matches `/Users/` or `/home/` anywhere, whether or not it is on disk.
- Most token matches run to the next whitespace, through minified JSON, URLs and paths.
- Broad prefixes can match ordinary text: `sk-learn` and `sk-worker-7f9` are masked.
- Email-shaped text such as `icon@2x.png` and `git@github.com` is masked even in asset names or SSH URLs.

So `the bearer of bad news` becomes `the [REDACTED] bad news`. `/var/home/alice/x` becomes
`/var~/x`, and `GET /home/feed` becomes `GET ~`.
[How far a token match runs](reference.md#how-far-a-token-match-runs) shows the token cases.

## RedactStruct

**Passes through unmasked (can leak)**

- A secret with no token prefix under a key not on the [PII key list](reference.md#pii-keys), such as `auth_method`.
- Map keys. A key named `alice@example.com` stays as it is.

**Masks more than it should (harmless)**

The `name` key masks non-person values too: `payments-service` becomes `p***`.
The `Redact` rules above apply to every string not under a PII key.

## VendorErrorDetail

**Passes through unmasked (can leak)**

- A short value with no whitespace under an allowlisted key.

The allowlist checks the shape of a value, not its meaning. So `{"status":"Jane"}` gives
`status=Jane`.

**Masks more than it should (harmless)**

None known beyond the `Redact` rules above, which run on each value it keeps.
