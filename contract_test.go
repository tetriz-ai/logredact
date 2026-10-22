// Copyright 2026 The logredact Authors
// SPDX-License-Identifier: MIT

package logredact

import (
	"reflect"
	"strings"
	"sync"
	"testing"

	"google.golang.org/protobuf/types/known/structpb"
)

// These tests pin the edges of the public contract that docs/reference.md
// documents: unusual input, the boundaries of each pattern, and the design
// choices listed in docs/limitations.md.

var long = strings.Repeat("a", 1<<20)

var redactEdgeCases = []redactCase{
	{"unicode around matches is kept", "日本語 Bearer abc ünï user@example.com", "日本語 [REDACTED] ünï u***@e***.com"},
	{"bearer value may be non-ASCII", "Bearer ключ", "[REDACTED]"},
	{"bearer is case-insensitive", "BEARER abc", "[REDACTED]"},
	{"bearer with no value is kept", "Bearer", "Bearer"},
	{"bearer credential after a tab", "Bearer\tabc", "[REDACTED]"},
	{"bearer credential after a vertical tab", "Bearer\vabc", "[REDACTED]"},
	{"bearer credential after a non-breaking space", "Authorization: Bearer abc123", "Authorization: [REDACTED]"},
	{"bearer stops at a line break", "auth bearer\nnext line", "auth bearer\nnext line"},
	{"bearer stops at a CRLF", "auth bearer\r\nnext line", "auth bearer\r\nnext line"},
	{"a repeated bearer word does not shield the secret", "Bearer Bearer secret", "[REDACTED]"},
	{"a repeated bearer word after a header name", "Authorization: bearer BEARER secret tail", "Authorization: [REDACTED] tail"},
	{"token match stops at whitespace", "sk-abc def", "[REDACTED] def"},
	{"standalone sk- key is redacted", "sk-abc", "[REDACTED]"},
	{"prefix after punctuation is redacted", "key=sk-abc", "key=[REDACTED]"},
	{"prefix after an underscore is redacted", "key_sk-abc", "key_[REDACTED]"},
	{"prefix after a digit is redacted", "1ghp_abc", "1[REDACTED]"},
	{"prefix after a non-ASCII letter is redacted", "ésk-abc", "é[REDACTED]"},
	{"prefix after a percent-escape is redacted", "cb?access_token%3Dya29.abc&x=1", "cb?access_token%3D[REDACTED]"},
	{"prefix after a lower-case percent-escape is redacted", "redirect=%3fkey%3dsk-abc", "redirect=%3fkey%3d[REDACTED]"},
	{"prefix after a double-encoded escape is redacted", "cb%3Faccess_token%253Dya29.abc", "cb%3Faccess_token%253D[REDACTED]"},
	{"prefix after a double-encoded equals sign is redacted", "key%253Dsk-abc", "key%253D[REDACTED]"},
	{"invalid UTF-8 before a token is kept", "\xffghp_abc", "\xff[REDACTED]"},
	// A prefix glued to a preceding ASCII letter is part of a word, not a token.
	{"prefix inside a word is not a token", "task-list", "task-list"},
	{"sk- inside disk-usage is not a token", "disk-usage", "disk-usage"},
	{"sk- inside risk-score is not a token", "risk-score", "risk-score"},
	{"gh prefix inside a word is not a token", "highghp_x", "highghp_x"},
	{"ya29. prefix inside a word is not a token", "xya29.abc", "xya29.abc"},
	{"github_pat_ prefix inside a word is not a token", "xgithub_pat_1", "xgithub_pat_1"},
	{"xox prefix inside a word is not a token", "xxoxb-1", "xxoxb-1"},
	{"jwt prefix inside a word is not a token", "abceyJa.eyJb.c", "abceyJa.eyJb.c"},
	{"github fine-grained personal token", "github_pat_11ABC", "[REDACTED]"},
	{"github user-to-server token", "ghu_abc", "[REDACTED]"},
	{"github refresh token", "ghr_abc", "[REDACTED]"},
	{"two-segment jwt lookalike is kept", "eyJabc.eyJdef", "eyJabc.eyJdef"},
	{"unsigned jwt is redacted", "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.", "[REDACTED]"},
	{"jwt after a separator", "id_token=eyJa.eyJb.c&x", "id_token=[REDACTED]&x"},
	{"aws access key id after a separator", "key=AKIAIOSFODNN7EXAMPLE next", "key=[REDACTED] next"},
	{"aws access key id matches its fixed 20-character length", "AKIAIOSFODNN7EXAMPLEtail", "[REDACTED]tail"},
	{"aws prefix glued to a preceding letter is not a token", "xAKIAIOSFODNN7EXAMPLE", "xAKIAIOSFODNN7EXAMPLE"},
	{"aws prefix without the full key shape is kept", "region=ASIA-PACIFIC now", "region=ASIA-PACIFIC now"}, // not a key, test fixture. gitleaks:allow
	{"aws temporary key id in minified JSON", `{"key":"ASIAY34FZKBOKMUTVV7A"}`, `{"key":"[REDACTED]"}`},     // fake AWS key, test fixture. gitleaks:allow
	{"aws sts service bearer token key id after a separator", "key=ABIAIOSFODNN7EXAMPLE next", "key=[REDACTED] next"},
	{"aws context-specific key id matches its fixed 20-character length", "ACCAY34FZKBOKMUTVV7Atail", "[REDACTED]tail"},
	// Tokens run before emails: with the order swapped this would be
	// "s***@e***.com".
	{"tokens run before emails", "sk-alice@example.com", "[REDACTED]"},
	// Tokens run before home directories: the token swallows the rest of the
	// path, so there is no "/Users/<name>" left to shorten.
	{"tokens run before home directories", "/Users/ghp_abc/x", "/Users/[REDACTED]"},
	{"token runs to the next whitespace in minified JSON", `{"token":"ghp_abc","user":"bob"}`, `{"token":"[REDACTED]`},
	{"token runs to the next whitespace in a URL", "https://x.test/cb?access_token=ya29.abc&state=xyz", "https://x.test/cb?access_token=[REDACTED]"},
	{"token runs past a comma", "token=ghp_abc,user=bob next", "token=[REDACTED] next"},
	{"token runs past a query-string separator", "?key=sk-abc&user=bob next", "?key=[REDACTED] next"},
	{"URL password is redacted", "postgres://app:hunter2@db.internal:5432/main", "postgres://app:[REDACTED]@db.internal:5432/main"},
	{"URL password with no user name is redacted", "redis://:hunter2@cache:6379", "redis://:[REDACTED]@cache:6379"},
	{"URL port is not a password", "http://db.internal:5432/main", "http://db.internal:5432/main"},
	{"URL password with a raw @ is redacted whole", "postgres://app:p@ssword@localhost:5432/main", "postgres://app:[REDACTED]@localhost:5432/main"},
	{"URL password with a colon is redacted whole", "redis://:a:b@host", "redis://:[REDACTED]@host"},
	{"an address in a URL path is not a password", "https://api.test:8443/users/bob@example.com", "https://api.test:8443/users/b***@e***.com"},
	// Tokens run before URL passwords: the token swallows the rest of the URL.
	{"tokens run before URL passwords", "postgres://app:sk-abc@db/main", "postgres://app:[REDACTED]"},
	// Emails run before home directories: the placeholder is not a user name.
	{"emails run before home directories", "/Users/x@.example.com/notes", "/Users/[REDACTED]/notes"},
	{"email inside a home path: the whole directory goes", "/Users/alice@example.com/notes", "~/notes"},
	{"unknown secret format passes through", "vendor_unknown_abc", "vendor_unknown_abc"},
	{"email keeps domain labels after the first", "alice@mail.example.co.uk", "a***@m***.example.co.uk"},
	{"email with dots and plus in local part", "a.b+tag@example.com", "a***@e***.com"},
	{"email with empty domain name is fully redacted", "x@.example.com", "[REDACTED]"},
	{"email with a non-ASCII local part", "jürgen@example.com", "j***@e***.com"},
	{"email starting with a non-ASCII letter", "ÉLODIE@example.com", "É***@e***.com"},
	{"email with a non-ASCII domain", "alice@bücher.de", "a***@b***.de"},
	{"home directory with nothing after it", "/home/bob/", "~/"},
	{"home directory without a trailing slash", "/Users/alice", "~"},
	{"home directory stops at a space", "see /home/bob and later /tmp/x", "see ~ and later /tmp/x"},
	{"home directory stops at punctuation", "path=/Users/alice, next", "path=~, next"},
	{"home directory inside a JSON string", `{"dir":"/home/bob"}`, `{"dir":"~"}`},
	{"home directory stops at an equals sign", "path=/Users/alice=x", "path=~=x"},
	{"home directory stops at a question mark", "/Users/alice?x", "~?x"},
	{"bare /home/ is kept", "/home/", "/home/"},
	{"windows paths are out of scope", `C:\Users\alice\file.txt`, `C:\Users\alice\file.txt`},
	{"one MiB of text around a token", long + " ghp_abc " + long, long + " [REDACTED] " + long},
}

func TestRedactEdgeCases(t *testing.T) {
	for _, tt := range redactEdgeCases {
		t.Run(tt.name, func(t *testing.T) {
			if got := Redact(tt.in); got != tt.want {
				t.Errorf("Redact(%.60q) = %.60q, want %.60q", tt.in, got, tt.want)
			}
		})
	}
}

// The design choices listed in docs/limitations.md. Each case is text
// that Redact leaves readable, or masks more than needed, on purpose.
var redactByDesignCases = []redactCase{
	{"ordinary sk prefix is masked", "pip install sk-learn", "pip install [REDACTED]"},
	{"pod name with sk prefix is masked", "pod sk-worker-7f9", "pod [REDACTED]"},
	{"asset name looks like an address", "icon@2x.png", "i***@2***.png"},
	{"SSH remote looks like an address", "git@github.com:org/r.git", "g***@g***.com:org/r.git"},
	{"unescaped slash terminates URL user info", "postgres://user:pass/word@db/main", "postgres://user:pass/word@db/main"},
	{"unescaped hash terminates URL user info", "postgres://user:pass#word@db/main", "postgres://user:pass#word@db/main"},
	{"Go MySQL DSN is not a URL", "user:pass@tcp(localhost:3306)/database", "user:pass@tcp(localhost:3306)/database"},
	{"libpq password has no prefix", "host=localhost password=hunter2", "host=localhost password=hunter2"},
	{"Windows home is not matched", `C:\Users\alice`, `C:\Users\alice`},
	{"bearer is matched as an ordinary word", "the bearer of bad news", "the [REDACTED] bad news"},
	{"basic auth credentials are not matched", "Authorization: Basic dXNlcjpwYXNz", "Authorization: Basic dXNlcjpwYXNz"},
	{"key=value secrets in free text are not matched", "password=hunter2", "password=hunter2"},
	// The AWS access key ID has a fixed prefix and is masked; the AWS secret
	// access key has none and cannot be matched without entropy detection.
	{"aws secret access key has no fixed prefix and is not matched", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
	{"URL-encoded address is not matched", "alice%40example.com", "alice%40example.com"},
	{"dotless domain is not matched", "alice@localhost", "alice@localhost"},
	{"single-letter TLD is not matched", "alice@example.c", "alice@example.c"},
	{"address without a dot in the domain is kept", "a@b", "a@b"},
	{"home directory below another directory", "/var/home/alice/x", "/var~/x"},
	{"a URL path under /home is shortened", "GET /home/feed", "GET ~"},
}

func TestRedactByDesign(t *testing.T) {
	for _, tt := range redactByDesignCases {
		t.Run(tt.name, func(t *testing.T) {
			if got := Redact(tt.in); got != tt.want {
				t.Errorf("Redact(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// The pre-check in redactTokens is an optimisation only. Every Redact case in
// the suite, plus generated cases around each prefix, must give the same token
// stage output with and without it.
func TestRedactPrecheckIsTransparent(t *testing.T) {
	var cases []redactCase
	cases = append(cases, redactCases...)
	cases = append(cases, redactEdgeCases...)
	cases = append(cases, redactByDesignCases...)
	for _, p := range tokenPatterns {
		if p.prefix != "" {
			cases = append(cases,
				redactCase{name: "bare prefix " + p.prefix, in: p.prefix},
				redactCase{name: "prefix inside a word " + p.prefix, in: "x" + p.prefix + "abc"},
				redactCase{name: "prefix after a space " + p.prefix, in: "x " + p.prefix + "abc"},
				redactCase{name: "prefix after a percent-escape " + p.prefix, in: "x%3D" + p.prefix + "abc"},
			)
		}
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			want := tt.in
			for _, p := range tokenPatterns {
				want = p.re.ReplaceAllString(want, tokenReplacement)
			}
			if got := redactTokens(tt.in); got != want {
				t.Errorf("redactTokens(%.60q) = %.60q, without pre-check %.60q", tt.in, got, want)
			}
		})
	}
}

// maskEmail's input is always one whole emailRegex match; each case checks that
// precondition before calling it.
func TestMaskEmail(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"well formed", "user@example.com", "u***@e***.com"},
		{"shortest the regex accepts", "a@b.cd", "a***@b***.cd"},
		{"several domain labels", "a@mail.example.co.uk", "a***@m***.example.co.uk"},
		{"empty first domain label", "x@.example.com", redactedPlaceholder},
		{"leading dots before the TLD", "x@..com", redactedPlaceholder},
		{"multi-byte first characters", "élodie@éxample.com", "é***@é***.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if m := emailRegex.FindString(tt.in); m != tt.in {
				t.Fatalf("precondition: %q is not a whole emailRegex match (got %q)", tt.in, m)
			}
			if got := maskEmail(tt.in); got != tt.want {
				t.Errorf("maskEmail(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestMaskPIIValue(t *testing.T) {
	tests := []struct {
		name string
		key  string
		in   string
		want string
	}{
		{"empty is kept", "name", "", ""},
		{"one character is kept", "password", "x", "x"},
		{"one multi-byte character is kept", "name", "é", "é"},
		{"two characters keep the first", "token", "ab", "a***"},
		// Identity keys (email, name): a value that is one whole address is
		// masked as an address. Anything else is cut to its first character.
		{"a whole address is masked as an address", "email", "alice@example.com", "a***@e***.com"},
		{"a whole address under name is masked as an address", "name", "alice@example.com", "a***@e***.com"},
		{"identity keys match case-insensitively", "EMAIL", "alice@example.com", "a***@e***.com"},
		{"a name beside an address is masked whole", "name", "Alice Smith <alice@example.com>", "A***"},
		{"a token beside an address is masked whole", "name", "Bearer abc123 for alice@example.com", "B***"},
		{"a home path beside an address is masked whole", "email", "alice@example.com at /Users/alice/src", "a***"},
		{"an identity value without an address is masked whole", "name", "Alice Smith", "A***"},
		// Secret keys: the first-character mask applies whatever the value holds.
		{"a secret that is an address is masked whole", "password", "alice@example.com", "a***"},
		{"a secret with an embedded address is masked whole", "secret", "S3cret!me@example.com tail", "S***"},
		{"a token without an address is masked whole", "token", "Bearer abc123", "B***"},
		// The mask keeps the first character, not the first byte.
		{"first character of a multi-byte value", "name", "Élodie", "É***"},
		{"invalid UTF-8 keeps the first byte", "secret", "\xffabc", "\xff***"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := maskPIIValue(tt.key, tt.in); got != tt.want {
				t.Errorf("maskPIIValue(%q, %q) = %q, want %q", tt.key, tt.in, got, tt.want)
			}
		})
	}
}

func TestIsPIIKey(t *testing.T) {
	tests := []struct {
		key  string
		want bool
	}{
		{"", false},
		{"email", true},
		{"EMAIL", true},
		{"Api_Key", true},
		{"apiKey", true},
		{"Api-Key", true},
		{"sessionToken", true},
		{"ACCESS-TOKEN", true},
		{"user_email", false},
		{"x-api-key", true},
		{"X-API-Key", true},
		{"client_secret", true},
		{"clientSecret", true},
		{"Cookie", true},
		{"private_key", true},
		{"Private-Key", true},
		{"credentials", true},
		{"Credentials", true},
		{"creds", true},
		{"user_name", false},
		{"session", true},
		{"Session", true},
		{"credential", true},
		{"Credential", true},
		{"secrets", true},
		{"SECRETS", true},
		{"auth", true},
		{"Auth", true},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			if got := isPIIKey(tt.key); got != tt.want {
				t.Errorf("isPIIKey(%q) = %v, want %v", tt.key, got, tt.want)
			}
		})
	}
}

type structCase struct {
	name string
	in   map[string]any
	want map[string]any
}

func runStructCases(t *testing.T, tests []structCase) {
	t.Helper()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := structpb.NewStruct(tt.in)
			if err != nil {
				t.Fatalf("NewStruct: %v", err)
			}
			RedactStruct(s)
			if got := s.AsMap(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("RedactStruct produced %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRedactStructContract(t *testing.T) {
	runStructCases(t, []structCase{
		{
			name: "recurses into structs inside a list, and their PII keys are masked",
			in: map[string]any{"items": []any{
				map[string]any{"email": "alice@example.com", "note": "Bearer abc"},
				map[string]any{"password": "hunter2"},
			}},
			want: map[string]any{"items": []any{
				map[string]any{"email": "a***@e***.com", "note": "[REDACTED]"},
				map[string]any{"password": "h***"},
			}},
		},
		{
			name: "PII keys ignore case, underscores and hyphens",
			in:   map[string]any{"Email": "bob@example.com", "API_KEY": "k-123", "apiKey": "sk_live_x", "Api-Key": "zzz", "Authorization": "Bearer abc", "refresh_token": "r-1"},
			want: map[string]any{"Email": "b***@e***.com", "API_KEY": "k***", "apiKey": "s***", "Api-Key": "z***", "Authorization": "B***", "refresh_token": "r***"},
		},
		{
			name: "a secret key with an address in its value is masked whole",
			in: map[string]any{
				"authorization": "Bearer abc123 for alice@example.com",
				"secret":        "S3cret!me@example.com tail",
			},
			want: map[string]any{"authorization": "B***", "secret": "S***"},
		},
		{
			name: "an identity value with text beside the address is masked whole",
			in:   map[string]any{"name": "Alice Smith <alice@example.com>", "email": "ops: alice@example.com"},
			want: map[string]any{"name": "A***", "email": "o***"},
		},
		{
			name: "an email under a non-PII key is still masked",
			in:   map[string]any{"user_email": "alice@example.com"},
			want: map[string]any{"user_email": "a***@e***.com"},
		},
		{
			name: "strings in a list under a PII key are masked by that key",
			in:   map[string]any{"password": []any{"hunter2", "Bearer abc"}, "email": []any{"alice@example.com"}},
			want: map[string]any{"password": []any{"h***", "B***"}, "email": []any{"a***@e***.com"}},
		},
		{
			name: "strings in a struct under a PII key are masked by that key",
			in:   map[string]any{"token": map[string]any{"value": "abc", "meta": map[string]any{"kind": "refresh"}}},
			want: map[string]any{"token": map[string]any{"value": "a***", "meta": map[string]any{"kind": "r***"}}},
		},
		{
			name: "a nearer PII key takes over from the one above it",
			in:   map[string]any{"token": map[string]any{"email": "alice@example.com"}},
			want: map[string]any{"token": map[string]any{"email": "a***@e***.com"}},
		},
		{
			name: "map keys are never redacted",
			in:   map[string]any{"alice@example.com": "ok", "ghp_abc": "ok"},
			want: map[string]any{"alice@example.com": "ok", "ghp_abc": "ok"},
		},
		{
			name: "one-character PII value is kept",
			in:   map[string]any{"password": "x"},
			want: map[string]any{"password": "x"},
		},
		{
			name: "empty PII value is kept",
			in:   map[string]any{"token": ""},
			want: map[string]any{"token": ""},
		},
		{
			name: "a number under a secret key is masked to its first character",
			in:   map[string]any{"password": 123456.0, "pin": map[string]any{"secret": -42.5}, "token": []any{1e21}},
			want: map[string]any{"password": "1***", "pin": map[string]any{"secret": "-***"}, "token": []any{"1***"}},
		},
		{
			name: "a one-digit number under a secret key is kept",
			in:   map[string]any{"password": 7.0},
			want: map[string]any{"password": 7.0},
		},
		{
			name: "null, boolean, and a number under an identity key are kept",
			in:   map[string]any{"token": nil, "password": true, "name": 42.0},
			want: map[string]any{"token": nil, "password": true, "name": 42.0},
		},
		{
			name: "client_secret, cookie, private_key and x-api-key are secret keys",
			in:   map[string]any{"client_secret": "hunter2", "Cookie": "sid=abc", "privateKey": "MIIE", "X-API-Key": "zzz"},
			want: map[string]any{"client_secret": "h***", "Cookie": "s***", "privateKey": "M***", "X-API-Key": "z***"},
		},
		{
			name: "session is a secret key, and a struct under it is masked by it",
			in:   map[string]any{"session": "hunter2", "Session": map[string]any{"id": "s-123", "ttl": 3600.0}},
			want: map[string]any{"session": "h***", "Session": map[string]any{"id": "s***", "ttl": "3***"}},
		},
		{
			name: "credentials and creds are secret keys, whatever the case",
			in:   map[string]any{"credentials": "topsecret", "creds": "abc123", "Credentials": "zzz"},
			want: map[string]any{"credentials": "t***", "creds": "a***", "Credentials": "z***"},
		},
		{
			name: "credential, secrets and auth are secret keys",
			in:   map[string]any{"credential": "hunter2", "secrets": "topsecret", "auth": "abc123"},
			want: map[string]any{"credential": "h***", "secrets": "t***", "auth": "a***"},
		},
		{
			name: "empty struct",
			in:   map[string]any{},
			want: map[string]any{},
		},
	})
}

// The key-list design choice listed in docs/limitations.md: only the
// listed names are PII keys.
func TestRedactStructByDesign(t *testing.T) {
	runStructCases(t, []structCase{
		{
			// password is the control: it must change, so a no-op passes nothing.
			name: "look-alike keys outside the PII key list get only the Redact rules",
			in: map[string]any{
				"user_name": "Alice Smith", "auth_method": "hunter2",
				"password": "hunter2",
			},
			want: map[string]any{
				"user_name": "Alice Smith", "auth_method": "hunter2",
				"password": "h***",
			},
		},
	})
}

// structpb values built by hand, rather than by NewStruct, can carry nil
// pointers at every level. None of them may panic, and a sibling field must
// still be redacted.
func TestRedactStructToleratesNilParts(t *testing.T) {
	RedactStruct(nil)
	RedactStruct(&structpb.Struct{})
	tests := []struct {
		name   string
		fields map[string]*structpb.Value
	}{
		{"nil value", map[string]*structpb.Value{"a": nil}},
		{"value with no kind", map[string]*structpb.Value{"a": {}}},
		{"nil nested struct", map[string]*structpb.Value{"a": {Kind: &structpb.Value_StructValue{}}}},
		{"nil list", map[string]*structpb.Value{"a": {Kind: &structpb.Value_ListValue{}}}},
		{"nil list item", map[string]*structpb.Value{
			"a": structpb.NewListValue(&structpb.ListValue{Values: []*structpb.Value{nil}}),
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.fields["b"] = structpb.NewStringValue("ghp_x")
			RedactStruct(&structpb.Struct{Fields: tt.fields})
			if got := tt.fields["b"].GetStringValue(); got != redactedPlaceholder {
				t.Errorf("sibling field b = %q, want %q", got, redactedPlaceholder)
			}
		})
	}
}

func TestVendorErrorDetailEdgeCases(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{"zero-length body", "", ""},
		{"non-string values are skipped", `{"status":404,"code":"NOT_FOUND"}`, "code=NOT_FOUND"},
		{"key match ignores case, output uses the allowlist spelling", `{"RequestID":"req-1"}`, "requestId=req-1"},
		{"whitespace around the colon is allowed", `{"code" : "X"}`, "code=X"},
		{"unquoted keys are not JSON and do not match", `{code:"X"}`, ""},
		{"empty value is dropped", `{"code":""}`, ""},
		{"64-byte value is kept", `{"code":"` + strings.Repeat("a", 64) + `"}`, "code=" + strings.Repeat("a", 64)},
		{"65-byte value is dropped", `{"code":"` + strings.Repeat("a", 65) + `"}`, ""},
		{"tab inside a value is dropped", "{\"code\":\"a\tb\"}", ""},
		{"CR inside a value is dropped", "{\"code\":\"a\rb\"}", ""},
		{"LF inside a value is dropped", "{\"code\":\"a\nb\"}", ""},
		// A value class that admitted backslashes would keep these two.
		{"escaped backslash inside a value is dropped", `{"code":"a\\b"}`, ""},
		{"escaped newline inside a value is dropped", `{"code":"a\nb"}`, ""},
		{"non-breaking space inside a value is dropped", "{\"code\":\"Jane\u00a0Doe\"}", ""},
		{"ideographic space inside a value is dropped", "{\"code\":\"a\u3000b\"}", ""},
		{"zero-width space inside a value is dropped", "{\"code\":\"a\u200bb\"}", ""},
		{"control character inside a value is dropped", "{\"code\":\"a\x01b\"}", ""},
		{"vertical tab and form feed inside a value are dropped", "{\"code\":\"a\vb\fc\"}", ""},
		{"Hangul filler inside a value is dropped", "{\"code\":\"JaneㅤDoe\"}", ""},
		{"combining grapheme joiner inside a value is dropped", "{\"code\":\"a͏b\"}", ""},
		{"braille blank inside a value is dropped", "{\"code\":\"a⠀b\"}", ""},
		{"invalid UTF-8 value is dropped", "{\"code\":\"\xff\xfe\"}", ""},
		{"non-ASCII letters are kept", `{"code":"ÉCHEC"}`, "code=ÉCHEC"},
		// By design: an allowlist admits any short value without whitespace, even
		// one that is a name or a phone number.
		{"a short personal value under an allowlisted key is kept", `{"status":"Jane","code":"+14155550123"}`, "code=+14155550123 status=Jane"},
		{"nesting is irrelevant", `{"error":{"code":"E42","message":"bad input"}}`, "code=E42"},
		{"first occurrence of a key wins", `{"code":"FIRST","nested":{"code":"SECOND"}}`, "code=FIRST"},
		{"a non-string first occurrence is passed over", `{"code":404,"nested":{"code":"E1"}}`, "code=E1"},
		{"a value with an escape is passed over", `{"code":"a\"b","nested":{"code":"OK"}}`, "code=OK"},
		{"an invalid first value drops the key", `{"code":"has space","nested":{"code":"OK"}}`, ""},
		{"token-shaped value is still redacted", `{"requestId":"ghp_abc"}`, "requestId=[REDACTED]"},
		{"each value is redacted on its own", `{"code":"Bearer","requestId":"r1"}`, "code=Bearer requestId=r1"},
		{
			"every allowlisted key, output sorted by key",
			`{"status":"h","requestId":"g","error_code":"f","errorType":"e","code":"d","correlation_id":"b","correlationId":"a","category":"c"}`,
			"category=c code=d correlationId=a correlation_id=b errorType=e error_code=f requestId=g status=h",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := VendorErrorDetail([]byte(tt.body)); got != tt.want {
				t.Errorf("VendorErrorDetail(%.80q) = %q, want %q", tt.body, got, tt.want)
			}
		})
	}
}

func TestVendorErrorDetailNilBody(t *testing.T) {
	if got := VendorErrorDetail(nil); got != "" {
		t.Errorf("VendorErrorDetail(nil) = %q, want empty", got)
	}
}

// The package doc promises that all three functions are safe for concurrent
// use. Run under -race, this fails if any of them writes shared state.
func TestConcurrentUse(t *testing.T) {
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				if got, want := Redact("Bearer abc a@b.co /home/bob/x"), "[REDACTED] a***@b***.co ~/x"; got != want {
					t.Errorf("Redact = %q, want %q", got, want)
				}
				s, err := structpb.NewStruct(map[string]any{"password": "hunter2", "note": "ghp_abc"})
				if err != nil {
					t.Error(err)
					return
				}
				RedactStruct(s)
				if got := s.AsMap(); got["password"] != "h***" || got["note"] != "[REDACTED]" {
					t.Errorf("RedactStruct = %v", got)
				}
				if got, want := VendorErrorDetail([]byte(`{"code":"E1","requestId":"r1"}`)), "code=E1 requestId=r1"; got != want {
					t.Errorf("VendorErrorDetail = %q, want %q", got, want)
				}
			}
		}()
	}
	wg.Wait()
}
