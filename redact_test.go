// Copyright 2026 The logredact Authors
// SPDX-License-Identifier: MIT

package logredact

import "testing"

// redactCase is shared by every table of Redact cases, so that
// TestRedactPrecheckIsTransparent can run all of them.
type redactCase struct {
	name string
	in   string
	want string
}

var redactCases = []redactCase{
	{"PEM precedes bearer matching", "Bearer -----BEGIN PRIVATE KEY-----\nsynthetic fixture\n-----END PRIVATE KEY-----", "[REDACTED]"}, // synthetic PEM fixture. gitleaks:allow
	{"public key is not private", "-----BEGIN PUBLIC KEY-----\nsynthetic fixture\n-----END PUBLIC KEY-----", "-----BEGIN PUBLIC KEY-----\nsynthetic fixture\n-----END PUBLIC KEY-----"},
	{"incomplete private block remains", "-----BEGIN PRIVATE KEY-----\nsynthetic fixture", "-----BEGIN PRIVATE KEY-----\nsynthetic fixture"}, // synthetic PEM fixture. gitleaks:allow
	{"AIza", "AIzaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "[REDACTED]"},                                                                        // synthetic fixture. gitleaks:allow
	{"AIza inside word", "xAIzaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "xAIzaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},                             // synthetic fixture. gitleaks:allow
	{"sk_live_", "sk_live_example", "[REDACTED]"},                                                                     // synthetic fixture. gitleaks:allow
	{"sk_live_ inside word", "xsk_live_example", "xsk_live_example"},                                                  // synthetic fixture. gitleaks:allow
	{"sk_test_", "sk_test_example", "[REDACTED]"},                                                                     // synthetic fixture. gitleaks:allow
	{"sk_test_ inside word", "xsk_test_example", "xsk_test_example"},                                                  // synthetic fixture. gitleaks:allow
	{"rk_live_", "rk_live_example", "[REDACTED]"},                                                                     // synthetic fixture. gitleaks:allow
	{"rk_live_ inside word", "xrk_live_example", "xrk_live_example"},                                                  // synthetic fixture. gitleaks:allow
	{"rk_test_", "rk_test_example", "[REDACTED]"},                                                                     // synthetic fixture. gitleaks:allow
	{"rk_test_ inside word", "xrk_test_example", "xrk_test_example"},                                                  // synthetic fixture. gitleaks:allow
	{"whsec_", "whsec_example", "[REDACTED]"},                                                                         // synthetic fixture. gitleaks:allow
	{"whsec_ inside word", "xwhsec_example", "xwhsec_example"},                                                        // synthetic fixture. gitleaks:allow
	{"glpat-", "glpat-example", "[REDACTED]"},                                                                         // synthetic fixture. gitleaks:allow
	{"glpat- inside word", "xglpat-example", "xglpat-example"},                                                        // synthetic fixture. gitleaks:allow
	{"npm_", "npm_example", "[REDACTED]"},                                                                             // synthetic fixture. gitleaks:allow
	{"npm_ inside word", "xnpm_example", "xnpm_example"},                                                              // synthetic fixture. gitleaks:allow
	{"xoxr-", "xoxr-example", "[REDACTED]"},                                                                           // synthetic fixture. gitleaks:allow
	{"xoxr- inside word", "xxoxr-example", "xxoxr-example"},                                                           // synthetic fixture. gitleaks:allow
	{"xoxs-", "xoxs-example", "[REDACTED]"},                                                                           // synthetic fixture. gitleaks:allow
	{"xoxs- inside word", "xxoxs-example", "xxoxs-example"},                                                           // synthetic fixture. gitleaks:allow
	{"xoxe-", "xoxe-example", "[REDACTED]"},                                                                           // synthetic fixture. gitleaks:allow
	{"xoxe- inside word", "xxoxe-example", "xxoxe-example"},                                                           // synthetic fixture. gitleaks:allow
	{"xapp-", "xapp-example", "[REDACTED]"},                                                                           // synthetic fixture. gitleaks:allow
	{"xapp- inside word", "xxapp-example", "xxapp-example"},                                                           // synthetic fixture. gitleaks:allow
	{"SG.", "SG.example.example", "[REDACTED]"},                                                                       // synthetic fixture. gitleaks:allow
	{"SG. inside word", "xSG.example.example", "xSG.example.example"},                                                 // synthetic fixture. gitleaks:allow
	{"https://hooks.slack.com/services/", "https://hooks.slack.com/services/TEXAMPLE/BEXAMPLE/example", "[REDACTED]"}, // synthetic fixture. gitleaks:allow
	{"https://hooks.slack.com/services/ inside word", "xhttps://hooks.slack.com/services/TEXAMPLE/BEXAMPLE/example", "xhttps://hooks.slack.com/services/TEXAMPLE/BEXAMPLE/example"}, // synthetic fixture. gitleaks:allow
	{"PRIVATE KEY", "-----BEGIN PRIVATE KEY-----\nsynthetic fixture\n-----END PRIVATE KEY-----", "[REDACTED]"},                                                                      // synthetic PEM fixture. gitleaks:allow
	{"RSA PRIVATE KEY", "-----BEGIN RSA PRIVATE KEY-----\nsynthetic fixture\n-----END RSA PRIVATE KEY-----", "[REDACTED]"},                                                          // synthetic PEM fixture. gitleaks:allow
	{"EC PRIVATE KEY", "-----BEGIN EC PRIVATE KEY-----\nsynthetic fixture\n-----END EC PRIVATE KEY-----", "[REDACTED]"},                                                             // synthetic PEM fixture. gitleaks:allow
	{"DSA PRIVATE KEY", "-----BEGIN DSA PRIVATE KEY-----\nsynthetic fixture\n-----END DSA PRIVATE KEY-----", "[REDACTED]"},                                                          // synthetic PEM fixture. gitleaks:allow
	{"OPENSSH PRIVATE KEY", "-----BEGIN OPENSSH PRIVATE KEY-----\nsynthetic fixture\n-----END OPENSSH PRIVATE KEY-----", "[REDACTED]"},                                              // synthetic PEM fixture. gitleaks:allow
	{"ENCRYPTED PRIVATE KEY", "-----BEGIN ENCRYPTED PRIVATE KEY-----\nsynthetic fixture\n-----END ENCRYPTED PRIVATE KEY-----", "[REDACTED]"},                                        // synthetic PEM fixture. gitleaks:allow
	{"empty", "", ""},
	{"plain text", "hello world", "hello world"},
	{"bearer token", "auth: Bearer abc.def", "auth: [REDACTED]"},
	{"github personal", "token=ghp_xyz123abc", "token=[REDACTED]"}, // fake token, test fixture. gitleaks:allow
	{"github oauth", "gho_xxx", "[REDACTED]"},
	{"github server", "ghs_yyy", "[REDACTED]"},
	{"google access", "ya29.token-here", "[REDACTED]"},
	{"openai", "sk-secret-thing", "[REDACTED]"},
	{"slack bot", "xoxb-12345", "[REDACTED]"},
	{"slack user", "xoxp-67890", "[REDACTED]"},
	{"slack admin", "xoxa-abcdef", "[REDACTED]"},
	{"jwt", "eyJabc.eyJdef.signature123", "[REDACTED]"},
	{"aws access key id", "AKIAIOSFODNN7EXAMPLE", "[REDACTED]"},
	{"aws temporary key id", "ASIAY34FZKBOKMUTVV7A", "[REDACTED]"}, // fake AWS key, test fixture. gitleaks:allow
	{"aws sts service bearer token key id", "ABIAIOSFODNN7EXAMPLE", "[REDACTED]"},
	{"aws context-specific credential key id", "ACCAY34FZKBOKMUTVV7A", "[REDACTED]"}, // fake AWS key, test fixture. gitleaks:allow
	{"email", "user@example.com", "u***@e***.com"},
	{"path with username", "/Users/alice/Documents/file.txt", "~/Documents/file.txt"},
	{"linux home", "/home/bob/code/main.go", "~/code/main.go"},
	{"multiple patterns", "Bearer xyz and email a@b.co", "[REDACTED] and email a***@b***.co"},
}

func TestRedact(t *testing.T) {
	for _, tt := range redactCases {
		t.Run(tt.name, func(t *testing.T) {
			got := Redact(tt.in)
			if got != tt.want {
				t.Errorf("Redact(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestRedactStruct(t *testing.T) {
	runStructCases(t, []structCase{
		{
			name: "redacts secret in PII-named field",
			in:   map[string]any{"password": "supersecret"},
			want: map[string]any{"password": "s***"},
		},
		{
			name: "redacts email value under email key",
			in:   map[string]any{"email": "alice@example.com"},
			want: map[string]any{"email": "a***@e***.com"},
		},
		{
			name: "redacts bearer in non-PII field",
			in:   map[string]any{"msg": "got Bearer xyz123"},
			want: map[string]any{"msg": "got [REDACTED]"},
		},
		{
			name: "preserves number and bool leaves",
			in:   map[string]any{"count": 42.0, "ok": true, "msg": "ok"},
			want: map[string]any{"count": 42.0, "ok": true, "msg": "ok"},
		},
		{
			name: "recurses into nested object",
			in: map[string]any{
				"outer": map[string]any{
					"token": "abc123",
					"deep":  map[string]any{"api_key": "k-secret"},
				},
			},
			want: map[string]any{
				"outer": map[string]any{
					"token": "a***",
					"deep":  map[string]any{"api_key": "k***"},
				},
			},
		},
		{
			name: "redacts strings inside list",
			in:   map[string]any{"lines": []any{"Bearer token-x", "ok", "ghp_y"}},
			want: map[string]any{"lines": []any{"[REDACTED]", "ok", "[REDACTED]"}},
		},
	})
}

func TestAdditionalSecretKeys(t *testing.T) {
	for _, key := range []string{"passwd", "pwd", "api_token", "apiToken", "secret_key", "access_key", "aws_secret_access_key", "set-cookie", "private_key_id", "dsn", "connection_string", "otp", "pin"} {
		runStructCases(t, []structCase{{name: key, in: map[string]any{key: "sensitive"}, want: map[string]any{key: "s***"}}})
	}
}
