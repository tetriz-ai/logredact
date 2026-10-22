// Copyright 2026 The logredact Authors
// SPDX-License-Identifier: MIT

package logredact_test

import (
	"strings"
	"testing"

	"github.com/tetriz-ai/logredact"
)

// The cases that matter are the rejections. An allowlist is only worth having if
// it drops the echoed submission a vendor sends back on a validation failure.
// Redact alone passes names and companies through.
func TestVendorErrorDetailAdmitsOnlyMachineIdentifiers(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		wantHas   []string
		wantLacks []string
	}{
		{
			name: "a CRM validation failure keeps the ids and drops the echoed properties",
			body: `{"status":"error","message":"Property values were not valid: name 'jane@example.com' is invalid",
			        "correlationId":"9c1f-4d2a","category":"VALIDATION_ERROR"}`,
			wantHas:   []string{"correlationId=9c1f-4d2a", "category=VALIDATION_ERROR"},
			wantLacks: []string{"jane@example.com", "name", "Property values"},
		},
		{
			name: "a contact API rejection drops every echoed contact field",
			body: `{"error":"duplicate contact","code":"DUPLICATE","first_name":"Jane","last_name":"Doe",
			        "role":"Staff Engineer","company":"Example Corp","website":"https://example.com",
			        "email":"jane@example.com"}`,
			wantHas:   []string{"code=DUPLICATE"},
			wantLacks: []string{"Jane", "Doe", "Staff Engineer", "Example Corp", "example.com", "jane@example.com"},
		},
		{
			name:      "prose wearing an allowlisted key is dropped, because an admitted value has no spaces",
			body:      `{"category":"the contact Jane Doe at Example Corp already exists"}`,
			wantLacks: []string{"Jane", "Doe", "Example Corp"},
		},
		{
			name:      "a non-JSON body yields nothing rather than passing itself through",
			body:      `<html><body>jane@example.com is not a valid contact</body></html>`,
			wantLacks: []string{"jane", "example", "html"},
		},
		{
			name:      "an empty body yields nothing",
			body:      `{}`,
			wantLacks: []string{"="},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := logredact.VendorErrorDetail([]byte(tt.body))
			for _, want := range tt.wantHas {
				if !strings.Contains(got, want) {
					t.Errorf("detail = %q, want it to carry %q", got, want)
				}
			}
			for _, leak := range tt.wantLacks {
				if strings.Contains(got, leak) {
					t.Errorf("detail = %q, must not carry %q", got, leak)
				}
			}
		})
	}
}

// The allowlist matches on key names inside an untrusted body, so it is a matcher
// and owes both failure directions. These are the attacks that would defeat it.
func TestVendorErrorDetailResistsAKeyInjectedIntoProse(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			// Inside a JSON string the decoy key's closing quote is escaped
			// (code\"), so the pattern's literal "code" followed by a quote never
			// matches. The key match fails before the value class is consulted.
			name: "an allowlisted key escaped inside a message value does not match",
			body: `{"message":"invalid \"code\":\"jane@example.com\" supplied"}`,
			want: "",
		},
		{
			name: "a real key still wins alongside a decoy in prose",
			body: `{"message":"see code:\"x\"","code":"REAL"}`,
			want: "code=REAL",
		},
		{
			// A longer key is not matched by a shorter one it contains: the pattern
			// anchors on the opening quote.
			name: "code does not match error_code's value",
			body: `{"error_code":"E1"}`,
			want: "error_code=E1",
		},
		{
			// Second layer: even if an email reached an allowlisted key, Redact masks
			// it. Neither layer is relied on alone.
			name: "an email-shaped value in an allowlisted key is still masked",
			body: `{"code":"jane@example.com"}`,
			want: "code=j***@e***.com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := logredact.VendorErrorDetail([]byte(tt.body)); got != tt.want {
				t.Errorf("detail = %q, want %q", got, tt.want)
			}
		})
	}
}
