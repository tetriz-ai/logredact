// Copyright 2026 The logredact Authors
// SPDX-License-Identifier: MIT

package logredact_test

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/tetriz-ai/logredact"
	"google.golang.org/protobuf/types/known/structpb"
)

// Redact every string attribute a log/slog logger writes. The time attribute
// is dropped only to keep this example's output stable.
func Example_slog() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			if a.Value.Kind() == slog.KindString {
				a.Value = slog.StringValue(logredact.Redact(a.Value.String()))
			}
			return a
		},
	}))
	logger.Info("sync failed", "user", "alice@example.com", "auth", "Bearer abc.def")
	// Output: level=INFO msg="sync failed" user=a***@e***.com auth=[REDACTED]
}

func ExampleRedact() {
	fmt.Println(logredact.Redact("upload of /Users/alice/report.csv for alice@example.com failed: 401 with Bearer abc.def"))
	// Output: upload of ~/report.csv for a***@e***.com failed: 401 with [REDACTED]
}

func ExampleRedactStruct() {
	payload, err := structpb.NewStruct(map[string]any{
		"event":    "login failed for bob@example.com",
		"password": "hunter2",
		"user":     map[string]any{"email": "bob@example.com", "id": 42},
	})
	if err != nil {
		panic(err)
	}
	logredact.RedactStruct(payload)

	fields := payload.GetFields()
	fmt.Println(fields["event"].GetStringValue())
	fmt.Println(fields["password"].GetStringValue())
	fmt.Println(fields["user"].GetStructValue().GetFields()["email"].GetStringValue())
	// Output:
	// login failed for b***@e***.com
	// h***
	// b***@e***.com
}

func ExampleVendorErrorDetail() {
	body := []byte(`{
		"status": "error",
		"message": "Contact 'Jane Doe <jane@example.com>' already exists",
		"code": "DUPLICATE",
		"requestId": "req-7f3a"
	}`)
	fmt.Println(logredact.VendorErrorDetail(body))
	// Output: code=DUPLICATE requestId=req-7f3a status=error
}
