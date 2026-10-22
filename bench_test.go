// Copyright 2026 The logredact Authors
// SPDX-License-Identifier: MIT

package logredact_test

import (
	"testing"

	"github.com/tetriz-ai/logredact"
)

// A typical log line: one token, one address, one home directory, and ordinary
// text around them.
const benchLine = "sync failed for alice@example.com: GET /Users/alice/Library/cache.db " +
	"returned 401 with Authorization: Bearer abc.def.ghi after 3 retries in 1.2s"

var benchBody = []byte(`{"status":"error","message":"Contact 'Jane Doe <jane@example.com>' already exists",` +
	`"code":"DUPLICATE","requestId":"req-7f3a","correlationId":"9c1f-4d2a","category":"VALIDATION_ERROR"}`)

// A line with no token, address or home directory, and none of the literal
// token prefixes. It measures the cost when the pre-check skips every anchored
// pattern.
const benchPlainLine = "request completed: GET /api/v1/items?page=3 returned 200 in 12ms " +
	"for user 42 after 1 retry; cache hit ratio 0.93, queue depth 7, worker 3 of 8"

var sink string

func BenchmarkRedact(b *testing.B) {
	b.SetBytes(int64(len(benchLine)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sink = logredact.Redact(benchLine)
	}
}

func BenchmarkRedactNoCandidates(b *testing.B) {
	b.SetBytes(int64(len(benchPlainLine)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sink = logredact.Redact(benchPlainLine)
	}
}

func BenchmarkVendorErrorDetail(b *testing.B) {
	b.SetBytes(int64(len(benchBody)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sink = logredact.VendorErrorDetail(benchBody)
	}
}
