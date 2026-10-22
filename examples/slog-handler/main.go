// Command slog-handler masks every string attribute a log/slog logger writes.
package main

import (
	"log/slog"
	"os"

	"github.com/tetriz-ai/logredact"
)

func main() {
	redact := func(_ []string, a slog.Attr) slog.Attr {
		if a.Key == slog.TimeKey {
			return slog.Attr{} // dropped only so that the output below is stable
		}
		if a.Value.Kind() == slog.KindString {
			a.Value = slog.StringValue(logredact.Redact(a.Value.String()))
		}
		return a
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{ReplaceAttr: redact}))
	logger.Info("sync failed", "user", "alice@example.com", "auth", "Bearer abc.def")
	// level=INFO msg="sync failed" user=a***@e***.com auth=[REDACTED]
}
