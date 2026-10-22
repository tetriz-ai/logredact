package main

import (
	"fmt"

	"github.com/tetriz-ai/logredact"
)

func main() {
	fmt.Println(logredact.Redact("upload of /Users/alice/report.csv for alice@example.com failed: 401 with Bearer abc.def"))
	// upload of ~/report.csv for a***@e***.com failed: 401 with [REDACTED]
}
