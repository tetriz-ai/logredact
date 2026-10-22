// Command custom-rules masks a secret format logredact does not know, by
// running a rule of your own before logredact.Redact.
package main

import (
	"fmt"
	"regexp"

	"github.com/tetriz-ai/logredact"
)

// yourKeys matches key=value secrets that your own logs use. logredact leaves
// them alone because they have no fixed prefix.
var yourKeys = regexp.MustCompile(`(?i)\b(password|client_secret)=\S+`)

// redact runs your rule first and then logredact's rules on what is left.
func redact(s string) string {
	return logredact.Redact(yourKeys.ReplaceAllString(s, "$1=[REDACTED]"))
}

func main() {
	line := "login alice@example.com password=hunter2 client_secret=s3cr3t"
	fmt.Println(logredact.Redact(line))
	fmt.Println(redact(line))
	// login a***@e***.com password=hunter2 client_secret=s3cr3t
	// login a***@e***.com password=[REDACTED] client_secret=[REDACTED]
}
