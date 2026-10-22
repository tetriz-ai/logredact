// Command api-error-message turns a failed response from a third-party API
// into an error that is safe to log, with logredact.VendorErrorDetail.
package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"

	"github.com/tetriz-ai/logredact"
)

// checkResponse turns a failed API response into an error that is safe to log.
func checkResponse(resp *http.Response) error {
	if resp.StatusCode < 400 {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return fmt.Errorf("HTTP %d, body unreadable: %w", resp.StatusCode, err)
	}
	return fmt.Errorf("HTTP %d %s", resp.StatusCode, logredact.VendorErrorDetail(body))
}

func main() {
	// A stand-in for a third-party API that rejects a duplicate contact.
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"status":"error","message":"Contact 'Jane Doe <jane@example.com>' already exists","code":"DUPLICATE","requestId":"req-7f3a"}`, http.StatusConflict)
	}))
	defer api.Close()

	resp, err := http.Get(api.URL)
	if err != nil {
		panic(err)
	}
	// The body has been read by then, so an error from Close changes nothing.
	defer func() { _ = resp.Body.Close() }()
	fmt.Println(checkResponse(resp))
	// HTTP 409 code=DUPLICATE requestId=req-7f3a status=error
}
