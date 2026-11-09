package licenseclient

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestQueryPageSignsAndPagesApplicationInventory(t *testing.T) {
	app := "app_" + strings.Repeat("a", 32)
	secret := "synthetic-private-secret"
	previousNonce := ""
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(r.Body)
		if r.URL.String() != queryURL || r.Method != http.MethodPost || string(body) != `{"cursor":0,"limit":2}` ||
			r.Header.Get("X-RTC-App-Key") != app {
			t.Error("unexpected license query")
		}
		nonce := r.Header.Get("X-RTC-Nonce")
		if nonce == "" || nonce == previousNonce {
			t.Error("nonce was missing or reused")
		}
		previousNonce = nonce
		digest := sha256.Sum256(body)
		canonical := strings.Join([]string{"RTC-APP-V1", app, r.Header.Get("X-RTC-Timestamp"), nonce,
			"POST", queryPath, hex.EncodeToString(digest[:])}, "\n")
		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = mac.Write([]byte(canonical))
		if !hmac.Equal([]byte(r.Header.Get("X-RTC-Signature")), []byte(hex.EncodeToString(mac.Sum(nil)))) {
			t.Error("query signature did not match the documented contract")
		}
		response := `{"licenses":[{"license_id":"lic_` + strings.Repeat("b", 32) + `","active":true,` +
			`"expires_at":null,"created_at":"2026-11-09T00:00:00Z","updated_at":"2026-11-09T00:00:00Z"}],"next_cursor":null}`
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(response)), Header: make(http.Header)}, nil
	})}
	for i := 0; i < 2; i++ {
		page, err := QueryPage(context.Background(), client, app, secret, 0, 2)
		if err != nil || len(page.Licenses) != 1 || page.Licenses[0].ExpiresAt != nil || page.NextCursor != nil {
			t.Fatal("valid test page was not decoded")
		}
	}
}

func TestQueryPageDoesNotExposeErrorResponse(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusUnauthorized,
			Body: io.NopCloser(strings.NewReader("synthetic-sensitive-response")), Header: make(http.Header)}, nil
	})}
	_, err := QueryPage(context.Background(), client, "app_"+strings.Repeat("a", 32), "synthetic-secret", 0, 2)
	if err == nil || !strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "synthetic-sensitive-response") {
		t.Fatal("unexpected error handling")
	}
	var status *HTTPError
	if !errors.As(err, &status) || status.StatusCode != 401 {
		t.Fatal("missing HTTP status")
	}
}

func TestQueryPageRejectsIncompleteOrInvalidPages(t *testing.T) {
	license := "lic_" + strings.Repeat("b", 32)
	item := `{"license_id":"` + license + `","active":true,"expires_at":null,"created_at":"2026-11-09T00:00:00Z","updated_at":"2026-11-09T00:00:00Z"}`
	cases := []string{
		`{}`, `{"licenses":null,"next_cursor":null}`, `{"licenses":[]}`,
		`{"licenses":[` + strings.Replace(item, `"active":true`, `"active":null`, 1) + `],"next_cursor":null}`,
		`{"licenses":[` + strings.Replace(item, license, "bad", 1) + `],"next_cursor":null}`,
		`{"licenses":[` + strings.Replace(item, `"expires_at":null,`, "", 1) + `],"next_cursor":null}`,
		`{"licenses":[` + strings.Replace(item, `2026-11-09T00:00:00Z`, `bad-date`, 1) + `],"next_cursor":null}`,
		`{"licenses":[],"next_cursor":0}`, strings.Repeat("x", 256*1024+1),
	}
	for _, body := range cases {
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		})}
		if _, err := QueryPage(context.Background(), client, "app_"+strings.Repeat("a", 32), "synthetic-secret", 0, 2); err == nil {
			t.Fatal("malformed response accepted")
		}
	}
}

func TestQueryPageDoesNotFollowRedirect(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		headers := make(http.Header)
		headers.Set("Location", "https://example.invalid/collect")
		return &http.Response{StatusCode: 302, Body: io.NopCloser(strings.NewReader("")), Header: headers}, nil
	})}
	_, err := QueryPage(context.Background(), client, "app_"+strings.Repeat("a", 32), "synthetic-secret", 0, 2)
	var status *HTTPError
	if calls != 1 || !errors.As(err, &status) || status.StatusCode != 302 {
		t.Fatal("redirect was followed or not rejected")
	}
}
