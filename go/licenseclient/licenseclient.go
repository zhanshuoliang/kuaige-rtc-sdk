// Package licenseclient synchronizes one RTC application's issued license pool.
// It does not assign licenses to devices or authorize viewers.
package licenseclient

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const queryPath = "/rtc/v1/applications/licenses/query"
const queryURL = "https://live.kuaige.cloud" + queryPath

var (
	appKeyPattern  = regexp.MustCompile(`^app_[A-Za-z0-9_-]{24,64}$`)
	licensePattern = regexp.MustCompile(`^lic_[A-Za-z0-9_-]{24,64}$`)
)

// HTTPError exposes the status code without exposing response bodies or signed headers.
type HTTPError struct{ StatusCode int }

func (e *HTTPError) Error() string {
	return fmt.Sprintf("RTC license query returned HTTP %d", e.StatusCode)
}

type License struct {
	LicenseID string     `json:"license_id"`
	Active    bool       `json:"active"`
	ExpiresAt *time.Time `json:"expires_at"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

type Page struct {
	Licenses   []License `json:"licenses"`
	NextCursor *int64    `json:"next_cursor"`
}

// QueryPage must be called only from a trusted business server. appSecret is
// the original AppSecret string; neither it nor the signed headers are logged.
// Follow NextCursor until nil; begin a fresh scan with cursor 0 to pick up
// changes to older licenses. A returned license is not an allocation to an SN.
func QueryPage(ctx context.Context, client *http.Client, appKey, appSecret string, cursor int64, limit int) (Page, error) {
	var result Page
	if !appKeyPattern.MatchString(appKey) || appSecret == "" || cursor < 0 || limit < 1 || limit > 100 {
		return result, errors.New("invalid license query parameters")
	}
	body, err := json.Marshal(struct {
		Cursor int64 `json:"cursor"`
		Limit  int   `json:"limit"`
	}{Cursor: cursor, Limit: limit})
	if err != nil {
		return result, err
	}
	random := make([]byte, 24)
	if _, err = io.ReadFull(rand.Reader, random); err != nil {
		return result, err
	}
	nonce := base64.RawURLEncoding.EncodeToString(random)
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	digest := sha256.Sum256(body)
	canonical := strings.Join([]string{"RTC-APP-V1", appKey, timestamp, nonce, "POST", queryPath, hex.EncodeToString(digest[:])}, "\n")
	mac := hmac.New(sha256.New, []byte(appSecret))
	_, _ = mac.Write([]byte(canonical))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, queryURL, bytes.NewReader(body))
	if err != nil {
		return result, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-RTC-App-Key", appKey)
	req.Header.Set("X-RTC-Timestamp", timestamp)
	req.Header.Set("X-RTC-Nonce", nonce)
	req.Header.Set("X-RTC-Signature", hex.EncodeToString(mac.Sum(nil)))
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	// Do not forward the signed request to a redirect destination.
	safeClient := *client
	safeClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := safeClient.Do(req)
	if err != nil {
		return result, errors.New("RTC license query unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return result, &HTTPError{StatusCode: resp.StatusCode}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024+1))
	if err != nil || len(data) > 256*1024 {
		return result, errors.New("invalid RTC license response")
	}
	var wire struct {
		Licenses   json.RawMessage `json:"licenses"`
		NextCursor json.RawMessage `json:"next_cursor"`
	}
	if err := json.Unmarshal(data, &wire); err != nil || len(wire.Licenses) == 0 || string(wire.Licenses) == "null" || len(wire.NextCursor) == 0 {
		return Page{}, errors.New("invalid RTC license response")
	}
	var fields []map[string]json.RawMessage
	if json.Unmarshal(wire.Licenses, &fields) != nil || fields == nil || len(fields) > limit ||
		json.Unmarshal(wire.Licenses, &result.Licenses) != nil || len(result.Licenses) != len(fields) {
		return Page{}, errors.New("invalid RTC license response")
	}
	for i, item := range result.Licenses {
		f := fields[i]
		if !licensePattern.MatchString(item.LicenseID) ||
			(string(f["active"]) != "true" && string(f["active"]) != "false") ||
			len(f["expires_at"]) == 0 || len(f["created_at"]) == 0 || len(f["updated_at"]) == 0 ||
			item.CreatedAt.IsZero() || item.UpdatedAt.IsZero() {
			return Page{}, errors.New("invalid RTC license response")
		}
	}
	if err := json.Unmarshal(wire.NextCursor, &result.NextCursor); err != nil || (result.NextCursor != nil && *result.NextCursor <= cursor) {
		return Page{}, errors.New("invalid RTC license response")
	}
	return result, nil
}
