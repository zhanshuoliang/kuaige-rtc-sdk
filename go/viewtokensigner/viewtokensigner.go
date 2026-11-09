// Package viewtokensigner signs short-lived RTC viewer tokens on a trusted
// vendor server. It is not an authorization service: the caller must first
// authenticate the user, check device binding/sharing, and select the vendor's
// license. Never use an application secret in a browser or mobile application.
package viewtokensigner

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"time"
)

const Audience = "kuaige-rtc-view"

var (
	appKeyPattern  = regexp.MustCompile(`^app_[A-Za-z0-9_-]{24,64}$`)
	licensePattern = regexp.MustCompile(`^lic_[A-Za-z0-9_-]{24,64}$`)
	devicePattern  = regexp.MustCompile(`^[A-Z0-9_-]{4,64}$`)
	userPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:@+-]{0,79}$`)
	sessionPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,96}$`)
)

// Request contains no application secret and is safe to construct on the
// server after authorization. Subject must be a stable, opaque user ID, not
// a phone number. SessionID is required for renew and empty for play.
type Request struct {
	AppKey     string
	LicenseID  string
	DeviceSN   string
	Subject    string
	Purpose    string
	SessionID  string
	TTLSeconds int
}

type claims struct {
	Issuer    string `json:"iss"`
	Audience  string `json:"aud"`
	Subject   string `json:"sub"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	TokenID   string `json:"jti"`
	LicenseID string `json:"license_id"`
	DeviceSN  string `json:"device_sn"`
	Purpose   string `json:"purpose"`
	SessionID string `json:"session_id,omitempty"`
}

// Issue signs a new single-use play or renewal token. TTLSeconds defaults to
// 300 and may be 60–900; the RTC server can impose a shorter session limit.
// A play request needs at least 60 seconds remaining on arrival, so use a TTL
// comfortably above 60 seconds. Sign the raw AppSecret string as provided by
// the RTC console; do not base64-decode it. The returned JWT is signed but not
// encrypted, so it must not contain a phone number or other private data.
func Issue(appSecret string, request Request) (token string, expiresAt time.Time, err error) {
	ttl := request.TTLSeconds
	if ttl == 0 {
		ttl = 300
	}
	if appSecret == "" || !appKeyPattern.MatchString(request.AppKey) || !licensePattern.MatchString(request.LicenseID) ||
		!devicePattern.MatchString(request.DeviceSN) || !userPattern.MatchString(request.Subject) || ttl < 60 || ttl > 900 ||
		(request.Purpose != "play" && request.Purpose != "renew") ||
		(request.Purpose == "play" && request.SessionID != "") ||
		(request.Purpose == "renew" && !sessionPattern.MatchString(request.SessionID)) {
		return "", time.Time{}, errors.New("invalid RTC token parameters")
	}
	random := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return "", time.Time{}, errors.New("RTC token randomness unavailable")
	}
	issuedAt := time.Now().UTC().Truncate(time.Second)
	expiresAt = issuedAt.Add(time.Duration(ttl) * time.Second)
	payload, err := json.Marshal(claims{
		Issuer: request.AppKey, Audience: Audience, Subject: request.Subject,
		IssuedAt: issuedAt.Unix(), ExpiresAt: expiresAt.Unix(), TokenID: base64.RawURLEncoding.EncodeToString(random),
		LicenseID: request.LicenseID, DeviceSN: request.DeviceSN, Purpose: request.Purpose, SessionID: request.SessionID,
	})
	if err != nil {
		return "", time.Time{}, errors.New("RTC token encoding failed")
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	message := header + "." + base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, []byte(appSecret))
	_, _ = mac.Write([]byte(message))
	return message + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), expiresAt, nil
}
