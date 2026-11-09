package viewtokensigner

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestIssuePlayAndRenewTokens(t *testing.T) {
	secret := "synthetic-private-secret"
	req := Request{AppKey: "app_" + strings.Repeat("a", 32), LicenseID: "lic_" + strings.Repeat("b", 32),
		DeviceSN: "KRTSYNTHETIC1", Subject: "user-1", Purpose: "play"}
	play, expiry, err := Issue(secret, req)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(play, ".")
	if len(parts) != 3 {
		t.Fatal("invalid JWT structure")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
	if !hmac.Equal([]byte(parts[2]), []byte(base64.RawURLEncoding.EncodeToString(mac.Sum(nil)))) {
		t.Fatal("invalid JWT signature")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(parts[1])
	var claims struct {
		Issuer    string `json:"iss"`
		LicenseID string `json:"license_id"`
		Purpose   string `json:"purpose"`
		ExpiresAt int64  `json:"exp"`
	}
	if err != nil || json.Unmarshal(decoded, &claims) != nil || claims.Issuer != req.AppKey ||
		claims.LicenseID != req.LicenseID || claims.Purpose != "play" || claims.ExpiresAt != expiry.Unix() {
		t.Fatal("invalid play token claims")
	}
	second, _, err := Issue(secret, req)
	if err != nil || second == play {
		t.Fatal("play token must use a new random identifier")
	}
	req.Purpose = "renew"
	if _, _, err = Issue(secret, req); err == nil {
		t.Fatal("renewal without a session was accepted")
	}
	req.SessionID = strings.Repeat("s", 24)
	if _, _, err = Issue(secret, req); err != nil {
		t.Fatal("valid renewal was rejected")
	}
}
