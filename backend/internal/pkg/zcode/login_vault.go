package zcode

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

func loginAAD(accountID, ownerID int64, flowID string) []byte {
	return []byte(fmt.Sprintf("sub2api/zcode/login/v1/%d/%d/%s", accountID, ownerID, flowID))
}

// Login records have a distinct authenticated purpose from account sessions;
// encrypted pending credentials can never be used as a completed account session.
func (v *Vault) SealLogin(accountID, ownerID int64, flowID string, payload []byte) (string, error) {
	if v == nil || v.aead == nil || accountID <= 0 || ownerID <= 0 || flowID == "" || len(payload) > 128*1024 {
		return "", errors.New("zcode: invalid login encryption scope")
	}
	nonce := make([]byte, v.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", errors.New("zcode: login encryption failed")
	}
	b := v.aead.Seal(nonce, nonce, payload, loginAAD(accountID, ownerID, flowID))
	return "zcode-login:v1:" + base64.RawStdEncoding.EncodeToString(b), nil
}

func (v *Vault) OpenLogin(accountID, ownerID int64, flowID, sealed string) ([]byte, error) {
	fail := errors.New("zcode: login session is unavailable")
	if v == nil || v.aead == nil || accountID <= 0 || ownerID <= 0 || flowID == "" || len(sealed) > 256*1024 || !strings.HasPrefix(sealed, "zcode-login:v1:") {
		return nil, fail
	}
	b, err := base64.RawStdEncoding.Strict().DecodeString(strings.TrimPrefix(sealed, "zcode-login:v1:"))
	if err != nil || len(b) < v.aead.NonceSize()+v.aead.Overhead() {
		return nil, fail
	}
	plain, err := v.aead.Open(nil, b[:v.aead.NonceSize()], b[v.aead.NonceSize():], loginAAD(accountID, ownerID, flowID))
	if err != nil {
		return nil, fail
	}
	return plain, nil
}
