package zcode

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

// Vault encrypts account sessions with a stable application secret. The caller
// must keep this secret across restarts and back it up separately from the DB.
// Changing it requires decrypt/re-encrypt migration or a new authorization.
type Vault struct{ aead cipher.AEAD }

func NewVault(secret string) (*Vault, error) {
	if len(secret) < 32 || strings.Trim(secret, "0") == "" {
		return nil, errors.New("zcode: a stable application secret is required")
	}
	key := sha256.Sum256([]byte("sub2api/zcode/session/v1\x00" + secret))
	block, err := aes.NewCipher(key[:])
	clear(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Vault{aead: aead}, nil
}

func sessionAAD(accountID int64) []byte {
	return []byte("sub2api/zcode/session/v1/account/" + strconv.FormatInt(accountID, 10))
}

func (v *Vault) Seal(accountID int64, session Session) (string, error) {
	if v == nil || v.aead == nil || accountID <= 0 {
		return "", errors.New("zcode: invalid session vault scope")
	}
	plain, err := json.Marshal(session)
	if err != nil {
		return "", errors.New("zcode: session serialization failed")
	}
	defer clear(plain)
	if len(plain) > 128*1024 {
		return "", errors.New("zcode: session exceeds storage limit")
	}
	nonce := make([]byte, v.aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", errors.New("zcode: session nonce failed")
	}
	packed := v.aead.Seal(nonce, nonce, plain, sessionAAD(accountID))
	return "zcode:v1:" + base64.RawStdEncoding.EncodeToString(packed), nil
}

func (v *Vault) Open(accountID int64, sealed string) (Session, error) {
	fail := errors.New("zcode: stored session cannot be decrypted")
	if v == nil || v.aead == nil || accountID <= 0 || len(sealed) > 256*1024 || !strings.HasPrefix(sealed, "zcode:v1:") {
		return Session{}, fail
	}
	packed, err := base64.RawStdEncoding.Strict().DecodeString(strings.TrimPrefix(sealed, "zcode:v1:"))
	if err != nil || len(packed) < v.aead.NonceSize()+v.aead.Overhead() {
		return Session{}, fail
	}
	plain, err := v.aead.Open(nil, packed[:v.aead.NonceSize()], packed[v.aead.NonceSize():], sessionAAD(accountID))
	if err != nil {
		return Session{}, fail
	}
	defer clear(plain)
	var session Session
	if json.Unmarshal(plain, &session) != nil {
		return Session{}, fail
	}
	return session, nil
}
