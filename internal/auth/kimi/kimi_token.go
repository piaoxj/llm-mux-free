package kimi

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	jsonutil "github.com/piaoxj/llm-mux-free/internal/json"
	"github.com/piaoxj/llm-mux-free/internal/misc"
)

// KimiTokenStorage represents the stored OAuth credentials.
type KimiTokenStorage struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    int64  `json:"expires_at"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
	LastRefresh  string `json:"last_refresh"`
	Email        string `json:"email"`
}

// NewKimiTokenStorage creates a new KimiTokenStorage from KimiTokenData.
func NewKimiTokenStorage(tokenData *KimiTokenData) *KimiTokenStorage {
	return &KimiTokenStorage{
		AccessToken:  tokenData.AccessToken,
		RefreshToken: tokenData.RefreshToken,
		ExpiresAt:    tokenData.ExpiresAt,
		Scope:        tokenData.Scope,
		TokenType:    tokenData.TokenType,
		LastRefresh:  time.Now().Format(time.RFC3339),
	}
}

// Update updates an existing token storage with new token data.
func (s *KimiTokenStorage) Update(tokenData *KimiTokenData) {
	s.AccessToken = tokenData.AccessToken
	s.RefreshToken = tokenData.RefreshToken
	s.ExpiresAt = tokenData.ExpiresAt
	s.Scope = tokenData.Scope
	s.TokenType = tokenData.TokenType
	s.LastRefresh = time.Now().Format(time.RFC3339)
}

// IsExpired checks if the token is expired or about to expire.
func (s *KimiTokenStorage) IsExpired(bufferSeconds int64) bool {
	return time.Now().Unix() >= s.ExpiresAt-int64(bufferSeconds)
}

// MarshalJSON implements custom JSON marshaling.
func (s *KimiTokenStorage) MarshalJSON() ([]byte, error) {
	type Alias KimiTokenStorage
	return jsonutil.Marshal(&struct {
		*Alias
	}{
		Alias: (*Alias)(s),
	})
}

// UnmarshalJSON implements custom JSON unmarshaling.
func (s *KimiTokenStorage) UnmarshalJSON(data []byte) error {
	type Alias KimiTokenStorage
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(s),
	}
	if err := jsonutil.Unmarshal(data, &aux); err != nil {
		return err
	}
	return nil
}

// SaveTokenToFile serializes the Kimi token storage to a JSON file.
func (ts *KimiTokenStorage) SaveTokenToFile(authFilePath string) error {
	misc.LogSavingCredentials(authFilePath)
	if err := os.MkdirAll(filepath.Dir(authFilePath), 0700); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	f, err := os.OpenFile(authFilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create token file: %w", err)
	}
	defer func() {
		_ = f.Close()
	}()

	if err = jsonutil.NewEncoder(f).Encode(ts); err != nil {
		return fmt.Errorf("failed to write token to file: %w", err)
	}
	return nil
}
