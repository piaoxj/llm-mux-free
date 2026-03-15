package kimi

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/piaoxj/llm-mux-free/internal/config"
	"github.com/piaoxj/llm-mux-free/internal/json"
	"github.com/piaoxj/llm-mux-free/internal/util"
)

const (
	// KimiOAuthDeviceCodeEndpoint is the URL for initiating the OAuth 2.0 device authorization flow.
	KimiOAuthDeviceCodeEndpoint = "https://auth.kimi.com/api/oauth/device_authorization"
	// KimiOAuthTokenEndpoint is the URL for exchanging device codes or refresh tokens for access tokens.
	KimiOAuthTokenEndpoint = "https://auth.kimi.com/api/oauth/token"
	// KimiOAuthClientID is the client identifier for the Kimi OAuth 2.0 application.
	KimiOAuthClientID = "17e5f671-d194-4dfb-9706-5516cb48c098"
)

// KimiTokenData represents the OAuth credentials, including access and refresh tokens.
type KimiTokenData struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresAt    int64  `json:"expires_at"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
}

// DeviceFlow represents the response from the device authorization endpoint.
type DeviceFlow struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI        string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn              int    `json:"expires_in"`
	Interval               int    `json:"interval"`
}

// KimiTokenResponse represents the successful token response from the token endpoint.
type KimiTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
}

// KimiAuth manages authentication and token handling for the Kimi API.
type KimiAuth struct {
	httpClient *http.Client
}

// NewKimiAuth creates a new KimiAuth instance with a proxy-configured HTTP client.
func NewKimiAuth(cfg *config.Config) *KimiAuth {
	return &KimiAuth{
		httpClient: util.SetProxy(&cfg.SDKConfig, &http.Client{}),
	}
}

// RefreshTokens exchanges a refresh token for a new access token.
func (a *KimiAuth) RefreshTokens(ctx context.Context, refreshToken string) (*KimiTokenData, error) {
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", KimiOAuthClientID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, KimiOAuthTokenEndpoint, strings.NewReader(url.Values(data).Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token refresh request failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errorData map[string]any
		if err := json.Unmarshal(body, &errorData); err == nil {
			return nil, fmt.Errorf("token refresh failed: %v - %v", errorData["error"], errorData["error_description"])
		}
		return nil, fmt.Errorf("token refresh failed: %s", string(body))
	}

	var tokenData KimiTokenResponse
	if err := json.Unmarshal(body, &tokenData); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	return &KimiTokenData{
		AccessToken:  tokenData.AccessToken,
		RefreshToken: tokenData.RefreshToken,
		ExpiresAt:    time.Now().Add(time.Duration(tokenData.ExpiresIn) * time.Second).Unix(),
		Scope:        tokenData.Scope,
		TokenType:    tokenData.TokenType,
	}, nil
}

// InitiateDeviceFlow starts the OAuth 2.0 device authorization flow and returns the device flow details.
func (a *KimiAuth) InitiateDeviceFlow(ctx context.Context) (*DeviceFlow, error) {
	data := url.Values{}
	data.Set("client_id", KimiOAuthClientID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, KimiOAuthDeviceCodeEndpoint, strings.NewReader(url.Values(data).Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create device authorization request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("device authorization request failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("device authorization failed: %d %s. Response: %s", resp.StatusCode, resp.Status, string(body))
	}

	var result DeviceFlow
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse device flow response: %w", err)
	}

	if result.DeviceCode == "" {
		return nil, fmt.Errorf("device authorization failed: device_code not found in response")
	}

	return &result, nil
}

// PollForToken polls the token endpoint with the device code to obtain an access token.
func (a *KimiAuth) PollForToken(ctx context.Context, deviceCode string) (*KimiTokenData, error) {
	pollInterval := 2 * time.Second
	maxAttempts := 150 // 5 minutes max

	for attempt := 0; attempt < maxAttempts; attempt++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		data := url.Values{}
		data.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
		data.Set("client_id", KimiOAuthClientID)
		data.Set("device_code", deviceCode)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, KimiOAuthTokenEndpoint, strings.NewReader(url.Values(data).Encode()))
		if err != nil {
			return nil, fmt.Errorf("failed to create token request: %w", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := a.httpClient.Do(req)
		if err != nil {
			fmt.Printf("Polling attempt %d/%d failed: %v\n", attempt+1, maxAttempts, err)
			time.Sleep(pollInterval)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			fmt.Printf("Polling attempt %d/%d failed: %v\n", attempt+1, maxAttempts, err)
			time.Sleep(pollInterval)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			var errorData map[string]any
			if err := json.Unmarshal(body, &errorData); err == nil {
				if resp.StatusCode == http.StatusBadRequest {
					errorType, _ := errorData["error"].(string)
					switch errorType {
					case "authorization_pending":
						fmt.Printf("Polling attempt %d/%d...\n\n", attempt+1, maxAttempts)
						time.Sleep(pollInterval)
						continue
					case "slow_down":
						pollInterval = time.Duration(float64(pollInterval) * 1.5)
						if pollInterval > 10*time.Second {
							pollInterval = 10 * time.Second
						}
						fmt.Printf("Server requested to slow down, increasing poll interval to %v\n\n", pollInterval)
						time.Sleep(pollInterval)
						continue
					case "expired_token":
						return nil, fmt.Errorf("device code expired. Please restart the authentication process")
					case "access_denied":
						return nil, fmt.Errorf("authorization denied by user. Please restart the authentication process")
					}
				}

				errorType, _ := errorData["error"].(string)
				errorDesc, _ := errorData["error_description"].(string)
				return nil, fmt.Errorf("device token poll failed: %s - %s", errorType, errorDesc)
			}

			return nil, fmt.Errorf("device token poll failed: %d %s. Response: %s", resp.StatusCode, resp.Status, string(body))
		}

		var response KimiTokenResponse
		if err := json.Unmarshal(body, &response); err != nil {
			return nil, fmt.Errorf("failed to parse token response: %w", err)
		}

		tokenData := &KimiTokenData{
			AccessToken:  response.AccessToken,
			RefreshToken: response.RefreshToken,
			ExpiresAt:    time.Now().Add(time.Duration(response.ExpiresIn) * time.Second).Unix(),
			Scope:        response.Scope,
			TokenType:    response.TokenType,
		}

		return tokenData, nil
	}

	return nil, fmt.Errorf("authentication timeout. Please restart the authentication process")
}

// RefreshTokensWithRetry attempts to refresh tokens with a specified number of retries upon failure.
func (a *KimiAuth) RefreshTokensWithRetry(ctx context.Context, refreshToken string, maxRetries int) (*KimiTokenData, error) {
	return util.WithRetry(ctx, maxRetries, "Token refresh", func(ctx context.Context) (*KimiTokenData, error) {
		return a.RefreshTokens(ctx, refreshToken)
	})
}

// GenerateRandomBytes generates cryptographically random bytes.
func GenerateRandomBytes(n int) ([]byte, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return nil, err
	}
	return bytes, nil
}

// GenerateDeviceID generates a unique device ID.
func GenerateDeviceID() (string, error) {
	bytes, err := GenerateRandomBytes(16)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}
