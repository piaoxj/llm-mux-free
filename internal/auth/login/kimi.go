package login

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/piaoxj/llm-mux-free/internal/auth/kimi"
	"github.com/piaoxj/llm-mux-free/internal/browser"
	"github.com/piaoxj/llm-mux-free/internal/config"
	"github.com/piaoxj/llm-mux-free/internal/provider"
)

type KimiAuthenticator struct{}

func NewKimiAuthenticator() *KimiAuthenticator {
	return &KimiAuthenticator{}
}

func (a *KimiAuthenticator) Provider() string {
	return "kimi"
}

func (a *KimiAuthenticator) RefreshLead() *time.Duration {
	lead := 3 * time.Hour
	return &lead
}

func (a *KimiAuthenticator) Login(ctx context.Context, cfg *config.Config, opts *LoginOptions) (*provider.Auth, error) {
	if cfg == nil {
		return nil, fmt.Errorf("kimi auth: configuration is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if opts == nil {
		opts = &LoginOptions{}
	}

	authSvc := kimi.NewKimiAuth(cfg)

	deviceFlow, err := authSvc.InitiateDeviceFlow(ctx)
	if err != nil {
		return nil, fmt.Errorf("kimi device flow initiation failed: %w", err)
	}

	authURL := deviceFlow.VerificationURIComplete

	if !opts.NoBrowser {
		fmt.Println("Opening browser for Kimi authentication")
		if !browser.IsAvailable() {
			fmt.Println("No browser available; please open the URL manually")
			fmt.Printf("Visit the following URL to continue authentication:\n%s\n", authURL)
		} else if err := browser.OpenURL(authURL); err != nil {
			fmt.Printf("Failed to open browser automatically: %v\n", err)
			fmt.Printf("Visit the following URL to continue authentication:\n%s\n", authURL)
		}
	} else {
		fmt.Printf("Visit the following URL to continue authentication:\n%s\n", authURL)
	}

	fmt.Printf("Enter the following code: %s\n", deviceFlow.UserCode)
	fmt.Println("Waiting for Kimi authentication...")

	tokenData, err := authSvc.PollForToken(context.Background(), deviceFlow.DeviceCode)
	if err != nil {
		return nil, fmt.Errorf("kimi authentication failed: %w", err)
	}

	tokenStorage := kimi.NewKimiTokenStorage(tokenData)

	email := ""
	if opts.Metadata != nil {
		email = opts.Metadata["email"]
		if email == "" {
			email = opts.Metadata["alias"]
		}
	}

	email = strings.TrimSpace(email)
	if email == "" {
		email = "kimi-user"
	}

	tokenStorage.Email = email

	fileName := fmt.Sprintf("kimi-%s.json", tokenStorage.Email)
	metadata := map[string]any{
		"email": tokenStorage.Email,
	}

	fmt.Println("Kimi authentication successful")

	return &provider.Auth{
		ID:       fileName,
		Provider: a.Provider(),
		FileName: fileName,
		Storage:  tokenStorage,
		Metadata: metadata,
	}, nil
}
