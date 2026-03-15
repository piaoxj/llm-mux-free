package cmd

import (
	"context"
	"errors"
	"fmt"

	"github.com/piaoxj/llm-mux-free/internal/auth/login"
	"github.com/piaoxj/llm-mux-free/internal/config"
	log "github.com/piaoxj/llm-mux-free/internal/logging"
)

// DoKimiLogin handles the Kimi device flow using the shared authentication manager.
// It initiates the device-based authentication process for Kimi services and saves
// the authentication tokens to the configured auth directory.
func DoKimiLogin(cfg *config.Config, options *LoginOptions) {
	if options == nil {
		options = &LoginOptions{}
	}

	manager := newAuthManager()

	promptFn := options.Prompt
	if promptFn == nil {
		promptFn = func(prompt string) (string, error) {
			fmt.Println()
			fmt.Println(prompt)
			var value string
			_, err := fmt.Scanln(&value)
			return value, err
		}
	}

	authOpts := &login.LoginOptions{
		NoBrowser: options.NoBrowser,
		Metadata:  map[string]string{},
		Prompt:    promptFn,
	}

	_, err := manager.Login(context.Background(), "kimi", cfg, authOpts)
	if err != nil {
		var emailErr *login.EmailRequiredError
		if errors.As(err, &emailErr) {
			log.Error(emailErr.Error())
			return
		}
		fmt.Printf("Kimi authentication failed: %v\n", err)
		return
	}

	fmt.Println("Kimi authentication successful!")
}
