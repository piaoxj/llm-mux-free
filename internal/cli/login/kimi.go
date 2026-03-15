package login

import (
	"github.com/piaoxj/llm-mux-free/internal/bootstrap"
	cmdpkg "github.com/piaoxj/llm-mux-free/internal/cmd"
	"github.com/spf13/cobra"
)

var kimiCmd = &cobra.Command{
	Use:   "kimi",
	Short: "Login to Kimi (Moonshot AI)",
	Long: `Login to Kimi using device-based authentication.

This command initiates the device flow authentication for Kimi services.
It will provide you with a URL and code to enter in your browser to authenticate.
Once authenticated, your credentials will be saved locally.

Use --no-browser flag to prevent automatic browser opening.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfgPath, _ := cmd.Flags().GetString("config")
		noBrowser, _ := cmd.Flags().GetBool("no-browser")

		result, err := bootstrap.Bootstrap(cfgPath)
		if err != nil {
			return err
		}

		options := &cmdpkg.LoginOptions{
			NoBrowser: noBrowser,
		}

		cmdpkg.DoKimiLogin(result.Config, options)
		return nil
	},
}

func init() {
	LoginCmd.AddCommand(kimiCmd)
}
