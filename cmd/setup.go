package cmd

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"
	"github.com/takutakahashi/nfa/pkg/networkfilter"
)

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Configure iptables rules for transparent proxy redirect (requires CAP_NET_ADMIN)",
	RunE: func(cmd *cobra.Command, args []string) error {
		log.Println("[nfa] setting up iptables rules...")
		if err := networkfilter.SetupIPTables(); err != nil {
			return fmt.Errorf("iptables setup failed: %w", err)
		}
		log.Println("[nfa] iptables rules configured successfully")
		return nil
	},
}
