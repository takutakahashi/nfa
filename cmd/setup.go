package cmd

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/takutakahashi/nfa/pkg/networkfilter"
)

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Configure iptables rules for transparent proxy redirect (requires CAP_NET_ADMIN)",
	RunE: func(cmd *cobra.Command, args []string) error {
		sidecarUID, err := sidecarUIDFromFlags(cmd)
		if err != nil {
			return err
		}
		log.Printf("[nfa] setting up iptables rules (sidecar uid: %d)...", sidecarUID)
		if err := networkfilter.SetupIPTablesForUID(sidecarUID); err != nil {
			return fmt.Errorf("iptables setup failed: %w", err)
		}
		log.Println("[nfa] iptables rules configured successfully")
		return nil
	},
}

func init() {
	setupCmd.Flags().String("sidecar-uid", "", "UID to exempt for the nfa sidecar. Defaults to current UID. Also via NETWORK_FILTER_SIDECAR_UID.")
}

func sidecarUIDFromFlags(cmd *cobra.Command) (int, error) {
	value, _ := cmd.Flags().GetString("sidecar-uid")
	if strings.TrimSpace(value) == "" {
		value = os.Getenv("NETWORK_FILTER_SIDECAR_UID")
	}
	if strings.TrimSpace(value) == "" {
		return networkfilter.CurrentUID(), nil
	}
	uid, err := networkfilter.ParseUID(value)
	if err != nil {
		return 0, err
	}
	return uid, nil
}
