package cmd

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
	"github.com/takutakahashi/nfa/pkg/networkfilter"
)

var setupIptablesCmd = &cobra.Command{
	Use:   "setup-iptables",
	Short: "Generate or apply iptables rules for the transparent proxy (requires CAP_NET_ADMIN for --apply)",
	Long: `setup-iptables manages the iptables rules needed by nfa.

Use --apply to execute the rules directly against the running kernel.
Use --output to write iptables-restore compatible rules to a file (or "-" for stdout).
Both flags can be combined in a single invocation.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		apply, _ := cmd.Flags().GetBool("apply")
		output, _ := cmd.Flags().GetString("output")
		sidecarUID, err := sidecarUIDFromFlags(cmd)
		if err != nil {
			return err
		}

		if !apply && output == "" {
			return fmt.Errorf("specify at least one of --apply or --output")
		}

		if apply {
			log.Printf("[nfa] applying iptables rules (sidecar uid: %d)...", sidecarUID)
			if err := networkfilter.SetupIPTablesForUID(sidecarUID); err != nil {
				return fmt.Errorf("iptables setup failed: %w", err)
			}
			log.Println("[nfa] iptables rules applied successfully")
		}

		if output != "" {
			content := networkfilter.GenerateIPTablesRestoreForUID(sidecarUID)
			if output == "-" {
				fmt.Print(content)
				return nil
			}
			if err := os.WriteFile(output, []byte(content), 0o644); err != nil {
				return fmt.Errorf("writing restore file: %w", err)
			}
			log.Printf("[nfa] iptables-restore rules written to %s", output)
		}

		return nil
	},
}

func init() {
	setupIptablesCmd.Flags().Bool("apply", false, "Apply iptables rules directly (requires CAP_NET_ADMIN)")
	setupIptablesCmd.Flags().String("output", "", `Write iptables-restore compatible rules to this file path ("-" for stdout)`)
	setupIptablesCmd.Flags().String("sidecar-uid", "", "UID to exempt for the nfa sidecar. Defaults to current UID. Also via NETWORK_FILTER_SIDECAR_UID.")
}
