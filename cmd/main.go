package main

import (
	"log"

	"github.com/spf13/cobra"

	"github.com/arashmh13/paqet-ngv2/cmd/dump"
	"github.com/arashmh13/paqet-ngv2/cmd/emergency"
	"github.com/arashmh13/paqet-ngv2/cmd/ping"
	"github.com/arashmh13/paqet-ngv2/cmd/run"
	"github.com/arashmh13/paqet-ngv2/cmd/secret"
	"github.com/arashmh13/paqet-ngv2/cmd/version"
)

var rootCmd = &cobra.Command{
	Use:   "paqet",
	Short: "KCP transport over raw TCP packet",
	Long:  `paqet is a bidirectional packet-level proxy using KCP and raw socket transport with encryption.`,
}

func main() {
	rootCmd.AddCommand(run.Cmd)
	rootCmd.AddCommand(dump.Cmd)
	rootCmd.AddCommand(ping.Cmd)
	rootCmd.AddCommand(secret.Cmd)
	rootCmd.AddCommand(version.Cmd)
	rootCmd.AddCommand(emergency.Cmd)

	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("%v", err)
	}
}
