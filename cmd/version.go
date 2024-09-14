package cmd

import (
	"fmt"
	"github.com/arcward/disconcierge/disconcierge"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version of the application",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf(
			"version=%s commit=%s built: %s",
			disconcierge.Version,
			disconcierge.CommitSHA,
			disconcierge.BuildTime,
		)
	},
}

//nolint:gochecknoinits
func init() {
	rootCmd.AddCommand(versionCmd)
}
