package cmd

import (
	"github.com/arcward/disconcierge/disconcierge"
	"github.com/spf13/cobra"
	"log"
)

var (
	runCmd = &cobra.Command{
		Use:   "run [flags]",
		Short: "Starts the DisConcierge bot, API and (optionally) webhook server",
		Run: func(cmd *cobra.Command, _ []string) {
			ctx := cmd.Context()
			dai, err := disconcierge.New(cfg)
			if err != nil {
				log.Fatalf("error creating disconcierge: %s", err.Error())
			}

			if err = dai.Run(ctx); err != nil {
				log.Fatalf("error running disconcierge: %s", err.Error())
			}
		},
	}
)

//goland:noinspection GoLinter
func init() {
	rootCmd.AddCommand(runCmd)
}
