package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"gorm.io/gorm"
	"log"
	"os"
	"strings"
	"syscall"

	"github.com/arcward/disconcierge/disconcierge"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// passwordReader is a function type for reading passwords. It's really only
// here to make testing easier.
type passwordReader func() ([]byte, error)

var customPasswordReader passwordReader

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize the database and set admin credentials",
	Run: func(cmd *cobra.Command, args []string) {
		ctx := cmd.Context()

		if cfg.DatabaseType == "" {
			log.Fatal("Environment variable DC_DATABASE_TYPE not set (must be one of: sqlite, postgres)")
		}
		if cfg.Database == "" {
			log.Fatal(
				"Environment variable DC_DATABASE not set (must be a valid " +
					"database connection string or sqlite file path)",
			)
		}
		// Run database migrations
		db, err := disconcierge.CreateDB(ctx, cfg.DatabaseType, cfg.Database)
		if err != nil {
			log.Fatalf("Error creating database: %v", err)
		}

		// Check if admin credentials are set

		var runtimeConfig disconcierge.RuntimeConfig
		rv := db.Last(&runtimeConfig)
		if rv.Error != nil {
			if errors.Is(rv.Error, gorm.ErrRecordNotFound) {
				runtimeConfig = disconcierge.DefaultRuntimeConfig()
				if err = db.Create(&runtimeConfig).Error; err != nil {
					log.Fatalf("Error creating runtime config: %v", err)
				}
			} else {
				log.Fatalf("Error retrieving runtime config: %s", rv.Error.Error())
			}
		}
		out := cmd.OutOrStdout()
		if runtimeConfig.AdminUsername == "" || runtimeConfig.AdminPassword == "" {
			fmt.Fprintln(out, "Admin credentials are not set. Let's set them up.")

			reader := bufio.NewReader(os.Stdin)

			// Prompt for username
			fmt.Fprint(out, "Enter admin username: ")
			username, _ := reader.ReadString('\n')
			username = strings.TrimSpace(username)

			// Prompt for password
			var password string

			if customPasswordReader == nil {
				customPasswordReader = func() ([]byte, error) {
					return term.ReadPassword(int(syscall.Stdin))
				}
			}
			for {
				fmt.Fprint(out, "Enter admin password: ")
				passwordBytes, _ := customPasswordReader()
				password = string(passwordBytes)
				fmt.Fprintln(out)

				fmt.Fprint(out, "Confirm admin password: ")
				confirmPasswordBytes, _ := customPasswordReader()
				confirmPassword := string(confirmPasswordBytes)
				fmt.Fprintln(out)

				if password == confirmPassword {
					break
				}
				fmt.Fprintln(out, "Passwords do not match. Please try again.")
			}

			hashedPassword, err := disconcierge.HashPassword(password)
			if err != nil {
				log.Fatalf("Error hashing password: %v", err)
			}

			if err := db.Model(&runtimeConfig).Updates(
				map[string]any{
					"admin_username": username,
					"admin_password": hashedPassword,
				},
			).Error; err != nil {
				log.Fatalf("Error updating admin credentials: %v", err)
			}

			fmt.Fprintln(out, "Admin credentials set successfully.")
		} else {
			fmt.Fprintln(out, "Admin credentials are already set.")
		}

		fmt.Fprintln(
			out,
			"Initialization complete. You can now start the server with the 'run' subcommand.",
		)
	},
}

func init() {
	rootCmd.AddCommand(initCmd)

}
