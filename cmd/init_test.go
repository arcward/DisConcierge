package cmd

import (
	"bytes"
	"fmt"
	"github.com/arcward/disconcierge/disconcierge"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"os"
	"path/filepath"
	"testing"
)

func TestInitCommand(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	os.Setenv("DC_DATABASE_TYPE", "sqlite")
	os.Setenv("DC_DATABASE", dbPath)
	t.Cleanup(
		func() {
			os.Unsetenv("DC_DATABASE_TYPE")
			os.Unsetenv("DC_DATABASE")
		},
	)

	// Mock user input
	oldStdin := os.Stdin
	t.Cleanup(
		func() {
			os.Stdin = oldStdin
		},
	)

	passwords := []string{"testpassword", "testpassword"}
	passwordIndex := 0

	mockPasswordReader := func() ([]byte, error) {
		if passwordIndex >= len(passwords) {
			return nil, fmt.Errorf("no more passwords")
		}
		password := passwords[passwordIndex]
		passwordIndex++
		return []byte(password), nil
	}

	t.Cleanup(
		func() {
			customPasswordReader = nil
		},
	)

	customPasswordReader = mockPasswordReader

	input := "testadmin\n"
	r, w, _ := os.Pipe()
	os.Stdin = r
	go func() {
		_, _ = w.Write([]byte(input))
		_ = w.Close()
	}()

	currentOut := rootCmd.OutOrStdout()
	currentErr := rootCmd.OutOrStderr()
	t.Cleanup(
		func() {
			rootCmd.SetOut(currentOut)
			rootCmd.SetErr(currentErr)
		},
	)
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)

	rootCmd.SetArgs([]string{"init"})
	err := rootCmd.Execute()
	require.NoError(t, err)

	_, err = os.Stat(dbPath)
	assert.NoError(t, err, "Database file should exist")

	// Verify the output
	output := out.String()
	t.Logf("output: %s", output)
	assert.Contains(t, output, "Admin credentials are not set. Let's set them up.")
	assert.Contains(t, output, "Enter admin username:")
	assert.Contains(t, output, "Enter admin password:")
	assert.Contains(t, output, "Confirm admin password:")
	assert.Contains(t, output, "Admin credentials set successfully")
	assert.Contains(t, output, "Initialization complete")

	// Verify the database contents
	db, err := gorm.Open(sqlite.Open(dbPath))
	require.NoError(t, err)

	t.Cleanup(
		func() {
			sqlDB, _ := db.DB()
			if sqlDB != nil {
				_ = sqlDB.Close()
			}
		},
	)

	var config disconcierge.RuntimeConfig
	err = db.First(&config).Error
	require.NoError(t, err)

	assert.Equal(t, "testadmin", config.AdminUsername)
	assert.NotEmpty(t, config.AdminPassword)
	assert.NotEqual(t, "testpassword", config.AdminPassword) // Password should be hashed

	mg := db.Migrator()

	assert.True(t, mg.HasTable(&disconcierge.OpenAICreateThread{}))
	assert.True(t, mg.HasTable(&disconcierge.OpenAICreateMessage{}))
	assert.True(t, mg.HasTable(&disconcierge.OpenAICreateRun{}))
	assert.True(t, mg.HasTable(&disconcierge.OpenAIRetrieveRun{}))
	assert.True(t, mg.HasTable(&disconcierge.OpenAIListMessages{}))
	assert.True(t, mg.HasTable(&disconcierge.OpenAIListRunSteps{}))
	assert.True(t, mg.HasTable(&disconcierge.User{}))
	assert.True(t, mg.HasTable(&disconcierge.ChatCommand{}))
	assert.True(t, mg.HasTable(&disconcierge.ClearCommand{}))
	assert.True(t, mg.HasTable(&disconcierge.UserFeedback{}))
	assert.True(t, mg.HasTable(&disconcierge.RuntimeConfig{}))
	assert.True(t, mg.HasTable(&disconcierge.InteractionLog{}))
	assert.True(t, mg.HasTable(&disconcierge.DiscordMessage{}))

	valid, err := disconcierge.VerifyPassword(config.AdminPassword, "testpassword")
	assert.NoError(t, err)
	assert.True(t, valid)
}
