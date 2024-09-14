package cmd

import (
	"fmt"
	"github.com/arcward/disconcierge/disconcierge"
	"github.com/stretchr/testify/assert"
	"io"
	"os"
	"testing"
)

func TestVersionCommand(t *testing.T) {
	originalVersion := disconcierge.Version
	originalCommitSHA := disconcierge.CommitSHA
	originalBuildTime := disconcierge.BuildTime

	t.Cleanup(
		func() {
			disconcierge.Version = originalVersion
			disconcierge.CommitSHA = originalCommitSHA
			disconcierge.BuildTime = originalBuildTime
		},
	)

	disconcierge.Version = "1.0.0"
	disconcierge.CommitSHA = "abc123"
	disconcierge.BuildTime = "2023-10-01T12:00:00Z"

	orig := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	t.Cleanup(
		func() {
			os.Stdout = orig
		},
	)

	// Capture the output
	versionCmd.Run(nil, nil)

	_ = w.Close()

	out, _ := io.ReadAll(r)
	output := string(out)
	t.Logf("output: %s", string(out))
	expected := fmt.Sprintf(
		"version=%s commit=%s built: %s",
		disconcierge.Version,
		disconcierge.CommitSHA,
		disconcierge.BuildTime,
	)
	assert.Equal(t, expected, output)
}
