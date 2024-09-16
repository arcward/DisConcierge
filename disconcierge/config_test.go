package disconcierge

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"log/slog"
	"path/filepath"
	"testing"
	"time"
)

func TestValidateDefaultRuntimeConfig(t *testing.T) {
	cfg := DefaultRuntimeConfig()
	cfg.AssistantPollInterval = Duration{0}
	err := structValidator.Struct(cfg)
	require.Error(t, err)
}

func DefaultTestConfig(t testing.TB) *Config {
	tmpdir := t.TempDir()
	cfg := DefaultConfig()
	ids := newCommandData(t)

	cfg.DatabaseType = dbTypeSQLite
	cfg.Database = filepath.Join(tmpdir, fmt.Sprintf("%s.sqlite3", t.Name()))
	cfg.StartupTimeout = 5 * time.Second
	cfg.API.CORS.AllowOrigins = []string{"*"}
	cfg.Development = true
	cfg.ShutdownTimeout = 10 * time.Second
	cfg.OpenAI.Token = ids.OpenAIToken
	cfg.Discord.Token = ids.DiscordToken
	cfg.RuntimeConfigTTL = 0
	cfg.UserCacheTTL = 0

	cfg.Discord.ApplicationID = ids.DiscordApplicationID

	cfg.OpenAI.AssistantID = ids.AssistantID
	certfile := filepath.Join(tmpdir, "cert.pem")
	keyfile := filepath.Join(tmpdir, "key.pem")
	_, err := generateSelfSignedCert(certfile, keyfile)
	require.NoError(t, err)

	cfg.API.SSL = &SSLConfig{
		CertFile: certfile,
		KeyFile:  keyfile,
	}

	cfg.API.Secret = "aksdfjakjsfdajfefIJHShi sfEISHSIDF HSIHDF"
	cfg.Discord.WebhookServer.SSL = &SSLConfig{}
	cfg.Discord.WebhookServer.SSL.CertFile = certfile
	cfg.Discord.WebhookServer.SSL.KeyFile = keyfile

	logLevel := slog.LevelWarn
	cfg.LogLevel.Set(logLevel)
	cfg.Discord.LogLevel.Set(logLevel)
	cfg.Discord.DiscordGoLogLevel.Set(logLevel)
	cfg.DatabaseLogLevel.Set(logLevel)
	cfg.OpenAI.LogLevel.Set(logLevel)
	cfg.API.LogLevel.Set(logLevel)

	return cfg
}
