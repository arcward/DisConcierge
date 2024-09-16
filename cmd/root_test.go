package cmd

import (
	"fmt"
	"github.com/arcward/disconcierge/disconcierge"
	"github.com/bwmarrin/discordgo"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadConfigFromEnvFile(t *testing.T) {
	// Save the original environment
	originalEnv := os.Environ()
	t.Cleanup(
		func() {
			os.Clearenv()
			for _, envVar := range originalEnv {
				parts := strings.SplitN(envVar, "=", 2)
				os.Setenv(parts[0], parts[1])
			}
		},
	)

	// Clear the environment before the test
	os.Clearenv()

	tmpdir := t.TempDir()

	// Set up the test environment file
	envFile := filepath.Join(tmpdir, "test.env")

	envContent := `
# General/database config

DC_DATABASE=/home/foo/disconcierge.sqlite3
DC_DATABASE_TYPE=sqlite
DC_DATABASE_LOG_LEVEL=INFO
DC_DATABASE_SLOW_THRESHOLD=200ms
DC_LOG_LEVEL=INFO
DC_STARTUP_TIMEOUT=30s
DC_SHUTDOWN_TIMEOUT=60s
DC_DEVELOPMENT=true

# In-memory ChatCommand queue config

DC_QUEUE_SIZE=100
DC_QUEUE_MAX_AGE=3m
DC_QUEUE_SLEEP_EMPTY=1s
DC_QUEUE_SLEEP_PAUSED=5s

# OpenAI config

DC_OPENAI_TOKEN=your-assistant-token
DC_OPENAI_LOG_LEVEL=INFO
DC_OPENAI_ASSISTANT_ID=asst_foo

# Discord bot config

DC_DISCORD_TOKEN=your-discord-bot-token
DC_DISCORD_APPLICATION_ID=your-discord-bot-app-id
DC_DISCORD_GUILD_ID=
DC_DISCORD_LOG_LEVEL=WARN
DC_DISCORD_DISCORDGO_LOG_LEVEL=WARN
DC_DISCORD_STARTUP_MESSAGE="I'm here!"
DC_DISCORD_GATEWAY_INTENTS=3243773

# Discord webhook server

DC_DISCORD_WEBHOOK_SERVER_ENABLED=false
DC_DISCORD_WEBHOOK_SERVER_LISTEN=127.0.0.1:5001
DC_DISCORD_WEBHOOK_SERVER_SSL_CERT_FILE=/etc/ssl/cert.pem
DC_DISCORD_WEBHOOK_SERVER_SSL_KEY_FILE=/etc/ssl/cert.key
DC_DISCORD_WEBHOOK_SERVER_SSL_TLS_MIN_VERSION=771
DC_DISCORD_WEBHOOK_SERVER_LOG_LEVEL=INFO
DC_DISCORD_WEBHOOK_SERVER_PUBLIC_KEY=your_discord_public_key_here
DC_DISCORD_WEBHOOK_SERVER_READ_TIMEOUT=5s
DC_DISCORD_WEBHOOK_SERVER_READ_HEADER_TIMEOUT=5s
DC_DISCORD_WEBHOOK_SERVER_WRITE_TIMEOUT=10s
DC_DISCORD_WEBHOOK_SERVER_IDLE_TIMEOUT=30s

# API server

DC_API_EXTERNAL_URL=https://127.0.0.1:5000
DC_API_LISTEN=127.0.0.1:5000
DC_API_SSL_CERT_FILE=/etc/ssl/cert.pem
DC_API_SSL_KEY_FILE=/etc/ssl/key.pem
DC_API_SSL_TLS_MIN_VERSION=771
DC_API_SECRET=your-api-secret
DC_API_LOG_LEVEL=DEBUG
DC_API_CORS_ALLOW_ORIGINS=https://127.0.0.1:5000 https://localhost:5000
DC_API_CORS_ALLOW_METHODS=GET POST PUT PATCH DELETE OPTIONS HEAD
DC_API_CORS_ALLOW_HEADERS=Origin Content-Length Content-Type Accept Authorization X-Requested-With Cache-Control X-CSRF-Token X-Request-ID
DC_API_CORS_EXPOSE_HEADERS=Content-Type Content-Length Accept-Encoding X-Request-ID Location ETag Authorization Last-Modified
DC_API_CORS_ALLOW_CREDENTIALS=true
DC_API_CORS_MAX_AGE=12h
DC_API_READ_TIMEOUT=5s
DC_API_READ_HEADER_TIMEOUT=5s
DC_API_WRITE_TIMEOUT=10s
DC_API_IDLE_TIMEOUT=30s
DC_API_SESSION_MAX_AGE=6h
`

	err := os.WriteFile(envFile, []byte(envContent), 0644)
	assert.NoError(t, err)

	rootCmd.SetArgs([]string{fmt.Sprintf("--config=%s", envFile), "version"})
	require.NoError(t, rootCmd.Execute())

	assert.Equal(t, "/home/foo/disconcierge.sqlite3", cfg.Database)
	assert.Equal(t, "/home/foo/disconcierge.sqlite3", viper.GetString("database"))
	assert.Equal(t, "sqlite", viper.GetString("database_type"))

	assertLogLevel(t, slog.LevelInfo, viper.Get("database_log_level"))

	assert.Equal(t, 200*time.Millisecond, viper.GetDuration("database_slow_threshold"))
	assertLogLevel(t, slog.LevelInfo, viper.Get("log_level"))
	assert.Equal(t, 30*time.Second, viper.GetDuration("startup_timeout"))
	assert.Equal(t, 60*time.Second, viper.GetDuration("shutdown_timeout"))
	assert.True(t, viper.GetBool("development"))

	assert.Equal(t, 100, viper.GetInt("queue.size"))
	assert.Equal(t, 3*time.Minute, viper.GetDuration("queue.max_age"))
	assert.Equal(t, 1*time.Second, viper.GetDuration("queue.sleep_empty"))
	assert.Equal(t, 5*time.Second, viper.GetDuration("queue.sleep_paused"))

	assert.Equal(t, "your-assistant-token", viper.GetString("openai.token"))

	assertLogLevel(t, slog.LevelInfo, viper.Get("openai.log_level"))

	assert.Equal(t, "asst_foo", viper.GetString("openai.assistant_id"))

	assert.Equal(t, "your-discord-bot-token", viper.GetString("discord.token"))
	assert.Equal(t, "your-discord-bot-app-id", viper.GetString("discord.application_id"))
	assert.Equal(t, "", viper.GetString("discord.guild_id"))

	assertLogLevel(t, slog.LevelWarn, viper.Get("discord.log_level"))

	assertLogLevel(t, slog.LevelWarn, viper.Get("discord.discordgo_log_level"))
	assert.Equal(t, "I'm here!", viper.GetString("discord.startup_message"))
	assert.Equal(t, 3243773, viper.GetInt("discord.gateway_intents"))

	assert.False(t, viper.GetBool("discord.webhook_server.enabled"))
	assert.Equal(t, "127.0.0.1:5001", viper.GetString("discord.webhook_server.listen"))
	assert.Equal(t, "/etc/ssl/cert.pem", viper.GetString("discord.webhook_server.ssl.cert_file"))
	assert.Equal(t, "/etc/ssl/cert.key", viper.GetString("discord.webhook_server.ssl.key_file"))
	assert.Equal(t, 771, viper.GetInt("discord.webhook_server.ssl.tls_min_version"))
	assertLogLevel(t, slog.LevelInfo, viper.Get("discord.webhook_server.log_level"))

	assert.Equal(
		t,
		"your_discord_public_key_here",
		viper.GetString("discord.webhook_server.public_key"),
	)
	assert.Equal(t, 5*time.Second, viper.GetDuration("discord.webhook_server.read_timeout"))
	assert.Equal(t, 5*time.Second, viper.GetDuration("discord.webhook_server.read_header_timeout"))
	assert.Equal(t, 10*time.Second, viper.GetDuration("discord.webhook_server.write_timeout"))
	assert.Equal(t, 30*time.Second, viper.GetDuration("discord.webhook_server.idle_timeout"))

	assert.Equal(t, "127.0.0.1:5000", viper.GetString("api.listen"))
	assert.Equal(t, "https://127.0.0.1:5000", viper.GetString("api.external_url"))
	assert.Equal(t, "/etc/ssl/cert.pem", viper.GetString("api.ssl.cert_file"))
	assert.Equal(t, "/etc/ssl/key.pem", viper.GetString("api.ssl.key_file"))
	assert.Equal(t, 771, viper.GetInt("api.ssl.tls_min_version"))
	assert.Equal(t, "your-api-secret", viper.GetString("api.secret"))
	assertLogLevel(t, slog.LevelDebug, viper.Get("api.log_level"))
	assert.Equal(t, slog.LevelDebug, cfg.API.LogLevel.Level())
	assert.Equal(
		t,
		[]string{"https://127.0.0.1:5000", "https://localhost:5000"},
		viper.GetStringSlice("api.cors.allow_origins"),
	)
	assert.Equal(
		t,
		[]string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"},
		viper.GetStringSlice("api.cors.allow_methods"),
	)
	assert.Equal(
		t,
		[]string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"},
		cfg.API.CORS.AllowMethods,
	)
	assert.Equal(
		t,
		[]string{
			"Origin",
			"Content-Length",
			"Content-Type",
			"Accept",
			"Authorization",
			"X-Requested-With",
			"Cache-Control",
			"X-CSRF-Token",
			"X-Request-ID",
		},
		viper.GetStringSlice("api.cors.allow_headers"),
	)
	assert.Equal(
		t,
		[]string{
			"Content-Type",
			"Content-Length",
			"Accept-Encoding",
			"X-Request-ID",
			"Location",
			"ETag",
			"Authorization",
			"Last-Modified",
		},
		viper.GetStringSlice("api.cors.expose_headers"),
	)
	assert.True(t, viper.GetBool("api.cors.allow_credentials"))
	assert.Equal(t, 12*time.Hour, viper.GetDuration("api.cors.max_age"))
	assert.Equal(t, 5*time.Second, viper.GetDuration("api.read_timeout"))
	assert.Equal(t, 5*time.Second, viper.GetDuration("api.read_header_timeout"))
	assert.Equal(t, 10*time.Second, viper.GetDuration("api.write_timeout"))
	assert.Equal(t, 30*time.Second, viper.GetDuration("api.idle_timeout"))
	assert.Equal(t, 6*time.Hour, viper.GetDuration("api.session_max_age"))

	// Unmarshal the configuration into a disconcierge.Config struct
	var config disconcierge.Config
	err = viper.Unmarshal(
		&config, viper.DecodeHook(
			mapstructure.ComposeDecodeHookFunc(
				mapstructure.StringToTimeDurationHookFunc(),
				LevelToStringHookFunc(),
			),
		),
	)
	assert.NoError(t, err)

	// Verify some key fields in the Config struct
	assert.Equal(t, "/home/foo/disconcierge.sqlite3", config.Database)
	assert.Equal(t, "sqlite", config.DatabaseType)
	assert.Equal(t, slog.LevelInfo, config.DatabaseLogLevel.Level())
	assert.Equal(t, 200*time.Millisecond, config.DatabaseSlowThreshold)
	assert.Equal(t, slog.LevelInfo, config.LogLevel.Level())
	assert.Equal(t, 30*time.Second, config.StartupTimeout)
	assert.Equal(t, 60*time.Second, config.ShutdownTimeout)
	assert.True(t, config.Development)

	assert.Equal(t, 100, config.Queue.Size)
	assert.Equal(t, 3*time.Minute, config.Queue.MaxAge)
	assert.Equal(t, time.Second, config.Queue.SleepEmpty)
	assert.Equal(t, 5*time.Second, config.Queue.SleepPaused)

	assert.Equal(t, "your-assistant-token", config.OpenAI.Token)
	assert.Equal(t, slog.LevelInfo, config.OpenAI.LogLevel.Level())
	assert.Equal(t, "asst_foo", config.OpenAI.AssistantID)

	assert.Equal(t, "your-discord-bot-token", config.Discord.Token)
	assert.Equal(t, "your-discord-bot-app-id", config.Discord.ApplicationID)
	assert.Equal(t, "", config.Discord.GuildID)
	assert.Equal(t, slog.LevelWarn, config.Discord.LogLevel.Level())
	assert.Equal(t, slog.LevelWarn, config.Discord.DiscordGoLogLevel.Level())
	assert.Equal(t, "I'm here!", config.Discord.StartupMessage)
	assert.Equal(t, discordgo.Intent(3243773), config.Discord.GatewayIntents)

	assert.False(t, config.Discord.WebhookServer.Enabled)
	assert.Equal(t, "127.0.0.1:5001", config.Discord.WebhookServer.Listen)

	assert.Equal(t, "/etc/ssl/cert.pem", config.Discord.WebhookServer.SSL.CertFile)
	assert.Equal(t, "/etc/ssl/cert.key", config.Discord.WebhookServer.SSL.KeyFile)
	assert.Equal(t, uint16(771), config.Discord.WebhookServer.SSL.TLSMinVersion)
	assert.Equal(t, slog.LevelInfo, config.Discord.WebhookServer.LogLevel.Level())
	assert.Equal(t, "your_discord_public_key_here", config.Discord.WebhookServer.PublicKey)
	assert.Equal(t, 5*time.Second, config.Discord.WebhookServer.ReadTimeout)
	assert.Equal(t, 5*time.Second, config.Discord.WebhookServer.ReadHeaderTimeout)
	assert.Equal(t, 10*time.Second, config.Discord.WebhookServer.WriteTimeout)
	assert.Equal(t, 30*time.Second, config.Discord.WebhookServer.IdleTimeout)

	assert.Equal(t, "127.0.0.1:5000", config.API.Listen)
	assert.Equal(t, "https://127.0.0.1:5000", config.API.ExternalURL)
	assert.Equal(t, "/etc/ssl/cert.pem", config.API.SSL.CertFile)
	assert.Equal(t, "/etc/ssl/key.pem", config.API.SSL.KeyFile)
	assert.Equal(t, uint16(771), config.API.SSL.TLSMinVersion)
	assert.Equal(t, "your-api-secret", config.API.Secret)
	assert.Equal(t, slog.LevelDebug, config.API.LogLevel.Level())
	assert.Equal(
		t,
		[]string{"https://127.0.0.1:5000", "https://localhost:5000"},
		config.API.CORS.AllowOrigins,
	)
	assert.Equal(
		t,
		[]string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"},
		config.API.CORS.AllowMethods,
	)
	assert.Equal(
		t,
		[]string{
			"Origin",
			"Content-Length",
			"Content-Type",
			"Accept",
			"Authorization",
			"X-Requested-With",
			"Cache-Control",
			"X-CSRF-Token",
			"X-Request-ID",
		},
		config.API.CORS.AllowHeaders,
	)
}
