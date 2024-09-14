package cmd

import (
	"fmt"
	"github.com/arcward/disconcierge/disconcierge"
	"github.com/bwmarrin/discordgo"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"
)

func setEnvVars(t testing.TB, vars map[string]string) {
	t.Helper()
	origVars := map[string]string{}

	for k, v := range vars {
		origVars[k] = os.Getenv(k)
		if err := os.Setenv(k, v); err != nil {
			t.Fatalf("error setting env var %s: %v", k, err)
		}
	}
	t.Cleanup(
		func() {
			for k, v := range origVars {
				if v == "" {
					_ = os.Unsetenv(k)
				} else {
					_ = os.Setenv(k, v)
				}
			}
		},
	)
}
func TestUnmarshalConfig(t *testing.T) {
	envPrefix := os.Getenv(disconcierge.EnvvarSetEnvPrefix)
	if envPrefix == "" {
		envPrefix = disconcierge.DefaultEnvPrefix
	}

	envVars := map[string]string{
		fmt.Sprintf("%s_DATABASE", envPrefix):      "test.sqlite3",
		fmt.Sprintf("%s_DATABASE_TYPE", envPrefix): "postgres",
		fmt.Sprintf("%s_LOG_LEVEL", envPrefix):     "INFO",

		fmt.Sprintf("%s_OPENAI_LOG_LEVEL", envPrefix): "DEBUG",

		fmt.Sprintf("%s_DATABASE_LOG_LEVEL", envPrefix):          "INFO",
		fmt.Sprintf("%s_DISCORD_DISCORDGO_LOG_LEVEL", envPrefix): "INFO",
		fmt.Sprintf("%s_STARTUP_TIMEOUT", envPrefix):             "30s",
		fmt.Sprintf("%s_SHUTDOWN_TIMEOUT", envPrefix):            "60s",
		fmt.Sprintf("%s_QUEUE_SIZE", envPrefix):                  "200",
		fmt.Sprintf("%s_QUEUE_MAX_AGE", envPrefix):               "5m",
		fmt.Sprintf("%s_QUEUE_SLEEP_PAUSED", envPrefix):          "10s",
		fmt.Sprintf("%s_QUEUE_SLEEP_EMPTY", envPrefix):           "15s",

		fmt.Sprintf(
			"%s_OPENAI_TOKEN",
			envPrefix,
		): "test-token",
		fmt.Sprintf(
			"%s_OPENAI_ASSISTANT_ID",
			envPrefix,
		): "assistant-id",

		fmt.Sprintf("%s_DISCORD_TOKEN", envPrefix): "discord-token",

		fmt.Sprintf("%s_DISCORD_LOG_LEVEL", envPrefix): "INFO",

		fmt.Sprintf(
			"%s_API_LISTEN",
			envPrefix,
		): "0.0.0.0:8080",
		fmt.Sprintf("%s_API_LISTEN_NETWORK", envPrefix): "tcp4",
		fmt.Sprintf(
			"%s_API_SSL_CERT",
			envPrefix,
		): "cert-path",
		fmt.Sprintf(
			"%s_API_SSL_KEY",
			envPrefix,
		): "key-path",

		fmt.Sprintf(
			"%s_DISCORD_GUILD_ID",
			envPrefix,
		): "guild-id",

		fmt.Sprintf(
			"%s_API_CORS_ALLOW_HEADERS",
			envPrefix,
		): "Content-Type Accept",
		fmt.Sprintf("%s_API_CORS_ALLOW_METHODS", envPrefix): "GET POST",
		fmt.Sprintf("%s_API_CORS_MAX_AGE", envPrefix):       "6h",
		fmt.Sprintf("%s_API_CORS_ALLOW_ORIGINS", envPrefix): "*",
		fmt.Sprintf(
			"%s_API_CORS_EXPOSE_HEADERS",
			envPrefix,
		): "Content-Type Authorization",

		fmt.Sprintf("%s_OPENAI_VECTOR_STORE_ID", envPrefix):   "vs-foo",
		fmt.Sprintf("%s_API_SECRET", envPrefix):               "somesecret",
		fmt.Sprintf("%s_API_MAX_MULTIPART_MEMORY", envPrefix): "256",

		fmt.Sprintf("%s_API_READ_TIMEOUT", envPrefix): "30s",

		fmt.Sprintf("%s_API_WRITE_TIMEOUT", envPrefix): "31s",

		fmt.Sprintf("%s_API_READ_HEADER_TIMEOUT", envPrefix): "32s",

		fmt.Sprintf("%s_API_IDLE_TIMEOUT", envPrefix): "33s",

		fmt.Sprintf("%s_API_SESSION_MAX_AGE", envPrefix): "1h",

		fmt.Sprintf("%s_API_DEVELOPMENT", envPrefix): "true",

		fmt.Sprintf("%s_API_BROADCAST_ENABLED", envPrefix): "true",

		fmt.Sprintf("%s_API_BROADCAST_TOKEN_EXPIRY", envPrefix): "9m",

		fmt.Sprintf("%s_API_BROADCAST_MAX_SUBSCRIBERS", envPrefix): "111",
	}

	setEnvVars(t, envVars)

	// Initialize the configuration
	initConfig()

	// Verify the configuration values
	assert.Equal(t, "test.sqlite3", viper.GetString("database"))
	assert.Equal(t, "postgres", viper.GetString("database_type"))
	assert.Equal(t, "30s", viper.GetString("startup_timeout"))
	assert.Equal(t, "60s", viper.GetString("shutdown_timeout"))
	assert.Equal(t, 200, viper.GetInt("queue.size"))
	assert.Equal(t, "5m", viper.GetString("queue.max_age"))
	assert.Equal(t, "test-token", viper.GetString("openai.token"))
	assert.Equal(t, "assistant-id", viper.GetString("openai.assistant.id"))
	assert.Equal(t, "vs-foo", viper.GetString("openai.vector_store_id"))
	assert.Equal(t, "discord-token", viper.GetString("discord.token"))
	assert.Equal(t, "somesecret", viper.GetString("api.secret"))
	assert.ElementsMatch(
		t,
		[]string{"GET", "POST"},
		viper.GetStringSlice("api.cors.allow_methods"),
	)
	assert.ElementsMatch(
		t,
		[]string{"Content-Type", "Accept"},
		viper.GetStringSlice("api.cors.allow_headers"),
	)
	assert.ElementsMatch(
		t,
		[]string{"*"},
		viper.GetStringSlice("api.cors.allow_origins"),
	)
	assert.ElementsMatch(
		t,
		[]string{"Content-Type", "Authorization"}, // do not do this for reals
		viper.GetStringSlice("api.cors.expose_headers"),
	)

	assert.Equal(t, 6*time.Hour, viper.GetDuration("api.cors.max_age"))

	assert.Equal(t, "guild-id", viper.GetString("discord.guild_id"))
	assert.Equal(t, "0.0.0.0:8080", viper.GetString("api.listen"))
	assert.Equal(t, "tcp4", viper.GetString("api.listen_network"))
	assert.Equal(t, "cert-path", viper.GetString("api.ssl.cert"))
	assert.Equal(t, "key-path", viper.GetString("api.ssl.key"))
	assert.Equal(t, "10s", viper.GetString("queue.sleep_paused"))
	assert.Equal(t, "15s", viper.GetString("queue.sleep_empty"))

	assert.Equal(t, 30*time.Second, viper.GetDuration("api.read_timeout"))

	assert.Equal(t, 31*time.Second, viper.GetDuration("api.write_timeout"))
	assert.True(t, viper.GetBool("api.development"))
	assert.Equal(
		t,
		32*time.Second,
		viper.GetDuration("api.read_header_timeout"),
	)

	assert.Equal(t, 33*time.Second, viper.GetDuration("api.idle_timeout"))

	assert.Equal(t, time.Hour, viper.GetDuration("api.session_max_age"))
	assert.Equal(t, int64(256), viper.GetInt64("api.max_multipart_memory"))

	assert.True(t, viper.GetBool("api.broadcast.enabled"))
	assert.Equal(
		t,
		9*time.Minute,
		viper.GetDuration("api.broadcast.token_expiry"),
	)
	assert.Equal(t, 111, viper.GetInt("api.broadcast.max_subscribers"))

	var botCfg disconcierge.Config

	err := viper.Unmarshal(
		&botCfg,
		viper.DecodeHook(
			mapstructure.ComposeDecodeHookFunc(
				mapstructure.StringToTimeDurationHookFunc(),
				LevelToStringHookFunc(),
			),
		),
	)
	assert.NoError(t, err)

	startupTimeout, err := time.ParseDuration("30s")
	assert.NoError(t, err)

	shutdownTimeout, err := time.ParseDuration("60s")
	assert.NoError(t, err)

	maxRequestAge, err := time.ParseDuration("5m")
	assert.NoError(t, err)

	assert.Equal(t, "test.sqlite3", botCfg.Database)
	assert.Equal(t, "postgres", botCfg.DatabaseType)
	assert.Equal(t, "INFO", botCfg.LogLevel.Level().String())
	assert.Equal(t, startupTimeout, botCfg.StartupTimeout)
	assert.Equal(t, shutdownTimeout, botCfg.ShutdownTimeout)
	assert.Equal(t, 200, botCfg.Queue.Size)
	assert.Equal(t, maxRequestAge, botCfg.Queue.MaxAge)
	assert.Equal(t, "test-token", botCfg.OpenAI.Token)
	assert.Equal(t, "assistant-id", botCfg.OpenAI.AssistantID)

	assert.Equal(t, "discord-token", botCfg.Discord.Token)

	assert.Equal(t, "guild-id", botCfg.Discord.GuildID)
	assert.Equal(t, "INFO", botCfg.Discord.LogLevel.Level().String())

	assert.Equal(t, "0.0.0.0:8080", botCfg.API.Listen)
	assert.Equal(t, "tcp4", botCfg.API.ListenNetwork)
	assert.Equal(t, "cert-path", botCfg.API.SSL.Cert)
	assert.Equal(t, "key-path", botCfg.API.SSL.Key)

	assert.Equal(t, 10*time.Second, botCfg.Queue.SleepPaused)
	assert.Equal(t, 15*time.Second, botCfg.Queue.SleepEmpty)
	assert.Equal(t, slog.LevelDebug, botCfg.OpenAI.LogLevel.Level())
	assert.Equal(t, slog.LevelInfo, botCfg.Discord.DiscordGoLogLevel.Level())
	assert.Equal(t, slog.LevelInfo, botCfg.DatabaseLogLevel.Level())
	assert.Equal(t, slog.LevelInfo, botCfg.LogLevel.Level())
	assert.Equal(t, "somesecret", botCfg.API.Secret)

	assert.ElementsMatch(
		t,
		[]string{"GET", "POST"},
		botCfg.API.CORS.AllowMethods,
	)
	assert.ElementsMatch(
		t,
		[]string{"Accept", "Content-Type"},
		botCfg.API.CORS.AllowHeaders,
	)
	assert.Equal(t, 6*time.Hour, botCfg.API.CORS.MaxAge)
	assert.ElementsMatch(t, []string{"*"}, botCfg.API.CORS.AllowOrigins)
	assert.ElementsMatch(
		t,
		[]string{"Content-Type", "Authorization"}, // do not do this for reals
		botCfg.API.CORS.ExposeHeaders,
	)

	assert.Equal(t, 30*time.Second, botCfg.API.ReadTimeout)

	assert.Equal(t, 31*time.Second, botCfg.API.WriteTimeout)

	assert.Equal(t, 32*time.Second, botCfg.API.ReadHeaderTimeout)

	assert.Equal(t, 33*time.Second, botCfg.API.IdleTimeout)

	assert.Equal(t, time.Hour, botCfg.API.SessionMaxAge)

	assert.True(t, botCfg.API.Development)

}

func TestConfigUnmarshal(t *testing.T) {
	yamlConfig := `
database: disconcierge.sqlite
database_type: sqlite
database_log_level: INFO
database_slow_threshold: 200ms
log_level: INFO
startup_timeout: 30s
shutdown_timeout: 60s
queue:
  size: 100
  max_age: 3m
  sleep_empty: 1s
  sleep_paused: 5s
openai:
  token: your_openai_token_here
  log_level: INFO
  assistant_id: your_assistant_id_here
  vector_store_id: your_vector_store_id_here
discord:
  token: your_discord_token_here
  application_id: your_discord_application_id_here
  guild_id: your_discord_guild_id_here
  log_level: WARN
  discordgo_log_level: WARN
  startup_message: "I'm here!"
  gateway_intents: 3276799
  webhook_server:
    enabled: false
    listen: 127.0.0.1:5001
    listen_network: tcp
    ssl:
      cert: ""
      key: ""
      tls_min_version: 771
    log_level: INFO
    public_key: your_discord_public_key_here
    read_timeout: 5s
    read_header_timeout: 5s
    write_timeout: 10s
    idle_timeout: 30s
api:
  enabled: true
  listen: 127.0.0.1:5000
  listen_network: tcp
  ssl:
    cert: ""
    key: ""
    tls_min_version: 771
  secret: your_api_secret_here
  log_level: INFO
  cors:
    allow_origins: []
    allow_methods:
      - GET
      - POST
      - PUT
      - PATCH
      - DELETE
      - OPTIONS
      - HEAD
    allow_headers:
      - Origin
      - Content-Length
      - Content-Type
      - Accept
      - Authorization
      - X-Requested-With
      - Cache-Control
      - X-CSRF-Token
      - X-Request-ID
    expose_headers:
      - Content-Type
      - Content-Length
      - Accept-Encoding
      - X-Request-ID
      - Location
      - ETag
      - Authorization
      - Last-Modified
    allow_credentials: true
    max_age: 12h
  max_multipart_memory: 33554432
  read_timeout: 5s
  read_header_timeout: 5s
  write_timeout: 10s
  idle_timeout: 30s
  session_max_age: 6h
  development: false
`

	v := viper.New()
	v.SetConfigType("yaml")
	err := v.ReadConfig(strings.NewReader(yamlConfig))
	assert.NoError(t, err)

	var config disconcierge.Config
	err = v.Unmarshal(
		&config, viper.DecodeHook(
			mapstructure.ComposeDecodeHookFunc(
				mapstructure.StringToTimeDurationHookFunc(),
				LevelToStringHookFunc(),
			),
		),
	)
	assert.NoError(t, err)

	// Now let's validate the unmarshalled config
	assert.Equal(t, "disconcierge.sqlite", config.Database)
	assert.Equal(t, "sqlite", config.DatabaseType)
	assert.Equal(t, slog.LevelInfo, config.DatabaseLogLevel.Level())
	assert.Equal(t, 200*time.Millisecond, config.DatabaseSlowThreshold)
	assert.Equal(t, slog.LevelInfo, config.LogLevel.Level())
	assert.Equal(t, 30*time.Second, config.StartupTimeout)
	assert.Equal(t, 60*time.Second, config.ShutdownTimeout)

	assert.Equal(t, 100, config.Queue.Size)
	assert.Equal(t, 3*time.Minute, config.Queue.MaxAge)
	assert.Equal(t, time.Second, config.Queue.SleepEmpty)
	assert.Equal(t, 5*time.Second, config.Queue.SleepPaused)

	assert.Equal(t, "your_openai_token_here", config.OpenAI.Token)
	assert.Equal(t, slog.LevelInfo, config.OpenAI.LogLevel.Level())
	assert.Equal(t, "your_assistant_id_here", config.OpenAI.AssistantID)

	assert.Equal(t, "your_discord_token_here", config.Discord.Token)
	assert.Equal(
		t,
		"your_discord_application_id_here",
		config.Discord.ApplicationID,
	)
	assert.Equal(t, "your_discord_guild_id_here", config.Discord.GuildID)
	assert.Equal(t, slog.LevelWarn, config.Discord.LogLevel.Level())
	assert.Equal(t, slog.LevelWarn, config.Discord.DiscordGoLogLevel.Level())
	assert.Equal(t, "I'm here!", config.Discord.StartupMessage)

	assert.False(t, config.Discord.WebhookServer.Enabled)
	assert.Equal(t, "127.0.0.1:5001", config.Discord.WebhookServer.Listen)
	assert.Equal(t, "tcp", config.Discord.WebhookServer.ListenNetwork)
	assert.Equal(t, uint16(771), config.Discord.WebhookServer.SSL.TLSMinVersion)
	assert.Equal(
		t,
		slog.LevelInfo,
		config.Discord.WebhookServer.LogLevel.Level(),
	)
	assert.Equal(
		t,
		"your_discord_public_key_here",
		config.Discord.WebhookServer.PublicKey,
	)
	assert.Equal(t, 5*time.Second, config.Discord.WebhookServer.ReadTimeout)
	assert.Equal(
		t,
		5*time.Second,
		config.Discord.WebhookServer.ReadHeaderTimeout,
	)
	assert.Equal(t, 10*time.Second, config.Discord.WebhookServer.WriteTimeout)
	assert.Equal(t, 30*time.Second, config.Discord.WebhookServer.IdleTimeout)

	assert.Equal(t, "127.0.0.1:5000", config.API.Listen)
	assert.Equal(t, "tcp", config.API.ListenNetwork)
	assert.Equal(t, uint16(771), config.API.SSL.TLSMinVersion)
	assert.Equal(t, "your_api_secret_here", config.API.Secret)
	assert.Equal(t, slog.LevelInfo, config.API.LogLevel.Level())

	assert.Empty(t, config.API.CORS.AllowOrigins)
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
		config.API.CORS.ExposeHeaders,
	)
	assert.True(t, config.API.CORS.AllowCredentials)
	assert.Equal(t, 12*time.Hour, config.API.CORS.MaxAge)

	assert.Equal(t, 5*time.Second, config.API.ReadTimeout)
	assert.Equal(t, 5*time.Second, config.API.ReadHeaderTimeout)
	assert.Equal(t, 10*time.Second, config.API.WriteTimeout)
	assert.Equal(t, 30*time.Second, config.API.IdleTimeout)
	assert.Equal(t, 6*time.Hour, config.API.SessionMaxAge)
	assert.False(t, config.API.Development)
	assert.Equal(
		t,
		discordgo.IntentsAll,
		config.Discord.GatewayIntents,
	)
}
