package cmd

import (
	"context"
	"fmt"
	"github.com/arcward/disconcierge/disconcierge"
	"github.com/joho/godotenv"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

var (
	cfg        = disconcierge.DefaultConfig()
	configFile string
)

var rootCmd = &cobra.Command{
	Use: "disconcierge [flags]",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		err := viper.Unmarshal(
			cfg,
			viper.DecodeHook(
				mapstructure.ComposeDecodeHookFunc(
					mapstructure.StringToTimeDurationHookFunc(),
					LevelToStringHookFunc(),
				),
			),
		)
		if err != nil {
			log.Fatalln(err)
		}
	},
}

func getLogLevel(level string) (slog.Level, error) {
	switch level {
	case slog.LevelDebug.String():
		return slog.LevelDebug, nil
	case slog.LevelInfo.String():
		return slog.LevelInfo, nil
	case slog.LevelWarn.String():
		return slog.LevelWarn, nil
	case slog.LevelError.String():
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("invalid log level: %s", level)
	}
}

func LevelToStringHookFunc() mapstructure.DecodeHookFuncType {
	return func(
		f reflect.Type,
		t reflect.Type,
		data any,
	) (any, error) {
		if f.Kind() != reflect.String {
			return data, nil
		}
		if t.Kind() != reflect.Ptr {
			return data, nil
		}

		typ := t.Elem()

		if typ != reflect.TypeOf(slog.LevelVar{}) {
			return data, nil
		}
		lvl, err := getLogLevel(data.(string))
		if err != nil {
			return nil, fmt.Errorf("invalid log level: %s", data)
		}
		lvlVar := &slog.LevelVar{}
		lvlVar.Set(lvl)
		return lvlVar, nil
	}
}

func Execute() {
	ctx, cancel := context.WithCancel(context.Background())
	rootCmd.SetContext(ctx)
	signals := make(chan os.Signal, 1)
	signal.Notify(
		signals,
		os.Interrupt,
		syscall.SIGHUP,
		syscall.SIGTERM,
		syscall.SIGINT,
	)
	defer func() {
		signal.Stop(signals)
		cancel()
	}()
	go func() {
		select {
		case <-signals:
			cancel()
		case <-ctx.Done():
			//
		}
	}()
	err := rootCmd.ExecuteContext(ctx)
	fmt.Println(err)
	if err != nil {
		os.Exit(1)
	}
}

func initConfig() {
	if configFile == "" {
		if err := godotenv.Load(); err != nil {
			log.Println("No .env file found")
		}
	} else {
		fmt.Println("loading env from file", configFile)
		if err := godotenv.Load(configFile); err != nil {
			log.Println("No .env file found")
		}
	}

	viper.SetDefault("database", disconcierge.DefaultDatabase)
	viper.SetDefault("database_type", disconcierge.DefaultDatabaseType)
	viper.SetDefault(
		"database_slow_threshold",
		disconcierge.DefaultDatabaseSlowThreshold,
	)
	viper.SetDefault(
		"database_log_level",
		disconcierge.DefaultDatabaseLogLevel.String(),
	)
	viper.SetDefault("external_url", "https://127.0.0.1:5000")
	viper.SetDefault("development", false)

	viper.SetDefault("runtime_config_ttl", disconcierge.DefaultRuntimeConfigTTL)
	viper.SetDefault("user_cache_ttl", disconcierge.DefaultUserCacheTTL)

	viper.SetDefault("log_level", disconcierge.DefaultLogLevel.String())
	viper.SetDefault("api.log_level", disconcierge.DefaultAPILogLevel.String())

	viper.SetDefault("startup_timeout", disconcierge.DefaultStartupTimeout)
	viper.SetDefault("shutdown_timeout", disconcierge.DefaultShutdownTimeout)

	viper.SetDefault("queue.max_age", disconcierge.DefaultQueueMaxAge)
	viper.SetDefault("queue.size", disconcierge.DefaultQueueSize)
	viper.SetDefault(
		"queue.sleep_paused",
		disconcierge.DefaultQueueSleepPaused,
	)
	viper.SetDefault(
		"queue.sleep_empty",
		disconcierge.DefaultQueueSleepEmpty,
	)

	// OpenAI config
	viper.SetDefault("openai.log_level", disconcierge.DefaultOpenAILogLevel.String())
	viper.SetDefault("openai.token", "")
	viper.SetDefault("openai.assistant_id", "")

	// Discord config
	viper.SetDefault("discord.token", "")
	viper.SetDefault("discord.application_id", "")
	viper.SetDefault("discord.guild_id", "")
	viper.SetDefault(
		"discord.log_level",
		disconcierge.DefaultDiscordLogLevel.String(),
	)
	viper.SetDefault(
		"discord.discordgo_log_level",
		disconcierge.DefaultDiscordgoLogLevel.String(),
	)
	viper.SetDefault(
		"discord.gateway_intents",
		disconcierge.DefaultDiscordGatewayIntent,
	)
	viper.SetDefault("discord.startup_message", disconcierge.DefaultDiscordStartupMessage)

	// Discord: Webhook server
	viper.SetDefault("discord.webhook_server.enabled", false)
	viper.SetDefault(
		"discord.webhook_server.listen",
		disconcierge.DefaultDiscordWebhookServerListen,
	)
	viper.SetDefault("discord.webhook_server.public_key", "")
	viper.SetDefault(
		"discord.webhook_server.read_timeout",
		disconcierge.DefaultReadTimeout,
	)
	viper.SetDefault(
		"discord.webhook_server.read_header_timeout",
		disconcierge.DefaultReadHeaderTimeout,
	)
	viper.SetDefault(
		"discord.webhook_server.write_timeout",
		disconcierge.DefaultWriteTimeout,
	)
	viper.SetDefault(
		"discord.webhook_server.idle_timeout",
		disconcierge.DefaultIdleTimeout,
	)
	viper.SetDefault(
		"discord.webhook_server.log_level",
		disconcierge.DefaultDiscordWebhookLogLevel.String(),
	)

	fatalErr := func(err error) {
		if err != nil {
			log.Fatalf("error: %v", err)
		}
	}

	// Discord: Webhook server: SSL

	fatalErr(viper.BindEnv("discord.webhook_server.ssl.cert_file"))
	fatalErr(viper.BindEnv("discord.webhook_server.ssl.key_file"))
	fatalErr(viper.BindEnv("discord.webhook_server.ssl.cert_pem"))
	fatalErr(viper.BindEnv("discord.webhook_server.ssl.key_pem"))
	fatalErr(viper.BindEnv("discord.webhook_server.ssl.tls_min_version"))

	// API config
	viper.SetDefault("api.listen", disconcierge.DefaultAPIListen)
	viper.SetDefault("api.secret", "")

	viper.SetDefault(
		"api.session_max_age",
		disconcierge.DefaultAPISessionMaxAge,
	)
	viper.SetDefault("api.read_timeout", disconcierge.DefaultReadTimeout)
	viper.SetDefault(
		"api.read_header_timeout",
		disconcierge.DefaultReadHeaderTimeout,
	)
	viper.SetDefault("api.write_timeout", disconcierge.DefaultWriteTimeout)
	viper.SetDefault("api.idle_timeout", disconcierge.DefaultIdleTimeout)

	// API: SSL config
	fatalErr(viper.BindEnv("api.external_url"))
	fatalErr(viper.BindEnv("api.ssl.cert_file"))
	fatalErr(viper.BindEnv("api.ssl.key_file"))
	fatalErr(viper.BindEnv("api.ssl.cert_pem"))
	fatalErr(viper.BindEnv("api.ssl.key_pem"))
	fatalErr(viper.BindEnv("api.ssl.tls_min_version"))

	// API: CORS config
	viper.SetDefault(
		"api.cors.allow_headers",
		disconcierge.DefaultCORSAllowHeaders,
	)
	viper.SetDefault(
		"api.cors.allow_methods",
		disconcierge.DefaultCORSAllowMethods,
	)
	viper.SetDefault(
		"api.cors.expose_headers",
		disconcierge.DefaultCORSExposeHeaders,
	)
	viper.SetDefault(
		"api.cors.allow_origins",
		[]string{},
	)
	viper.SetDefault("api.cors.max_age", disconcierge.DefaultCORSMaxAge)
	viper.SetDefault(
		"api.cors.allow_credentials",
		disconcierge.DefaultAPICORSAllowCredentials,
	)

	envPrefix := os.Getenv(disconcierge.EnvvarSetEnvPrefix)
	if envPrefix == "" {
		envPrefix = disconcierge.DefaultEnvPrefix
	}
	viper.SetEnvPrefix(envPrefix)

	replacer := strings.NewReplacer(".", "_")
	viper.SetEnvKeyReplacer(replacer)
	viper.AutomaticEnv()

	// Convert values to correct types
	viper.Set(
		"api.cors.allow_headers",
		viper.GetStringSlice("api.cors.allow_headers"),
	)
	viper.Set(
		"api.cors.allow_origins",
		viper.GetStringSlice("api.cors.allow_origins"),
	)
	viper.Set(
		"api.cors.allow_methods",
		viper.GetStringSlice("api.cors.allow_methods"),
	)
	viper.Set(
		"api.cors.expose_headers",
		viper.GetStringSlice("api.cors.expose_headers"),
	)

	for k, v := range viper.AllSettings() {
		log.Printf("config: %s: %v", k, v)
	}
	logLevelVar, err := levelStringToLevelVar(viper.GetString("log_level"))
	if err != nil {
		log.Fatalf("error parsing log_level: %v", err)
	}
	viper.Set("log_level", logLevelVar)

	logLevelVar, err = levelStringToLevelVar(viper.GetString("discord.log_level"))
	if err != nil {
		log.Fatalf("error parsing discord log level: %v", err)
	}
	viper.Set("discord.log_level", logLevelVar)

	logLevelVar, err = levelStringToLevelVar(viper.GetString("openai.log_level"))
	if err != nil {
		log.Fatalf("error parsing openai log level: %v", err)
	}
	viper.Set("openai.log_level", logLevelVar)

	logLevelVar, err = levelStringToLevelVar(viper.GetString("discord.discordgo_log_level"))
	if err != nil {
		log.Fatalf("error parsing discordgo log level: %v", err)
	}
	viper.Set("discord.discordgo_log_level", logLevelVar)

	logLevelVar, err = levelStringToLevelVar(viper.GetString("database_log_level"))
	if err != nil {
		log.Fatalf("error parsing database log level: %v", err)
	}
	viper.Set("database_log_level", logLevelVar)

	logLevelVar, err = levelStringToLevelVar(viper.GetString("api.log_level"))
	if err != nil {
		log.Fatalf("error parsing api log level: %v", err)
	}
	viper.Set("api.log_level", logLevelVar)

	logLevelVar, err = levelStringToLevelVar(viper.GetString("discord.webhook_server.log_level"))
	if err != nil {
		log.Fatalf("error parsing webhook server log level: %v", err)
	}
	viper.Set("discord.webhook_server.log_level", logLevelVar)

}

func assertLogLevel(t testing.TB, expected slog.Level, v any) {
	t.Helper()

	lvl, ok := v.(*slog.LevelVar)
	require.Truef(t, ok, "could not convert %#v (%T) to *slog.LevelVar", v, v)
	assert.Equal(t, expected, lvl.Level())
}

func levelStringToLevelVar(lvl string) (*slog.LevelVar, error) {
	level := &slog.LevelVar{}
	err := level.UnmarshalText([]byte(lvl))
	return level, err
}

//goland:noinspection GoLinter,GoLinter
func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(
		&configFile,
		"config",
		"",
		"Config file to use",
	)
}
