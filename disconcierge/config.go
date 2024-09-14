//nolint:lll // struct tags can't be split
package disconcierge

import (
	"crypto/tls"
	"github.com/bwmarrin/discordgo"
	"github.com/gin-contrib/cors"
	openai "github.com/sashabaranov/go-openai"
	"log/slog"
	"net/http"
	"reflect"
	"time"
)

const (
	EnvvarSetEnvPrefix                = "DISCONCIERGE_ENV_PREFIX"
	DefaultEnvPrefix                  = "DC"
	DefaultRequestLimit6h             = 10
	DefaultDatabaseType               = "sqlite"
	DefaultDatabase                   = "disconcierge.sqlite3"
	DefaultLogLevel                   = slog.LevelInfo
	DefaultStartupTimeout             = 30 * time.Second
	DefaultShutdownTimeout            = 60 * time.Second
	DefaultOpenAIPollInterval         = 3 * time.Second
	DefaultOpenAIMaxRequestsPerSecond = 1
	DefaultOpenAITruncationStrategy   = openai.TruncationStrategyAuto

	DefaultReadTimeout                         = 5 * time.Second
	DefaultReadHeaderTimeout                   = 5 * time.Second
	DefaultWriteTimeout                        = 10 * time.Second
	DefaultIdleTimeout                         = 30 * time.Second
	DefaultFeedbackModalInputLabel             = "Problem description"
	DefaultFeedbackModalPlaceholder            = "Ex: \"Outdated information\", \"Hallucinating\", \"Not helpful\""
	DefaultFeedbackModalMinLength              = 5
	DefaultFeedbackModalMaxLength              = 2000
	DiscordSlashCommandChat                    = "chat"
	DefaultDiscordChatCommandOptionDescription = "What would you like to say or ask?"
	DefaultDiscordReportModalTitle             = "Feedback/Report a problem"
	DiscordSlashCommandPrivate                 = "private"
	DefaultDiscordPrivateCommandDescription    = "Chat with me, but only you can see your message or my response"
	DefaultDiscordWebhookServerListen          = "127.0.0.1:5001"
	DefaultDiscordWebhookServerTLSminVersion   = tls.VersionTLS12
	DefaultDiscordGatewayIntent                = discordgo.IntentsAllWithoutPrivileged

	DiscordSlashCommandClear        = "clear"
	DefaultDiscordQuestionMaxLength = 0
	DefaultDiscordWebhookLogLevel   = slog.LevelInfo
	DefaultDiscordLogLevel          = slog.LevelWarn
	DefaultDiscordErrorMessage      = "sorry, something went wrong!"
	DefaultDiscordRateLimitMessage  = "I'm still working on your last message!"
	DefaultDiscordCustomStatus      = "/chat with me!"
	DefaultDiscordStartupMessage    = "I'm here!"
	discordMaxMessageLength         = 2000
	DefaultAPIListen                = "127.0.0.1:5000"
	DefaultUITLSMinVersion          = tls.VersionTLS12
	DefaultQueueSleepEmpty          = 1 * time.Second
	DefaultQueueSleepPaused         = 5 * time.Second
	DefaultQueueSize                = 100
	DefaultQueueMaxAge              = 3 * time.Minute
	DefaultAPISessionMaxAge         = 6 * time.Hour

	DefaultDatabaseSlowThreshold   = 200 * time.Millisecond
	DefaultDatabaseLogLevel        = slog.LevelInfo
	DefaultDiscordgoLogLevel       = slog.LevelWarn
	DefaultOpenAILogLevel          = slog.LevelInfo
	DefaultAPILogLevel             = slog.LevelInfo
	defaultListenNetwork           = "tcp"
	DefaultAPICORSAllowCredentials = true

	DefaultRuntimeConfigTTL = 5 * time.Minute
	DefaultUserCacheTTL     = time.Hour
)

type DiscordInteractionReceiveMethod string

var (
	discordInteractionReceiveMethodGateway DiscordInteractionReceiveMethod = "gateway"
	discordInteractionReceiveMethodWebhook DiscordInteractionReceiveMethod = "webhook"
)

var (
	DefaultCORSAllowMethods = []string{
		http.MethodGet,
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
		http.MethodOptions,
		http.MethodHead,
	}
	DefaultCORSAllowHeaders = []string{
		"Origin",
		"Content-Length",
		"Content-Type",
		"Accept",
		"Authorization",
		"X-Requested-With",
		"Cache-Control",
		"X-CSRF-Token",
		xRequestIDHeader,
	}
	DefaultCORSExposeHeaders = []string{
		"Content-Type",
		"Content-Length",
		"Accept-Encoding",
		xRequestIDHeader,
		"Location",
		"ETag",
		"Authorization",
		"Last-Modified",
	}
	DefaultCORSMaxAge = 12 * time.Hour
)

type Config struct {
	// Database connection string
	Database string `yaml:"database" mapstructure:"database" json:"database"`

	// DatabaseType specifies the type of database, either 'sqlite' or 'postgres'
	DatabaseType string `yaml:"database_type" mapstructure:"database_type" json:"database_type" binding:"oneof=sqlite postgres"`

	// DatabaseLogLevel sets the log level for database operations
	DatabaseLogLevel *slog.LevelVar `yaml:"database_log_level" mapstructure:"database_log_level" json:"database_log_level"`

	// DatabaseSlowThreshold is the duration threshold for identifying slow database queries
	DatabaseSlowThreshold time.Duration `yaml:"database_slow_threshold" mapstructure:"database_slow_threshold" json:"database_slow_threshold"`

	// Queue holds the configuration for the ChatCommand queue
	Queue *QueueConfig `yaml:"queue" mapstructure:"queue" json:"queue"`

	// OpenAI holds the configuration for OpenAI integration
	OpenAI *OpenAIConfig `yaml:"openai" mapstructure:"openai" json:"openai"`

	// API configures the backend API server
	API *APIConfig `yaml:"api" mapstructure:"api" json:"api"`

	// Discord configures aspects of the Discord bot itself
	Discord *DiscordConfig `yaml:"discord" mapstructure:"discord" json:"discord"`

	// LogLevel is the base log level, for the default logger
	LogLevel *slog.LevelVar `yaml:"log_level" mapstructure:"log_level" json:"log_level"`

	// StartupTimeout sets a limit on the amount of time the bot has to
	// initialize/enqueue running. If this is passed, the bot will abort startup.
	StartupTimeout time.Duration `yaml:"startup_timeout" mapstructure:"startup_timeout" json:"startup_timeout"`

	// ShutdownTimeout is the time to allow for a graceful shutdown. After this
	// elapses, the bot will force close all connections and exit.
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout" mapstructure:"shutdown_timeout" json:"shutdown_timeout"`

	// RuntimeConfigTTL sets the time-to-live for the RuntimeConfig cache.
	// By default, RuntimeConfig is loaded on start, and refreshed with each
	// update. When running multiple instances, though, the config may become
	// 'stale' if updated from another instance. If this TTL is set above 0,
	// the config will be refreshed from the database at least every TTL duration.
	// If using PostgreSQL, LISTEN/NOTIFY will be used to announce updates in
	// addition to this.
	RuntimeConfigTTL time.Duration `yaml:"runtime_config_ttl" mapstructure:"runtime_config_ttl" json:"runtime_config_ttl"`

	// UserCacheTTL sets the time-to-live for the User cache. By default, all
	// [User] entries are loaded on startup, and new/updated entries are
	// added/updated as needed. If this TTL is set above 0, the cache will
	// be refreshed from the database at least every TTL duration. This is
	// primarily useful when running multiple instances.
	UserCacheTTL time.Duration `yaml:"user_cache_ttl" mapstructure:"user_cache_ttl" json:"user_cache_ttl"`

	HTTPClient *http.Client `log:"[redacted]"`
}

type CrawlerConfig struct {
	Enabled                    bool          `yaml:"enabled" mapstructure:"enabled" json:"enabled"`
	URL                        string        `yaml:"url" mapstructure:"url" json:"url"`
	DataDir                    string        `yaml:"data_dir" mapstructure:"data_dir" json:"data_dir" binding:"required_if=Enabled true"`
	FilePollInterval           time.Duration `yaml:"file_poll_interval" mapstructure:"file_poll_interval" json:"file_poll_interval" binding:"required_if=Enabled true"`
	UploadMissingEmbeddedFiles bool          `yaml:"upload_missing_embedded_files" mapstructure:"upload_missing_embedded_files" json:"upload_missing_embedded_files"`
}

func (c Config) LogValue() slog.Value {
	return structToSlogValue(c)
}

// QueueConfig configures the capacity and behavior of the ChatCommand queue.
type QueueConfig struct {
	// Maximum queue size. 0=unlimited
	Size int `yaml:"size" mapstructure:"size" json:"size"`

	// Maximum age of a request that will be returned from the queue. Requests
	// older than this will be discarded. 0=unlimited
	MaxAge time.Duration `yaml:"max_age" mapstructure:"max_age" json:"max_age"`

	// Sleep for this duration when the queue is empty, before checking again
	SleepEmpty time.Duration `yaml:"sleep_empty" mapstructure:"sleep_empty" json:"sleep_empty"`

	// Sleep for this duration when the bot is paused, before checking again
	SleepPaused time.Duration `yaml:"sleep_paused" mapstructure:"sleep_paused" json:"sleep_paused"`
}

func validateQueueConfig(field reflect.Value) any {
	if value, ok := field.Interface().(QueueConfig); ok {
		if value.Size < 0 {
			return "size must be >= 0"
		}
		if value.MaxAge < 0 {
			return "max_age must be >= 0"
		}
		if value.SleepEmpty < 0 {
			return "sleep_empty must be >= 0"
		}
		if value.SleepPaused < 0 {
			return "sleep_paused must be >= 0"
		}
	}
	return nil
}

// DiscordConfig configures the discord bot itself.
//
//nolint:lll // can't break tags
type DiscordConfig struct {
	// Discord bot token (from the 'Bot' tab in the discord dev portal)
	Token string `yaml:"token" mapstructure:"token" json:"token" log:"[redacted]" binding:"required"`

	// Discord application ID (from the 'General Information' tab in the discord dev portal)
	ApplicationID string `yaml:"application_id" mapstructure:"application_id" json:"application_id" binding:"required"`

	// Required when receiving webhook events rather than websockets
	WebhookServer DiscordWebhookServerConfig `yaml:"webhook_server" mapstructure:"webhook_server" json:"webhook_server"`

	// GuildID specifies the guild ID used when registering slash commands.
	// Leave empty for commands to be registered as global.
	GuildID string `yaml:"guild_id" mapstructure:"guild_id" json:"guild_id"`

	// Base discord logging level
	LogLevel *slog.LevelVar `yaml:"log_level" mapstructure:"log_level" json:"log_level"`

	// Log level for the `discordgo` library's logger
	DiscordGoLogLevel *slog.LevelVar `yaml:"discordgo_log_level" mapstructure:"discordgo_log_level" json:"discordgo_log_level"`

	// If specified, _and_ [RuntimeConfig.DiscordGatewayEnabled] is true,
	// _and_ [RuntimeConfig.DiscordNotificationChannelID] is set, the bot will
	// send the specified message to that channel ID whenever it connects to the
	// discord gateway.
	StartupMessage string `yaml:"startup_message" mapstructure:"startup_message" json:"startup_message" binding:"required"`

	// Discord gateway intents. See: https://discord.com/developers/docs/topics/gateway#gateway-intents
	GatewayIntents discordgo.Intent `yaml:"gateway_intents" mapstructure:"gateway_intents" json:"gateway_intents"`

	httpClient *http.Client
}

// DiscordWebhookServerConfig represents the configuration for the Discord webhook server.
//
// This struct defines the settings required to run a server that handles Discord
// webhook interactions. It includes options for enabling the server, specifying
// network details, SSL configuration, logging, and various timeouts.
type DiscordWebhookServerConfig struct {
	// Determines if the webhook server should be active.
	Enabled bool `yaml:"enabled" mapstructure:"enabled" json:"enabled"`

	// The address and port on which the server should listen (e.g., "127.0.0.1:5001").
	Listen string `yaml:"listen" mapstructure:"listen" json:"listen" binding:"required_if=Enabled true,hostname|filepath"`

	// The network type for listening (e.g., "tcp", "tcp4", "tcp6", "unix").
	ListenNetwork string `yaml:"listen_network" mapstructure:"listen_network" json:"listen_network" binding:"required_if=Enabled true,oneof=tcp tcp4 tcp6 unix"`

	// Configuration for SSL/TLS.
	SSL SSLConfig `yaml:"ssl" mapstructure:"ssl" json:"ssl"`

	// The public key used for verifying Discord interaction POST requests.
	// In the Discord dev portal for your bot, this is under 'General Information'
	PublicKey string `yaml:"public_key" mapstructure:"public_key" json:"public_key" binding:"required_if=Enabled true"`

	// The logging level for the webhook server.
	LogLevel *slog.LevelVar `yaml:"log_level" mapstructure:"log_level" json:"log_level"`

	// Maximum duration for reading the entire request, including the body.
	ReadTimeout time.Duration `yaml:"read_timeout" mapstructure:"read_timeout" json:"read_timeout" binding:"required_if=Enabled true,min=1s"`

	// Amount of time allowed to read request headers.
	ReadHeaderTimeout time.Duration `yaml:"read_header_timeout" mapstructure:"read_header_timeout" json:"read_header_timeout"  binding:"required_if=Enabled true,min=1s"`

	// Maximum duration before timing out writes of the response.
	WriteTimeout time.Duration `yaml:"write_timeout" mapstructure:"write_timeout" json:"write_timeout"  binding:"required_if=Enabled true,min=1s"`

	// Maximum amount of time to wait for the next request when keep-alives are enabled.
	IdleTimeout time.Duration `yaml:"idle_timeout" mapstructure:"idle_timeout" json:"idle_timeout"  binding:"required_if=Enabled true,min=1s"`
}

// OpenAIConfig configures OpenAI API integration and assistant parameters
type OpenAIConfig struct {
	// OpenAI API token
	Token string `yaml:"token" mapstructure:"token" json:"token" log:"[redacted]" binding:"required"`

	// OpenAI base log level
	LogLevel *slog.LevelVar `yaml:"log_level" mapstructure:"log_level" json:"log_level"`

	// ID of the OpenAI assistant to use
	AssistantID string `yaml:"assistant_id" mapstructure:"assistant_id" json:"assistant_id"`
}

// APIConfig configures the backend API server
type APIConfig struct {
	// The address and port on which the server should listen (e.g., "127.0.0.1:5001").
	Listen string `yaml:"listen" mapstructure:"listen" json:"listen" binding:"required_if=Enabled true,hostname|filepath"`

	// The network type for listening (e.g., "tcp", "tcp4", "tcp6", "unix").
	ListenNetwork string `yaml:"listen_network" mapstructure:"listen_network" json:"listen_network" binding:"required_if=Enabled true,oneof=tcp tcp4 tcp6 unix"`

	// Secret used for signing cookies
	Secret string `yaml:"secret" mapstructure:"secret" json:"secret" log:"[redacted]"`

	// Configuration for SSL/TLS.
	SSL SSLConfig `yaml:"ssl" mapstructure:"ssl" json:"ssl"`

	// The logging level for the API server.
	LogLevel *slog.LevelVar `yaml:"log_level" mapstructure:"log_level" json:"log_level"`

	// Cross-origin configuration
	CORS CORSConfig `yaml:"cors" mapstructure:"cors" json:"cors"`

	// Maximum duration for reading the entire request, including the body.
	ReadTimeout time.Duration `yaml:"read_timeout" mapstructure:"read_timeout" json:"read_timeout" binding:"required_if=Enabled true,min=1s"`

	// Amount of time allowed to read request headers.
	ReadHeaderTimeout time.Duration `yaml:"read_header_timeout" mapstructure:"read_header_timeout" json:"read_header_timeout"  binding:"required_if=Enabled true,min=1s"`

	// Maximum duration before timing out writes of the response.
	WriteTimeout time.Duration `yaml:"write_timeout" mapstructure:"write_timeout" json:"write_timeout"  binding:"required_if=Enabled true,min=1s"`

	// Maximum amount of time to wait for the next request when keep-alives are enabled.
	IdleTimeout time.Duration `yaml:"idle_timeout" mapstructure:"idle_timeout" json:"idle_timeout"  binding:"required_if=Enabled true,min=1s"`

	// Max age for session cookies
	SessionMaxAge time.Duration `yaml:"session_max_age" mapstructure:"session_max_age" json:"session_max_age"  binding:"required_if=Enabled true,min=10m,max=24h"`

	// If true, the SameSite attribute of the session cookie will be set to 'None'
	Development bool `yaml:"development" mapstructure:"development" json:"development"`
}

// SSLConfig specifies cert paths and the TLS version to use
type SSLConfig struct {
	// Path to an SSL certificate
	Cert string `yaml:"cert" mapstructure:"cert" json:"cert"`

	// Path to an SSL cert key
	Key string `yaml:"key" mapstructure:"key" json:"key"`

	// Minimum TLS version
	TLSMinVersion uint16 `yaml:"tls_min_version" mapstructure:"tls_min_version" json:"tls_min_version"`
}

// CORSConfig specifies cross-origin resource sharing settings
type CORSConfig struct {
	AllowOrigins     []string      `yaml:"allow_origins" mapstructure:"allow_origins" json:"allow_origins"`
	AllowMethods     []string      `yaml:"allow_methods" mapstructure:"allow_methods" json:"allow_methods"`
	AllowHeaders     []string      `yaml:"allow_headers" mapstructure:"allow_headers" json:"allow_headers"`
	ExposeHeaders    []string      `yaml:"expose_headers" mapstructure:"expose_headers" json:"expose_headers"`
	AllowCredentials bool          `yaml:"allow_credentials" mapstructure:"allow_credentials" json:"allow_credentials"`
	MaxAge           time.Duration `yaml:"max_age" mapstructure:"max_age" json:"max_age"`
}

func (c CORSConfig) GINConfig() cors.Config {
	return cors.Config{
		AllowOrigins:     c.AllowOrigins,
		AllowMethods:     c.AllowMethods,
		AllowHeaders:     c.AllowHeaders,
		MaxAge:           c.MaxAge,
		ExposeHeaders:    c.ExposeHeaders,
		AllowCredentials: c.AllowCredentials,
	}
}

func DefaultCORSConfig() CORSConfig {
	defaultMethods := make([]string, len(DefaultCORSAllowMethods))
	copy(defaultMethods, DefaultCORSAllowMethods)

	defaultHeaders := make([]string, len(DefaultCORSAllowHeaders))
	copy(defaultHeaders, DefaultCORSAllowHeaders)

	defaultExpose := make([]string, len(DefaultCORSExposeHeaders))
	copy(defaultExpose, DefaultCORSExposeHeaders)

	return CORSConfig{
		AllowOrigins:     []string{},
		AllowMethods:     defaultMethods,
		AllowHeaders:     defaultHeaders,
		ExposeHeaders:    defaultExpose,
		MaxAge:           DefaultCORSMaxAge,
		AllowCredentials: DefaultAPICORSAllowCredentials,
	}
}

// DefaultConfig returns a Config with all default settings populated
func DefaultConfig() *Config {
	mainLogLevel := &slog.LevelVar{}
	openaiLogLevel := &slog.LevelVar{}
	discordLogLevel := &slog.LevelVar{}
	discordgoLogLevel := &slog.LevelVar{}
	dbLogLevel := &slog.LevelVar{}
	apiLogLevel := &slog.LevelVar{}
	discordWebhookLogLevel := &slog.LevelVar{}

	mainLogLevel.Set(DefaultLogLevel)
	openaiLogLevel.Set(DefaultOpenAILogLevel)
	discordLogLevel.Set(DefaultDiscordLogLevel)
	discordgoLogLevel.Set(DefaultDiscordgoLogLevel)
	dbLogLevel.Set(DefaultDatabaseLogLevel)
	apiLogLevel.Set(DefaultAPILogLevel)
	discordWebhookLogLevel.Set(DefaultDiscordWebhookLogLevel)

	return &Config{
		DatabaseType:          DefaultDatabaseType,
		Database:              DefaultDatabase,
		DatabaseLogLevel:      dbLogLevel,
		DatabaseSlowThreshold: DefaultDatabaseSlowThreshold,
		LogLevel:              mainLogLevel,
		StartupTimeout:        DefaultStartupTimeout,
		ShutdownTimeout:       DefaultShutdownTimeout,
		RuntimeConfigTTL:      DefaultRuntimeConfigTTL,
		UserCacheTTL:          DefaultUserCacheTTL,
		Queue: &QueueConfig{
			Size:        DefaultQueueSize,
			MaxAge:      DefaultQueueMaxAge,
			SleepEmpty:  DefaultQueueSleepEmpty,
			SleepPaused: DefaultQueueSleepPaused,
		},
		OpenAI: &OpenAIConfig{
			LogLevel: openaiLogLevel,
		},
		Discord: &DiscordConfig{
			WebhookServer: DiscordWebhookServerConfig{
				Enabled:       false,
				Listen:        DefaultDiscordWebhookServerListen,
				ListenNetwork: defaultListenNetwork,
				SSL: SSLConfig{
					TLSMinVersion: DefaultDiscordWebhookServerTLSminVersion,
				},
				LogLevel:          discordWebhookLogLevel,
				ReadHeaderTimeout: DefaultReadHeaderTimeout,
				ReadTimeout:       DefaultReadTimeout,
				WriteTimeout:      DefaultWriteTimeout,
				IdleTimeout:       DefaultIdleTimeout,
			},
			GatewayIntents:    DefaultDiscordGatewayIntent,
			LogLevel:          discordLogLevel,
			DiscordGoLogLevel: discordgoLogLevel,
			StartupMessage:    DefaultDiscordStartupMessage,
		},
		API: &APIConfig{
			Listen:        DefaultAPIListen,
			ListenNetwork: defaultListenNetwork,
			SSL: SSLConfig{
				TLSMinVersion: DefaultUITLSMinVersion,
			},
			LogLevel:          apiLogLevel,
			ReadHeaderTimeout: DefaultReadHeaderTimeout,
			ReadTimeout:       DefaultReadTimeout,
			WriteTimeout:      DefaultWriteTimeout,
			IdleTimeout:       DefaultIdleTimeout,
			SessionMaxAge:     DefaultAPISessionMaxAge,
			CORS:              DefaultCORSConfig(),
		},
	}
}
