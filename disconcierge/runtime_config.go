package disconcierge

import (
	"context"
	"fmt"
	"github.com/bwmarrin/discordgo"
	"github.com/lmittmann/tint"
	"github.com/sashabaranov/go-openai"
	"gorm.io/gorm"
	"log/slog"
	"reflect"
	"time"
)

var (
	columnRuntimeConfigAdminUsername          = "admin_username"
	columnRuntimeConfigAdminPassword          = "admin_password"
	columnRuntimeConfigChatCommandMaxAttempts = "chat_command_max_attempts"

	columnRuntimeConfigUserChatCommandLimit6h               = "user_chat_command_limit_6h"
	columnRuntimeConfigAssistantTemperature                 = "assistant_temperature"
	columnRuntimeConfigAssistantInstructions                = "assistant_instructions"
	columnRuntimeConfigAssistantAdditionalInstructions      = "assistant_additional_instructions"
	columnRuntimeConfigAssistantMaxPollInterval             = "assistant_max_poll_interval"
	columnRuntimeConfigAssistantPollInterval                = "assistant_poll_interval"
	columnRuntimeConfigOpenAIMaxCompletionTokens            = "openai_max_completion_tokens"
	columnRuntimeConfigOpenAIMaxPromptTokens                = "openai_max_prompt_tokens"
	columnRuntimeConfigOpenAITruncationStrategyLastMessages = "openai_truncation_strategy_last_messages"
	columnRuntimeConfigOpenAITruncationStrategyType         = "openai_truncation_strategy_type"
	columnRuntimeConfigDiscordNotificationChannelID         = "discord_notification_channel_id"
	columnRuntimeConfigPaused                               = "paused"
)

// RuntimeConfig represents the runtime configuration of the DisConcierge bot.
// It stores settings that can be modified during runtime and persisted
// across restarts. This struct is used to manage the 'live' application state
// for states we would want to maintain across restarts (e.g., being paused).
//
// The struct includes settings for Discord interactions, OpenAI configurations,
// logging levels, and various command behaviors.
//
//nolint:lll // struct tags can't be split
type RuntimeConfig struct {
	ModelUintID
	ModelUnixTime
	CommandOptions

	// Paused indicates whether the bot is currently paused.
	Paused bool `json:"paused" gorm:"not null;default:false"`

	// Opens a discord gateway websocket connection.
	// If the bot receives slash commands via gateway, this is required.
	// If the bot receives commands via webhook, enabling this allows the
	// bot to appear online and set its status.
	DiscordGatewayEnabled bool `json:"discord_gateway_enabled" gorm:"not null;default:true"`

	// DiscordCustomStatus is the custom status message displayed for the bot on Discord.
	DiscordCustomStatus string `json:"discord_custom_status" gorm:"type:string"`

	// ChatCommandDescription is the description for the 'chat' command.
	ChatCommandDescription string `json:"chat_command_description" gorm:"default:Chat with me!" binding:"min=1,max=100"`

	// ChatCommandOptionDescription is the description for the 'chat' command's option.
	ChatCommandOptionDescription string `json:"chat_command_option_description" gorm:"default:What would you like to say or ask?" binding:"min=1,max=100"`

	// ChatCommandMaxLength is the maximum length for an 'chat' command prompt.
	ChatCommandMaxLength int `json:"chat_command_max_length" gorm:"default:500" binding:"omitempty,min=1,max=6000"`

	// PrivateCommandDescription is the description for the 'private' command.
	PrivateCommandDescription string `json:"private_command_description" gorm:"type:string" binding:"min=1,max=100"`

	// OpenAIMaxRequestsPerSecond is the rate limit for how many OpenAI "Create Run"
	// API requests can be made per second
	// TODO give this a clearer name, as it only applies to 'Create Run' requests
	OpenAIMaxRequestsPerSecond int `gorm:"column:openai_max_requests_per_second;default:1" json:"openai_max_requests_per_second" binding:"min=1"`

	// Limits the number of ChatCommands requests per user per 6-hour window
	// (commands are 'billable' if OpenAI's response reflects tokens
	// were consumed)
	UserChatCommandLimit6h int `gorm:"column:user_chat_command_limit_6h;check:user_chat_command_limit_6h > 0" json:"user_chat_command_limit_6h" binding:"min=1"`

	// AdminUsername for the web UI
	AdminUsername string `json:"admin_username" gorm:"type:string" log:"[redacted]"`

	// AdminPassword stores the hashed password for the admin user
	AdminPassword string `json:"admin_password" gorm:"type:string" log:"[redacted]"`

	// LogLevel is the general logging level for the application.
	LogLevel DBLogLevel `gorm:"default:INFO;type:string;check:log_level in ('INFO', 'WARN', 'ERROR', 'DEBUG')" json:"log_level" binding:"omitnil,oneof=INFO WARN ERROR DEBUG"`

	// OpenAILogLevel is the logging level for OpenAI-related operations.
	OpenAILogLevel DBLogLevel `gorm:"default:INFO;column:openai_log_level;type:string;check:openai_log_level in ('INFO', 'WARN', 'ERROR', 'DEBUG')" json:"openai_log_level" binding:"omitnil,oneof=INFO WARN ERROR DEBUG"`

	// DiscordLogLevel is the logging level for Discord-related operations.
	DiscordLogLevel DBLogLevel `gorm:"default:INFO;type:string;check:discord_log_level in ('INFO', 'WARN', 'ERROR', 'DEBUG')" json:"discord_log_level" binding:"omitnil,oneof=INFO WARN ERROR DEBUG"`

	// DiscordGoLogLevel is the logging level for the DiscordGo library.
	DiscordGoLogLevel DBLogLevel `gorm:"default:INFO;column:discordgo_log_level;type:string;check:discordgo_log_level in ('INFO', 'WARN', 'ERROR', 'DEBUG')" json:"discordgo_log_level" binding:"omitnil,oneof=INFO WARN ERROR DEBUG"`

	// DatabaseLogLevel is the logging level for database operations.
	DatabaseLogLevel DBLogLevel `gorm:"default:INFO;type:string;check:database_log_level in ('INFO', 'WARN', 'ERROR', 'DEBUG')" json:"database_log_level" binding:"omitnil,oneof=INFO WARN ERROR DEBUG"`

	// DiscordWebhookLogLevel is the logging level for Discord webhook operations.
	DiscordWebhookLogLevel DBLogLevel `gorm:"default:INFO;type:string;check:discord_webhook_log_level in ('INFO', 'WARN', 'ERROR', 'DEBUG')" json:"discord_webhook_log_level" binding:"omitnil,oneof=INFO WARN ERROR DEBUG"`

	// APILogLevel is the logging level for API operations.
	APILogLevel DBLogLevel `gorm:"default:INFO;type:string;check:api_log_level in ('INFO', 'WARN', 'ERROR', 'DEBUG')" json:"api_log_level" binding:"omitnil,oneof=INFO WARN ERROR DEBUG"`
}

func (RuntimeConfig) TableName() string {
	return "config"
}

func DefaultRuntimeConfig() RuntimeConfig {
	b := RuntimeConfig{
		CommandOptions: CommandOptions{
			FeedbackEnabled:          true,
			FeedbackModalTitle:       DefaultDiscordReportModalTitle,
			FeedbackModalInputLabel:  DefaultFeedbackModalInputLabel,
			FeedbackModalPlaceholder: DefaultFeedbackModalPlaceholder,
			FeedbackModalMinLength:   DefaultFeedbackModalMinLength,
			FeedbackModalMaxLength:   DefaultFeedbackModalMaxLength,
			RecoverPanic:             false,
			DiscordErrorMessage:      DefaultDiscordErrorMessage,
			DiscordRateLimitMessage:  DefaultDiscordRateLimitMessage,
		},
		ChatCommandOptionDescription: DefaultDiscordChatCommandOptionDescription,
		ChatCommandMaxLength:         DefaultDiscordQuestionMaxLength,
		PrivateCommandDescription:    DefaultDiscordPrivateCommandDescription,
		OpenAIMaxRequestsPerSecond:   DefaultOpenAIMaxRequestsPerSecond,
		DiscordCustomStatus:          DefaultDiscordCustomStatus,
		UserChatCommandLimit6h:       DefaultRequestLimit6h,
		LogLevel:                     DBLogLevel(slog.LevelInfo.String()),
		OpenAILogLevel:               DBLogLevel(slog.LevelInfo.String()),
		DiscordLogLevel:              DBLogLevel(slog.LevelInfo.String()),
		DiscordGoLogLevel:            DBLogLevel(slog.LevelInfo.String()),
		DatabaseLogLevel:             DBLogLevel(slog.LevelInfo.String()),
		DiscordWebhookLogLevel:       DBLogLevel(slog.LevelInfo.String()),
		APILogLevel:                  DBLogLevel(slog.LevelInfo.String()),
	}
	b.OpenAIRunSettings = OpenAIRunSettings{
		OpenAITruncationStrategyType:         DefaultOpenAITruncationStrategy,
		OpenAITruncationStrategyLastMessages: 3,
		AssistantPollInterval:                Duration{DefaultOpenAIPollInterval},
		AssistantMaxPollInterval:             Duration{DefaultOpenAIPollInterval * 5},
		AssistantTemperature:                 1,
	}

	return b
}

// pollInterval converts the given number of seconds to a time.Duration
func pollInterval(secs float64) time.Duration {
	return time.Duration(secs * float64(time.Second))
}

// runtimeConfigValueChanged accepts two interface{} values,
// where runtimeConfigVal should be the value of a field from RuntimeConfig,
// and runtimeConfigUpdateVal should be the value of a field from
// RuntimeConfigUpdate.
// A boolean is returned, where `true` indicates that runtimeConfigUpdateVal
// is non-nil, and its dereferenced value is different from runtimeConfigVal.
// If `false`, it indicates either runtimeConfigUpdateVal is nil,
// or its underlying value is the same as runtimeConfigVal.
// This is used to compare the current RuntimeConfig with an update
// payload, to determine which User fields should be updated.
func runtimeConfigValueChanged(runtimeConfigVal, runtimeConfigUpdateVal any) bool {
	newValRef := reflect.ValueOf(runtimeConfigUpdateVal)
	if newValRef.Kind() != reflect.Ptr {
		return false
	}

	if newValRef.IsNil() {
		return false
	}

	// Dereference the pointer to get the actual value
	updateValDereferenced := newValRef.Elem().Interface()

	// Compare the dereferenced value with currentVal
	return !reflect.DeepEqual(runtimeConfigVal, updateValDereferenced)
}

// updateUsersFromRuntimeConfig determines which fields have been changed
// between the current RuntimeConfig, and a RuntimeConfigUpdate payload.
// For each field that has changed, which has a corresponding field in the User
// struct, the User records are updated to reflect the new values, for users
// where their current value matches the old value.
// This allows a "global" config update to also update users, without
// overwriting user-specific settings.
func updateUsersFromRuntimeConfig(
	ctx context.Context,
	db DBI,
	update RuntimeConfigUpdate,
	currentConfig *RuntimeConfig,
) error {
	log, ok := ContextLogger(ctx)
	if !ok || log == nil {
		log = slog.Default()
	}

	isNilPointer := func(v any) bool {
		if v == nil {
			return true
		}

		val := reflect.ValueOf(v)
		if val.Kind() == reflect.Ptr {
			return val.IsNil()
		}

		return false
	}

	return db.Transaction(
		func(tx *gorm.DB) error {
			// Helper function to update config and user fields
			updateField := func(updateVal any, currentVal any, fieldName string) error {
				if isNilPointer(updateVal) {
					return nil
				}
				changed := runtimeConfigValueChanged(currentVal, updateVal)
				log.InfoContext(
					ctx,
					"globally updating user field",
					"field", fieldName,
					"current", currentVal,
					"new", updateVal,
				)
				if changed {
					log.Debug(
						"field changed",
						"field", fieldName,
						"current", currentVal,
						"new", updateVal,
					)

					if err := tx.Model(&User{}).Where(
						fieldName+" = ?",
						currentVal,
					).Update(fieldName, updateVal).Error; err != nil {
						log.Error(
							"error updating user records",
							tint.Err(err),
							"field", fieldName,
						)
						return err
					}
				}
				return nil
			}

			if err := updateField(
				update.OpenAITruncationStrategyType,
				currentConfig.OpenAITruncationStrategyType,
				columnRuntimeConfigOpenAITruncationStrategyType,
			); err != nil {
				return err
			}
			if err := updateField(
				update.OpenAITruncationStrategyLastMessages,
				currentConfig.OpenAITruncationStrategyLastMessages,
				columnRuntimeConfigOpenAITruncationStrategyLastMessages,
			); err != nil {
				return err
			}
			if err := updateField(
				update.OpenAIMaxPromptTokens,
				currentConfig.OpenAIMaxPromptTokens,
				columnRuntimeConfigOpenAIMaxPromptTokens,
			); err != nil {
				return err
			}
			if err := updateField(
				update.OpenAIMaxCompletionTokens,
				currentConfig.OpenAIMaxCompletionTokens,
				columnRuntimeConfigOpenAIMaxCompletionTokens,
			); err != nil {
				return err
			}

			if err := updateField(
				update.AssistantPollInterval,
				currentConfig.AssistantPollInterval,
				columnRuntimeConfigAssistantPollInterval,
			); err != nil {
				return err
			}
			if err := updateField(
				update.AssistantMaxPollInterval,
				currentConfig.AssistantMaxPollInterval,
				columnRuntimeConfigAssistantMaxPollInterval,
			); err != nil {
				return err
			}
			if err := updateField(
				update.AssistantInstructions,
				currentConfig.AssistantInstructions,
				columnRuntimeConfigAssistantInstructions,
			); err != nil {
				return err
			}
			if err := updateField(
				update.AssistantAdditionalInstructions,
				currentConfig.AssistantAdditionalInstructions,
				columnRuntimeConfigAssistantAdditionalInstructions,
			); err != nil {
				return err
			}
			if err := updateField(
				update.AssistantTemperature,
				currentConfig.AssistantTemperature,
				columnRuntimeConfigAssistantTemperature,
			); err != nil {
				return err
			}
			if err := updateField(
				update.UserChatCommandLimit6h,
				currentConfig.UserChatCommandLimit6h,
				columnRuntimeConfigUserChatCommandLimit6h,
			); err != nil {
				return err
			}
			return nil
		},
	)
}

//nolint:lll // can't break tags
type RuntimeConfigUpdate struct {
	Paused       *bool `json:"paused,omitempty"`
	RecoverPanic *bool `json:"recover_panic,omitempty"`

	DiscordGatewayEnabled        *bool   `json:"discord_gateway_enabled,omitempty"`
	DiscordCustomStatus          *string `json:"discord_custom_status,omitempty"`
	DiscordRateLimitMessage      *string `json:"discord_rate_limit_message,omitempty"`
	DiscordErrorMessage          *string `json:"discord_error_message,omitempty"`
	DiscordNotificationChannelID *string `json:"discord_notification_channel_id,omitempty"`

	FeedbackEnabled          *bool   `json:"feedback_enabled,omitempty"`
	FeedbackModalInputLabel  *string `json:"feedback_modal_input_label,omitempty" binding:"omitnil,min=0,max=45"`
	FeedbackModalPlaceholder *string `json:"feedback_modal_placeholder,omitempty" binding:"omitnil,min=0,max=100"`
	FeedbackModalMinLength   *int    `json:"feedback_modal_min_length,omitempty" binding:"omitnil,min=0,max=4000"`
	FeedbackModalMaxLength   *int    `json:"feedback_modal_max_length,omitempty" binding:"omitnil,min=0,max=4000"`
	FeedbackModalTitle       *string `json:"feedback_modal_title,omitempty"`

	ChatCommandDescription       *string `json:"chat_command_description,omitempty" binding:"omitnil,min=1,max=100"`
	ChatCommandOptionDescription *string `json:"chat_command_option_description,omitempty" binding:"omitnil,min=1,max=100"`
	ChatCommandMaxLength         *int    `json:"chat_command_max_length,omitempty" binding:"omitnil,min=1,max=6000"`
	ChatCommandMaxAttempts       *int    `json:"chat_command_max_attempts,omitempty" binding:"omitnil,min=1,max=10"`
	PrivateCommandDescription    *string `json:"private_command_description,omitempty"`

	OpenAITruncationStrategyType         *openai.TruncationStrategy `json:"openai_truncation_strategy_type,omitempty" binding:"omitnil,oneof=auto last_messages"`
	OpenAITruncationStrategyLastMessages *int                       `json:"openai_truncation_strategy_last_messages,omitempty" binding:"omitnil,min=0,required_if=OpenAITruncationStrategyType last_messages"`
	OpenAIMaxRequestsPerSecond           *int                       `json:"openai_max_requests_per_second,omitempty" binding:"omitnil,min=1,max=30000"`
	OpenAIMaxPromptTokens                *int                       `json:"openai_max_prompt_tokens,omitempty" binding:"omitnil,min=256"`
	OpenAIMaxCompletionTokens            *int                       `json:"openai_max_completion_tokens,omitempty" binding:"omitnil,min=0"`
	AssistantPollInterval                *Duration                  `json:"assistant_poll_interval,omitempty"`
	AssistantMaxPollInterval             *Duration                  `json:"assistant_max_poll_interval,omitempty"`
	AssistantInstructions                *string                    `json:"assistant_instructions,omitempty"`
	AssistantAdditionalInstructions      *string                    `json:"assistant_additional_instructions,omitempty"`
	AssistantTemperature                 *float32                   `json:"assistant_temperature,omitempty" binding:"omitnil,min=0,max=2"`

	UserChatCommandLimit6h *int `json:"user_chat_command_limit_6h,omitempty" binding:"omitnil,min=1"`

	LogLevel               *DBLogLevel `json:"log_level,omitempty" binding:"omitnil,oneof=INFO WARN ERROR DEBUG"`
	OpenAILogLevel         *DBLogLevel `json:"openai_log_level,omitempty" binding:"omitnil,oneof=INFO WARN ERROR DEBUG"`
	DiscordLogLevel        *DBLogLevel `json:"discord_log_level,omitempty" binding:"omitnil,oneof=INFO WARN ERROR DEBUG"`
	DiscordGoLogLevel      *DBLogLevel `json:"discordgo_log_level,omitempty" binding:"omitnil,oneof=INFO WARN ERROR DEBUG"`
	DatabaseLogLevel       *DBLogLevel `json:"database_log_level,omitempty" binding:"omitnil,oneof=INFO WARN ERROR DEBUG"`
	DiscordWebhookLogLevel *DBLogLevel `json:"discord_webhook_log_level,omitempty" binding:"omitnil,oneof=INFO WARN ERROR DEBUG"`
	APILogLevel            *DBLogLevel `json:"api_log_level,omitempty" binding:"omitnil,oneof=INFO WARN ERROR DEBUG"`
}

func validateRuntimeUpdateLimits(field reflect.Value) any {
	if value, ok := field.Interface().(RuntimeConfigUpdate); ok {
		if value.AssistantPollInterval != nil {
			pollDuration := *value.AssistantPollInterval
			if pollDuration.Duration < 100*time.Millisecond {
				return fmt.Errorf("poll interval must be at least 100ms")
			}
			if pollDuration.Duration > 60*time.Second {
				return fmt.Errorf("poll interval must be at most 60s")
			}
		}

		if value.AssistantMaxPollInterval != nil {
			maxDuration := *value.AssistantMaxPollInterval
			if maxDuration.Duration < 100*time.Millisecond {
				return fmt.Errorf("max poll interval must be at least 100ms")
			}
		}

		if value.AssistantMaxPollInterval != nil && value.AssistantPollInterval != nil {
			assistantPollInterval := *value.AssistantPollInterval
			maxInterval := *value.AssistantMaxPollInterval
			if maxInterval.Duration < assistantPollInterval.Duration {
				return "assistant_max_poll_interval must be >= assistant_poll_interval"
			}
		}
	}
	return nil
}

func (b RuntimeConfigUpdate) validate() error {
	err := structValidator.Struct(b)
	return err
}

func getDiscordPresenceStatusUpdate(config RuntimeConfig) discordgo.GatewayStatusUpdate {
	if config.Paused {
		return discordgo.GatewayStatusUpdate{
			AFK:    true,
			Status: string(discordgo.StatusDoNotDisturb),
		}
	}
	return discordgo.GatewayStatusUpdate{Status: config.DiscordCustomStatus}
}
