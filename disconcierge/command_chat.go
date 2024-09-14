package disconcierge

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"github.com/bwmarrin/discordgo"
	"github.com/lmittmann/tint"
	openai "github.com/sashabaranov/go-openai"
	"gorm.io/gorm"
	"log/slog"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	ChatCommandStateReceived    ChatCommandState = "received"
	ChatCommandStateQueued      ChatCommandState = "queued"
	ChatCommandStateInProgress  ChatCommandState = "in_progress"
	ChatCommandStateCompleted   ChatCommandState = "completed"
	ChatCommandStateFailed      ChatCommandState = "failed"
	ChatCommandStateExpired     ChatCommandState = "expired"
	ChatCommandStateIgnored     ChatCommandState = "ignored"
	ChatCommandStateRateLimited ChatCommandState = "rate_limited"
	ChatCommandStateAborted     ChatCommandState = "aborted"
)

const (
	ChatCommandStepEnqueue         ChatCommandStep = "enqueue"
	ChatCommandStepCreatingThread  ChatCommandStep = "creating_thread"
	ChatCommandStepCreatingMessage ChatCommandStep = "creating_message"
	ChatCommandStepCreatingRun     ChatCommandStep = "creating_run"
	ChatCommandStepPollingRun      ChatCommandStep = "polling_run"
	ChatCommandStepListMessage     ChatCommandStep = "list_message"
	ChatCommandStepFeedbackOpen    ChatCommandStep = "feedback_open"
	ChatCommandStepFeedbackClosed  ChatCommandStep = "feedback_closed"
)

var (
	chatCommandPollRunStatusMaxErrors = 5
)

//goland:noinspection GoLinter
var (
	columnChatCommandState                 = "state"
	columnChatCommandStep                  = "step"
	columnChatCommandRunStatus             = "run_status"
	columnChatCommandThreadID              = "thread_id"
	columnChatCommandMessageID             = "message_id"
	columnChatCommandRunID                 = "run_id"
	columnChatCommandResponse              = "response"
	columnChatCommandError                 = "error"
	columnChatCommandStartedAt             = "started_at"
	columnChatCommandFinishedAt            = "finished_at"
	columnChatCommandUsagePromptTokens     = "usage_prompt_tokens"
	columnChatCommandUsageCompletionTokens = "usage_completion_tokens"
	columnChatCommandUsageTotalTokens      = "usage_total_tokens"
	columnChatCommandAttempts              = "attempts"
	columnChatCommandPriority              = "priority"
	columnChatCommandAcknowledged          = "acknowledged"
	columnChatCommandClear                 = "private"
	columnChatCommandInteractionID         = "interaction_id"
	columnChatCommandContext               = "command_context"
	columnChatCommandPrompt                = "prompt"
	columnChatCommandID                    = "id"

	columnChatCommandButtonStateGood         = "feedback_button_state_good"
	columnChatCommandButtonStateOutdated     = "feedback_button_state_outdated"
	columnChatCommandButtonStateHallucinated = "feedback_button_state_hallucinated"
	columnChatCommandButtonStateOther        = "feedback_button_state_other"
	columnChatCommandButtonStateUndo         = "feedback_button_state_reset"

	columnChatCommandDiscordMessageID = "discord_message_id"
	columnUserID                      = "user_id"
	columnChatCommandCreatedAt        = "created_at"
)

// ChatCommandState is the current or final processing state for an ChatCommand
type ChatCommandState string

// IsFinal returns true if the ChatCommandState is one in which a ChatCommand
// should not be executed (completed, failed, expired, ignored, rate limited,
// aborted, ...)
func (s ChatCommandState) IsFinal() bool {
	switch s {
	case ChatCommandStateCompleted:
		return true
	case ChatCommandStateFailed:
		return true
	case ChatCommandStateExpired:
		return true
	case ChatCommandStateIgnored:
		return true
	case ChatCommandStateRateLimited:
		return true
	case ChatCommandStateAborted:
		return true
	default:
		return false
	}
}

// IsProcessing returns true if the ChatCommandState is in a 'non-final'
// state- either it's been received, is currently queued, or in progress.
func (s ChatCommandState) IsProcessing() bool {
	switch s {
	case ChatCommandStateReceived:
		return true
	case ChatCommandStateQueued:
		return true
	case ChatCommandStateInProgress:
		return true
	default:
		return false
	}
}

// StopProcessing returns true if the ChatCommandState is one that indicates
// a ChatCommand should either not be executed, or execution should stop
// (rate limited, aborted, ignored, expired, failed...)
func (s ChatCommandState) StopProcessing() bool {
	switch s {
	case ChatCommandStateRateLimited:
		return true
	case ChatCommandStateAborted:
		return true
	case ChatCommandStateIgnored:
		return true
	case ChatCommandStateExpired:
		return true
	case ChatCommandStateFailed:
		return true
	default:
		return false
	}
}

func (s ChatCommandState) String() string {
	return string(s)
}

// ChatCommandStep reflects an execution step in the ChatCommand
type ChatCommandStep string

func (s ChatCommandStep) String() string {
	return string(s)
}

// CommandOptions defines the runtime execution config for slash commands
//
//nolint:lll // struct tags can't be split
type CommandOptions struct {
	OpenAIRunSettings

	// RecoverPanic determines whether the bot should recover from panics
	// while processing user commands
	RecoverPanic bool `json:"recover_panic" gorm:"not null;default:true"`

	// Error message to send to the user if an error is encountered during
	// their command execution, which prevents the command from finishing normally
	DiscordErrorMessage string `json:"discord_error_message" gorm:"type:string"`

	// Message sent to the user if they've exceeded their rate limit, or
	// if they send a command while one is already in progress
	DiscordRateLimitMessage string `json:"discord_rate_limit_message" gorm:"type:string"`

	// If specified, the bot will send certain events to the specified channel,
	// such as errors, when a new user is seen, when a user hits their rate
	// limit, when the bot connects, etc.
	DiscordNotificationChannelID string `json:"discord_notification_channel_id" gorm:"type:string"`

	// FeedbackEnabled determines if user feedback functionality is enabled.
	FeedbackEnabled bool `gorm:"default:true" json:"feedback_enabled"`

	// FeedbackModalInputLabel is the label for the feedback input in the modal.
	FeedbackModalInputLabel string `json:"feedback_modal_input_label" gorm:"default:Feedback;size:45" binding:"min=0,max=45"`

	// FeedbackModalPlaceholder is the placeholder text for the feedback input.
	FeedbackModalPlaceholder string `json:"feedback_modal_placeholder" gorm:"default:Please provide feedback" binding:"min=0,max=100"`

	// FeedbackModalMinLength is the minimum length for feedback text.
	FeedbackModalMinLength int `json:"feedback_modal_min_length" gorm:"default:5" binding:"min=0,max=4000"`

	// FeedbackModalMaxLength is the maximum length for feedback text.
	FeedbackModalMaxLength int `json:"feedback_modal_max_length" gorm:"default:4000" binding:"gtfield=FeedbackModalMinLength,min=0,max=4000"`

	// FeedbackModalTitle is the title of the feedback modal.
	FeedbackModalTitle string `json:"feedback_modal_title" gorm:"default:Report an issue"`

	// If 0, the command will be attempted indefinitely.
	//
	// If 1, the command will not be retried. In the event of a crash/restart,
	// this will only attempt to resume commands that were in ChatCommandStateReceived
	// or ChatCommandStateQueued states, and had no previous attempts.
	ChatCommandMaxAttempts int `json:"chat_command_max_attempts" gorm:"default:3" binding:"min=0"`
}

//nolint:lll // can't break tags
type OpenAIRunSettings struct {
	// OpenAITruncationStrategyType is the type of truncation strategy for OpenAI requests.
	OpenAITruncationStrategyType openai.TruncationStrategy `gorm:"column:openai_truncation_strategy_type" json:"openai_truncation_strategy_type"  binding:"omitempty,oneof=auto last_messages"`

	// OpenAITruncationStrategyLastMessages is the number of messages to keep when truncating.
	OpenAITruncationStrategyLastMessages int `gorm:"column:openai_truncation_strategy_last_messages;default:3" json:"openai_truncation_strategy_last_messages"  binding:"required_if=OpenAITruncationStrategyType last_messages,min=0"`

	// OpenAIMaxPromptTokens is the maximum number of tokens allowed in a prompt.
	OpenAIMaxPromptTokens int `gorm:"column:openai_max_prompt_tokens;check:openai_max_prompt_tokens = 0 OR openai_max_prompt_tokens >= 256" json:"openai_max_prompt_tokens"  binding:"omitempty,min=256"`

	// OpenAIMaxCompletionTokens is the maximum number of tokens allowed in a completion.
	OpenAIMaxCompletionTokens int `gorm:"column:openai_max_completion_tokens;check:openai_max_completion_tokens >= 0" json:"openai_max_completion_tokens" binding:"min=0"`

	// AssistantPollInterval is the interval for polling the OpenAI assistant.
	AssistantPollInterval Duration `gorm:"column:assistant_poll_interval;default:'3s'" json:"assistant_poll_interval"`

	// AssistantMaxPollInterval is the maximum interval for polling the OpenAI assistant.
	AssistantMaxPollInterval Duration `gorm:"column:assistant_max_poll_interval;default:'30s'" json:"assistant_max_poll_interval"`

	// AssistantInstructions overrides the instructions of the assistant
	AssistantInstructions string `json:"assistant_instructions"`

	// AssistantAdditionalInstructions are additional instructions for the OpenAI assistant.
	AssistantAdditionalInstructions string `json:"assistant_additional_instructions"`

	// AssistantTemperature is the temperature setting for the OpenAI assistant.
	AssistantTemperature float32 `gorm:"default:1;check:assistant_temperature >= 0 AND assistant_temperature <= 2" json:"assistant_temperature" binding:"min=0,max=2"`
}

// ChatCommand is a single `/chat` or `/private` slash command.
//
// When DisConcierge receives a new interaction for these slash commands,
// a new ChatCommand record is created with State set to ChatCommandStateReceived.
//
// When the bot starts, it queries for existing ChatCommand records where
// either:
//   - State is ChatCommandStateReceived, ChatCommandStateQueued, or ChatCommandStateInProgress
//   - RunStatus is [openai.RunStatusInProgress] or [openai.RunStatusQueued]
//
// Commands matching one of those criteria are then attempted to be resumed.
// If Attempts has met or exceeded Config.ChatCommandMaxAttempts, and
// max attempts > 0, State will be set ChatCommandStateAborted.
//
//goland:noinspection GoMixedReceiverTypes
//nolint:lll // struct tags can't be split
type ChatCommand struct {
	ModelUintID
	ModelUnixTime
	Interaction

	// State is the overall execution state of this command.
	// If this is ChatCommandStateQueued when the bot starts,
	// and TokenExpires
	// If this is ChatCommandStateInProgress when the bot starts,
	//
	State ChatCommandState `json:"state" gorm:"type:string"`

	// Step is the current, or most recent step in the command
	// execution (such as where the bot stopped execution,
	// such as due to a failure or a restart)
	Step ChatCommandStep `json:"step" gorm:"type:string"`

	// Prompt is the value of the 'question' option in from the
	// discord interaction. This is the question (or just
	// general statement) from the user.
	Prompt string `json:"prompt" gorm:"type:string"`

	// Private indicates this is a `/private` command, so
	// responses should be ephemeral.
	Private bool `json:"private" gorm:"type:bool"`

	// ThreadID is the OpenAI thread ID associated with this request.
	// This may or may not be unique - a new thread is started either
	// on the first request ever seen from the user, or the first
	// request seen after the user uses the `/clear` command.
	ThreadID string `json:"thread_id" gorm:"type:string"`

	// MessageID is the OpenAI message ID associated with
	// this request.
	MessageID string `json:"message_id" gorm:"type:string"`

	// RunID is the OpenAI run ID associated with this thread
	RunID string `json:"run_id" gorm:"type:string"`

	// RunStatus is the most recently seen OpenAI run status for
	// RunID
	RunStatus openai.RunStatus `json:"run_status" gorm:"type:string"`

	Priority bool `json:"priority" gorm:"type:bool"`

	// Attempts is the number of times this command has had an execution
	// attempt. This only increments when the command is first executed,
	// or when an attempt is made to resume command upon starting the
	// bot (either after a crash, or a normal restart).
	// If this number is >2, it may mean the command is causing
	// the bot to crash midway through executing the command, in which
	// case you may want to consider enabling [Config.RecoverPanic]
	Attempts int `json:"attempts" gorm:"type:int"`

	UsagePromptTokens     int `json:"usage_prompt_tokens,omitempty"`
	UsageCompletionTokens int `json:"usage_completion_tokens,omitempty"`
	UsageTotalTokens      int `json:"usage_total_tokens,omitempty"`

	// CustomID is a random 25-character string we generate for each
	// interaction, and is used as part of message component custom IDs,
	// so we know which button was clicked and for which command
	CustomID string `json:"custom_id" gorm:"index"`

	// Discord button states
	FeedbackButtonStateGood         FeedbackButtonState `json:"feedback_button_state_good" gorm:"type:int;check:feedback_button_state_good >= 0 AND feedback_button_state_good <= 2;default:0"`
	FeedbackButtonStateOutdated     FeedbackButtonState `json:"feedback_button_state_outdated" gorm:"type:int;check:feedback_button_state_outdated >= 0 AND feedback_button_state_outdated <= 2;default:0"`
	FeedbackButtonStateHallucinated FeedbackButtonState `json:"feedback_button_state_hallucinated" gorm:"type:int;check:feedback_button_state_hallucinated >= 0 AND feedback_button_state_hallucinated <= 2;default:0"`
	FeedbackButtonStateOther        FeedbackButtonState `json:"feedback_button_state_other" gorm:"type:int;check:feedback_button_state_other >= 0 AND feedback_button_state_other <= 2;default:0"`
	FeedbackButtonStateReset        FeedbackButtonState `json:"feedback_button_state_reset" gorm:"type:int;check:feedback_button_state_reset = 0 OR feedback_button_state_reset = 1;default:0"`

	UserFeedback []UserFeedback `gorm:"->"`

	index   int
	mu      *sync.RWMutex
	handler InteractionHandler
}

// NewChatCommand creates a new ChatCommand instance, and any error
// encountered during creation.
func NewChatCommand(u *User, i *discordgo.InteractionCreate) (
	rec *ChatCommand, err error,
) {
	if u == nil {
		return nil, errors.New("user required")
	}
	interaction := NewUserInteraction(i, u)
	rec = &ChatCommand{
		Interaction: *interaction,
		State:       ChatCommandStateReceived,
		mu:          &sync.RWMutex{},
	}
	rec.User = u
	rec.Priority = rec.User.Priority
	if rec.User.ThreadID != "" {
		rec.ThreadID = rec.User.ThreadID
	}

	if u.Ignored {
		rec.State = ChatCommandStateIgnored
	}

	optionMap := discordInteractionOptions(i)
	if opt, ok := optionMap[chatCommandQuestionOption]; ok {
		rec.Prompt = strings.TrimSpace(opt.StringValue())
	}

	randomID, err := generateRandomHexString(discordComponentCustomIDLength)
	rec.CustomID = randomID

	return rec, err
}

func (c *ChatCommand) Deadline() time.Time {
	return time.UnixMilli(c.TokenExpires).UTC()
}

// Answer performs the actual ChatCommand processing. At this point,
// we're actually making API requests.
// There are context checks between steps to ensure we stop in a
// 'clean' place, when we want to.
// For example, if you stop the bot, you don't want a request to
// move from ChatCommandStepCreatingThread, past ChatCommandStepCreatingRun -
// because the bot may be stopping to address a bug or issue, where we
// don't want to go ahead and incur cost from creating a run that may
// fail.
func (c *ChatCommand) Answer(ctx context.Context, d *DisConcierge) {
	req := c
	logger, ok := ContextLogger(ctx)
	if logger == nil || !ok {
		logger = d.logger
		if logger == nil {
			logger = slog.Default()
		}
		ctx = WithLogger(ctx, logger)
	}

	if ctx.Err() != nil {
		logger.WarnContext(ctx, "context canceled, aborting")
		return
	}

	if req.ThreadID == "" {
		_, err := getOrCreateThreadID(ctx, d, req)
		if err != nil {
			req.finalize(
				ctx,
				d,
				"",
				err,
			)
			return
		}
	}

	logger = logger.With(
		slog.Group(
			"chat_command",
			columnChatCommandThreadID,
			req.ThreadID,
		),
	)
	ctx = WithLogger(ctx, logger)

	if ctx.Err() != nil {
		logger.WarnContext(ctx, "context canceled, aborting")
		return
	}

	// POST /threads/{id}/messages
	// record under create_message_requests
	if req.MessageID == "" {
		logger.InfoContext(ctx, "message_id blank, creating a new message")
		msgID, err := d.openai.CreateMessage(ctx, d.writeDB, req)
		if msgID == "" && err == nil {
			err = errors.New("did not receive a message id")
		}
		if err != nil {
			req.finalize(ctx, d, "", err)
			return
		}
		if _, err = d.writeDB.Update(
			req,
			columnChatCommandMessageID,
			msgID,
		); err != nil {
			req.finalize(
				ctx,
				d,
				"",
				fmt.Errorf("error updating message_id: %w", err),
			)
			return
		}
	} else {
		logger.InfoContext(
			ctx,
			fmt.Sprintf(
				"existing message '%s' found, skipping message creation",
				req.MessageID,
			),
		)
	}

	logger = logger.With(
		slog.Group(
			"chat_command",
			columnChatCommandMessageID,
			req.MessageID,
		),
	)
	ctx = WithLogger(ctx, logger)

	if ctx.Err() != nil {
		logger.WarnContext(ctx, "context canceled, aborting")
		return
	}

	// POST /threads/{threadID}/runs
	// record OpenAICreateRunRequest
	if req.RunID == "" {
		logger.InfoContext(
			ctx,
			fmt.Sprintf(
				"no run_id found, creating new run for thread_id '%s', message_id '%s'",
				req.ThreadID,
				req.MessageID,
			),
		)
		run, err := d.openai.CreateRun(ctx, d.writeDB, req)

		if err != nil {
			req.finalize(ctx, d, "", err)
			return
		}
		if _, err = d.writeDB.Updates(
			req, map[string]any{
				columnChatCommandRunID:     run.ID,
				columnChatCommandRunStatus: run.Status,
			},
		); err != nil {
			req.finalize(
				ctx,
				d,
				"",
				fmt.Errorf("error updating run_id: %w", err),
			)
		}
	} else {
		logger.InfoContext(
			ctx,
			fmt.Sprintf(
				"existing run_id '%s' found, skipping run creation",
				req.RunID,
			),
		)
	}
	logger = logger.With(
		slog.Group(
			"chat_command",
			columnChatCommandRunID,
			req.RunID,
		),
	)
	ctx = WithLogger(ctx, logger)

	if ctx.Err() != nil {
		logger.WarnContext(ctx, "context canceled, aborting")
		return
	}

	req.executeFromPollingRun(ctx, d)
}

// OtherButton returns a Discord button for the "Other" feedback option.
func (c *ChatCommand) OtherButton() *discordgo.Button {
	if c.CustomID == "" {
		return nil
	}
	if c.FeedbackButtonStateOther == FeedbackButtonStateHidden {
		return nil
	}

	return &discordgo.Button{
		Label:    feedbackTypeDescription[UserFeedbackOther],
		Style:    discordgo.DangerButton,
		Disabled: c.FeedbackButtonStateOther == FeedbackButtonStateDisabled,
		CustomID: fmt.Sprintf(
			customIDFormat,
			UserFeedbackOther,
			c.CustomID,
		),
	}
}

// GoodButton returns a Discord button for the "Good" feedback option.
func (c *ChatCommand) GoodButton() *discordgo.Button {
	if c.CustomID == "" {
		return nil
	}
	if c.FeedbackButtonStateGood == FeedbackButtonStateHidden {
		return nil
	}

	return &discordgo.Button{
		Style: discordgo.SuccessButton,
		Emoji: &discordgo.ComponentEmoji{
			Name: "👍",
		},
		Disabled: c.FeedbackButtonStateGood == FeedbackButtonStateDisabled,
		CustomID: fmt.Sprintf(
			customIDFormat,
			UserFeedbackGood,
			c.CustomID,
		),
	}
}

// HallucinatedButton returns a Discord button for the "Hallucinated" feedback option.
func (c *ChatCommand) HallucinatedButton() *discordgo.Button {
	if c.CustomID == "" {
		return nil
	}
	if c.FeedbackButtonStateHallucinated == FeedbackButtonStateHidden {
		return nil
	}

	return &discordgo.Button{
		Label:    feedbackTypeDescription[UserFeedbackHallucinated],
		Style:    discordgo.DangerButton,
		Disabled: c.FeedbackButtonStateHallucinated == FeedbackButtonStateDisabled,
		CustomID: fmt.Sprintf(
			customIDFormat,
			UserFeedbackHallucinated,
			c.CustomID,
		),
	}
}

// OutdatedButton returns a Discord button for the "Outdated" feedback option.
func (c *ChatCommand) OutdatedButton() *discordgo.Button {
	if c.CustomID == "" {
		return nil
	}
	if c.FeedbackButtonStateOutdated == FeedbackButtonStateHidden {
		return nil
	}

	return &discordgo.Button{
		Label:    feedbackTypeDescription[UserFeedbackOutdated],
		Style:    discordgo.DangerButton,
		Disabled: c.FeedbackButtonStateOutdated == FeedbackButtonStateDisabled,
		CustomID: fmt.Sprintf(
			customIDFormat,
			UserFeedbackOutdated,
			c.CustomID,
		),
	}
}

// UndoButton returns a Discord button for the "Undo" action.
func (c *ChatCommand) UndoButton() *discordgo.Button {
	if c.CustomID == "" {
		return nil
	}
	if c.FeedbackButtonStateReset == FeedbackButtonStateHidden {
		return nil
	}

	return &discordgo.Button{
		Style: discordgo.SecondaryButton,
		Label: feedbackTypeDescription[UserFeedbackReset],
		CustomID: fmt.Sprintf(
			customIDFormat,
			UserFeedbackReset,
			c.CustomID,
		),
	}
}

// responseEditWithButtons edits a response message with buttons in a Discord interaction.
//
// Parameters:
//   - ctx: The context for managing the lifecycle of the request.
//   - content: The content of the response message to be sent.
//   - reportComponents: A pointer to a slice of discordgo.MessageComponent
//     representing the buttons to be included in the response.
//   - requestOptions: Variadic arguments for additional request options to
//     pass to discordgo.Session.
//
// Returns:
//   - error: An error if the response message could not be edited.
func (c *ChatCommand) responseEditWithButtons(
	ctx context.Context,
	content string,
	reportComponents *[]discordgo.MessageComponent,
	requestOptions ...discordgo.RequestOption,
) error {
	logger, ok := ContextLogger(ctx)
	if logger == nil || !ok {
		logger = slog.Default()
		ctx = WithLogger(ctx, logger)
	}
	logger.InfoContext(ctx, "response message", "msg", content)
	start := time.Now()
	defer func() {
		finished := time.Now()
		logger.InfoContext(
			ctx,
			"response edit",
			"started", start,
			"ended", finished,
			"duration", finished.Sub(start),
		)
	}()
	_, err := c.handler.Edit(
		ctx,
		&discordgo.WebhookEdit{
			Content:    &content,
			Components: reportComponents,
		},
		requestOptions...,
	)
	return err
}

// createReport creates a new UserFeedback instance based on the
// provided report type and detail.
func (c *ChatCommand) createReport(reportType FeedbackButtonType, detail string) UserFeedback {
	return UserFeedback{
		ChatCommandID: &c.ID,
		UserID:        &c.UserID,
		Description:   feedbackTypeDescription[reportType],
		Type:          string(reportType),
		Detail:        detail,
		CustomID:      c.CustomID,
	}
}

// setButtonStates updates the current state of all buttons and their
// components, based on the given report type.
func (c *ChatCommand) setButtonStates(reportType FeedbackButtonType) error {
	switch reportType {
	case UserFeedbackReset:
		c.setFreshButtonStates()
	case UserFeedbackGood:
		c.FeedbackButtonStateGood = FeedbackButtonStateDisabled
		c.FeedbackButtonStateOutdated = FeedbackButtonStateHidden
		c.FeedbackButtonStateHallucinated = FeedbackButtonStateHidden
		c.FeedbackButtonStateOther = FeedbackButtonStateHidden
		c.FeedbackButtonStateReset = FeedbackButtonStateEnabled
	case UserFeedbackOutdated:
		c.FeedbackButtonStateOutdated = FeedbackButtonStateDisabled
		c.FeedbackButtonStateReset = FeedbackButtonStateEnabled
		c.FeedbackButtonStateGood = FeedbackButtonStateHidden
	case UserFeedbackHallucinated:
		c.FeedbackButtonStateHallucinated = FeedbackButtonStateDisabled

		c.FeedbackButtonStateGood = FeedbackButtonStateHidden
		c.FeedbackButtonStateReset = FeedbackButtonStateEnabled

		if c.FeedbackButtonStateOutdated == FeedbackButtonStateHidden {
			c.FeedbackButtonStateOutdated = FeedbackButtonStateEnabled
		}

		if c.FeedbackButtonStateOther == FeedbackButtonStateHidden {
			c.FeedbackButtonStateOther = FeedbackButtonStateEnabled
		}

	case UserFeedbackOther:
		c.FeedbackButtonStateOther = FeedbackButtonStateDisabled
		c.FeedbackButtonStateGood = FeedbackButtonStateHidden
		c.FeedbackButtonStateReset = FeedbackButtonStateEnabled

		if c.FeedbackButtonStateOutdated == FeedbackButtonStateHidden {
			c.FeedbackButtonStateOutdated = FeedbackButtonStateEnabled
		}

		if c.FeedbackButtonStateHallucinated == FeedbackButtonStateHidden {
			c.FeedbackButtonStateHallucinated = FeedbackButtonStateEnabled
		}
	default:
		return fmt.Errorf("unknown report type: %s", reportType)
	}
	return nil
}

// setButtons sets the current button states, components and updates the
// current interaction based on the given UserFeedback records.
// If no reports are provided, a 'fresh' state will be set (the default new state).
// The overall state is set on a per-report basis, in order - so in the off
// chance a UserFeedbackGood is provided along with a UserFeedbackOutdated, the state
// set by UserFeedbackOutdated will be the final state.
func (c *ChatCommand) setButtons(
	ctx context.Context,
	reports ...UserFeedback,
) error {
	logger, ok := ContextLogger(ctx)
	if logger == nil || !ok {
		logger = slog.Default()
		ctx = WithLogger(ctx, logger)
	}

	if time.Now().UTC().UnixMilli() >= c.TokenExpires {
		logger.WarnContext(ctx, "token expired, ignoring")
		c.setExpiredButtonStates()
		return nil
	}

	if len(reports) == 0 {
		c.setFreshButtonStates()
	} else {
		for _, report := range reports {
			if err := c.setButtonStates(FeedbackButtonType(report.Type)); err != nil {
				return err
			}
		}
	}

	buttons := c.discordUserFeedbackComponents()

	var errs []error
	_, updErr := c.handler.Edit(
		ctx,
		&discordgo.WebhookEdit{
			Components: &buttons,
		},
	)
	if updErr != nil {
		logger.ErrorContext(
			ctx,
			"error updating interaction response",
			tint.Err(updErr),
		)
		errs = append(errs, updErr)
	}

	return errors.Join(errs...)
}

// newDMReport handles UserFeedback creation.
// If this is an 'undo' action, it's subject to maxUndo as a limit (0=unlimited).
//
// If FeedbackButtonType is UserFeedbackGood or UserFeedbackReset, all existing
// UserFeedback records will be soft-deleted. So UserFeedbackGood will remove an
// existing UserFeedbackOutdated, for example.
//
// UserFeedbackHallucinated, UserFeedbackOutdated, and UserFeedbackOther will remove
// any existing report that is not one of those three report types.
//
// This will also update the ChatCommand record, and attempt to update
// the discord interaction to reflect new button states.
func (c *ChatCommand) newDMReport(
	ctx context.Context,
	db DBI,
	report *UserFeedback,
) error {
	logger, ok := ContextLogger(ctx)
	if logger == nil || !ok {
		logger = slog.Default()
		ctx = WithLogger(ctx, logger)
	}

	var errs []error

	if err := db.CreateReport(ctx, report); err != nil {
		logger.ErrorContext(
			ctx,
			"error creating report",
			tint.Err(err),
			slog.Any("report", report),
		)
		errs = append(
			errs,
			fmt.Errorf("error creating/deleting report records: %w", err),
		)
		return errors.Join(errs...)
	}
	existingReports, err := c.getReports(ctx, db.DB())
	if err != nil {
		errs = append(errs, err)
		return errors.Join(errs...)
	}
	logger.InfoContext(
		ctx,
		fmt.Sprintf("Found %d existing reports", len(existingReports)),
	)
	for _, r := range existingReports {
		logger.DebugContext(ctx, "existing report", "report", r)
	}

	err = c.setButtons(ctx, existingReports...)
	if err != nil {
		errs = append(errs, err)
	}
	_, err = db.Updates(
		c,
		map[string]any{
			columnChatCommandButtonStateGood:         c.FeedbackButtonStateGood,
			columnChatCommandButtonStateOutdated:     c.FeedbackButtonStateOutdated,
			columnChatCommandButtonStateHallucinated: c.FeedbackButtonStateHallucinated,
			columnChatCommandButtonStateOther:        c.FeedbackButtonStateOther,
			columnChatCommandButtonStateUndo:         c.FeedbackButtonStateReset,
		},
	)
	errs = append(errs, err)
	return errors.Join(errs...)
}

// discordUserFeedbackComponents returns a discordgo.MessageComponent slice, including
// any non-nil buttons. Nil buttons indicate the button should not be included in the
// final message components.
func (c *ChatCommand) discordUserFeedbackComponents() []discordgo.MessageComponent {
	// TODO check if BOT_DM or home guild
	buttons := make([]discordgo.MessageComponent, 0, discordMaxButtonsPerActionRow)

	goodButton := c.GoodButton()
	otherButton := c.OtherButton()
	hallucinatedButton := c.HallucinatedButton()
	outdatedButton := c.OutdatedButton()
	undoButton := c.UndoButton()

	if goodButton != nil {
		buttons = append(
			buttons,
			*goodButton,
		)
	}

	if outdatedButton != nil {
		buttons = append(buttons, *outdatedButton)
	}
	if hallucinatedButton != nil {
		buttons = append(buttons, *hallucinatedButton)
	}
	if otherButton != nil {
		buttons = append(buttons, *otherButton)
	}

	if undoButton != nil {
		buttons = append(buttons, *undoButton)
	}

	rows := chunkItems(discordMaxButtonsPerActionRow, buttons...)
	messageComponent := make([]discordgo.MessageComponent, 0, len(rows))

	for _, r := range rows {
		messageComponent = append(
			messageComponent,
			discordgo.ActionsRow{Components: r},
		)
	}
	return messageComponent
}

// undoReportCount returns the number of 'undo' actions for this command
// func (c *ChatCommand) undoReportCount(db *gorm.DB) (int64, error) {
// 	var previousUndo int64
//
// 	ctErr := db.Model(&UserFeedback{}).Unscoped().Where(
// 		"user_id = ? AND custom_id = ? AND type = ?",
// 		c.UserID,
// 		c.CustomID,
// 		string(UserFeedbackReset),
// 	).Count(&previousUndo).Error
// 	return previousUndo, ctErr
// }

func (c *ChatCommand) setAbandoned(
	ctx context.Context,
	log *slog.Logger,
	d *DisConcierge,
) {
	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, updErr := d.writeDB.Update(
			c,
			columnChatCommandState, ChatCommandStateAborted,
		); updErr != nil {
			log.ErrorContext(
				ctx,
				"error updating attempts",
				tint.Err(updErr),
			)
		}
	}()

	if c.handler != nil && c.TokenExpires > time.Now().UTC().UnixMilli() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			config := c.handler.Config()
			if _, editErr := c.handler.Edit(
				ctx,
				&discordgo.WebhookEdit{Content: &config.DiscordErrorMessage},
			); editErr != nil {
				log.ErrorContext(
					ctx,
					"error editing interaction",
					tint.Err(editErr),
				)
			}
		}()
	}
	wg.Wait()
}

// handleError handles errors that occur during the execution of a ChatCommand.
//
// This function increments the attempt count for the command and checks if the
// maximum number of attempts has been reached. If the maximum attempts are exceeded,
// it updates the command state to aborted and sends an error message to the user.
func (c *ChatCommand) handleError(ctx context.Context, d *DisConcierge) {
	log, ok := ContextLogger(ctx)
	if !ok || log == nil {
		log = d.logger
		if log == nil {
			log = slog.Default()
		}
		log = log.With("chat_command", c)
		ctx = WithLogger(ctx, log)
	}
	attempts := c.Attempts + 1
	maxAttempts := c.handler.Config().ChatCommandMaxAttempts
	if maxAttempts > 0 && attempts >= maxAttempts {
		wg := &sync.WaitGroup{}

		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, updErr := d.writeDB.Updates(
				c,
				map[string]any{
					columnChatCommandAttempts: attempts,
					columnChatCommandState:    ChatCommandStateAborted,
				},
			); updErr != nil {
				log.ErrorContext(
					ctx,
					"error updating attempts",
					tint.Err(updErr),
				)
			}
		}()

		if c.handler != nil && c.TokenExpires > time.Now().UTC().UnixMilli() {
			wg.Add(1)
			go func() {
				defer wg.Done()
				config := c.handler.Config()
				if _, editErr := c.handler.Edit(
					ctx,
					&discordgo.WebhookEdit{Content: &config.DiscordErrorMessage},
				); editErr != nil {
					log.ErrorContext(
						ctx,
						"error editing interaction",
						tint.Err(editErr),
					)
				}
			}()
		}
		wg.Wait()
		return
	}

	if _, updErr := d.writeDB.Update(c, "attempts", attempts); updErr != nil {
		log.ErrorContext(
			ctx,
			"error updating attempts",
			tint.Err(updErr),
		)
	}
}

// newReportButtons creates and returns a slice of Discord message components
// representing feedback buttons for an ChatCommand.
//
// This method generates a set of buttons that allow users to provide feedback
// on the bot's response. The buttons include options for positive feedback,
// reporting outdated information, reporting hallucinations, and reporting other issues.
//
// The function creates a single ActionsRow containing four buttons:
// 1. A "thumbs up" button for positive feedback
// 2. A button to report outdated information
// 3. A button to report hallucinations or inaccuracies
// 4. A button for other types of feedback
//
// Each button is assigned a custom ID based on the ChatCommand's CustomID
// and the type of feedback it represents.
//
// Returns:
//   - []discordgo.MessageComponent: A slice containing a single ActionsRow
//     with the feedback buttons.
//
// Note: This method relies on the ChatCommand's CustomID field to generate
// unique identifiers for each button.
func (c *ChatCommand) newReportButtons() []discordgo.MessageComponent {
	customID := c.CustomID
	buttonComponents := []discordgo.MessageComponent{
		discordgo.Button{
			Style: discordgo.SuccessButton,
			Emoji: &discordgo.ComponentEmoji{
				Name: "👍",
			},
			CustomID: fmt.Sprintf(
				customIDFormat,
				UserFeedbackGood,
				customID,
			),
		},
		discordgo.Button{
			Label: feedbackTypeDescription[UserFeedbackOutdated],
			Style: discordgo.DangerButton,
			CustomID: fmt.Sprintf(
				customIDFormat,
				UserFeedbackOutdated,
				customID,
			),
		},
		discordgo.Button{
			Label: feedbackTypeDescription[UserFeedbackHallucinated],
			Style: discordgo.DangerButton,
			CustomID: fmt.Sprintf(
				customIDFormat,
				UserFeedbackHallucinated,
				customID,
			),
		},
		discordgo.Button{
			Label: feedbackTypeDescription[UserFeedbackOther],
			Style: discordgo.DangerButton,
			CustomID: fmt.Sprintf(
				customIDFormat,
				UserFeedbackOther,
				customID,
			),
		},
	}

	return []discordgo.MessageComponent{
		discordgo.ActionsRow{
			Components: buttonComponents,
		},
	}
}

// finalizeCompletedRun picks up after an openai.Run has been polled and
// is in a 'completed' state ([openai.RunStatusCompleted])
func (c *ChatCommand) finalizeCompletedRun(
	ctx context.Context,
	d *DisConcierge,
) {
	logger, ok := ContextLogger(ctx)
	if logger == nil || !ok {
		logger = d.logger
		if logger == nil {
			logger = slog.Default()
		}
		ctx = WithLogger(ctx, logger)
	}

	responseMsg, err := d.openai.getMessageResponse(ctx, d.writeDB, c)
	if err != nil {
		logger.ErrorContext(
			ctx,
			"error getting message response",
			tint.Err(err),
			"response_msg", responseMsg,
		)
		if responseMsg == "" {
			c.finalize(ctx, d, responseMsg, err)
			return
		}
	}

	responseMsg = removeCitations(responseMsg)
	var suffixTag string

	usage, err := GetCommandUsagePrevious6h(ctx, d.db, c.User)
	if err != nil {
		logger.ErrorContext(
			ctx,
			"error getting command usage",
			tint.Err(err),
		)
	} else {
		go notifyDiscordUserReachedRateLimit(
			ctx,
			logger,
			d.discord,
			c.User,
			usage,
			c.Prompt,
			c.handler.Config().DiscordNotificationChannelID,
		)

		suffixTag = fmt.Sprintf(
			"\n%s",
			usage.UsageMessage(),
		)
	}
	responseMsg = removeCitations(responseMsg)

	responseMsg = minifyString(
		responseMsg,
		discordMaxMessageLength-len(suffixTag)-5,
	)
	responseMsg = fmt.Sprintf("%s\n%s", responseMsg, suffixTag)
	c.finalize(ctx, d, responseMsg, nil)
}

// enqueue performs some upfront checks on the ChatCommand, and in the
// happy path, pushes the command onto the queue. Otherwise, it will
// ignore or abort the request if:
// - [User.Ignored] is true
// - The bot is paused and this is not a priority user ([User.Priority])
func (c *ChatCommand) enqueue(ctx context.Context, d *DisConcierge) {
	userRequest := c

	wg := &sync.WaitGroup{}
	defer wg.Wait()

	logger := c.handler.Logger()
	logger.InfoContext(ctx, "starting command")

	switch {
	case userRequest.User.Ignored:
		userRequest.State = ChatCommandStateIgnored
	case d.paused.Load() && !userRequest.User.Priority:
		logger.Warn("paused and non-priority user, will not handle interaction")
		userRequest.State = ChatCommandStateIgnored
	}

	if userRequest.Prompt == "" && !userRequest.State.IsFinal() {
		userRequest.State = ChatCommandStateAborted
		userRequest.Error = "invalid prompt"
	}

	if userRequest.State == ChatCommandStateIgnored || userRequest.State == ChatCommandStateAborted {
		if userRequest.Acknowledged {
			wg.Add(1)
			go func() {
				defer wg.Done()
				logger.Warn("ignoring request, deleting original interaction")
				c.handler.Delete(ctx)
			}()
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := d.writeDB.ChatCommandUpdates(
				userRequest, map[string]any{
					columnChatCommandState:        userRequest.State,
					columnChatCommandError:        userRequest.Error,
					columnChatCommandAcknowledged: userRequest.Acknowledged,
					columnChatCommandResponse:     userRequest.Response,
				},
			); err != nil {
				logger.ErrorContext(
					ctx,
					"error saving chat_command record",
					tint.Err(err),
				)
			}
		}()
		wg.Wait()
		return
	}

	usage, err := GetCommandUsagePrevious6h(ctx, d.db, userRequest.User)

	if err != nil {
		config := userRequest.handler.Config()
		userRequest.State = ChatCommandStateFailed
		userRequest.Response = &config.DiscordErrorMessage
		userRequest.Error = NullableString(
			fmt.Sprintf(
				"error retrieving completed commands: %s",
				err.Error(),
			),
		)

		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = c.handler.Edit(
				ctx,
				&discordgo.WebhookEdit{Content: &config.DiscordErrorMessage},
			)
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := d.writeDB.ChatCommandUpdates(
				userRequest, map[string]any{
					columnChatCommandState:        userRequest.State,
					columnChatCommandError:        userRequest.Error,
					columnChatCommandAcknowledged: userRequest.Acknowledged,
					columnChatCommandResponse:     userRequest.Response,
				},
			); e != nil {
				logger.ErrorContext(
					ctx,
					"error saving chat_command record",
					tint.Err(e),
				)
			}
		}()

		wg.Wait()
		return
	}

	if usage.CommandsAvailable {
		logger.InfoContext(ctx, "usage details", "usage", usage)
	} else {
		logger.WarnContext(ctx, "no commands available")
		response := usage.UsageMessage()
		userRequest.State = ChatCommandStateRateLimited
		userRequest.Response = &response

		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = c.handler.Edit(
				ctx,
				&discordgo.WebhookEdit{Content: &response},
			)
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, dbErr := d.writeDB.ChatCommandUpdates(
				userRequest, map[string]any{
					"state":        userRequest.State,
					"error":        userRequest.Error,
					"acknowledged": userRequest.Acknowledged,
					"response":     userRequest.Response,
				},
			); dbErr != nil {
				logger.ErrorContext(
					ctx,
					"error saving chat_command record",
					tint.Err(dbErr),
				)
			}
		}()

		wg.Wait()
		return
	}

	logger.InfoContext(ctx, "pushing request to queue")
	err = d.requestQueue.Push(ctx, userRequest, d.writeDB)
	if err != nil {
		logger.ErrorContext(ctx, "error adding request to queue", tint.Err(err))
		newState := ChatCommandStateFailed
		if errors.Is(err, ErrChatCommandTooOld) {
			newState = ChatCommandStateExpired
		}
		if _, e := d.writeDB.ChatCommandUpdates(
			userRequest, map[string]any{
				columnChatCommandState:        newState,
				columnChatCommandError:        userRequest.Error,
				columnChatCommandAcknowledged: userRequest.Acknowledged,
				columnChatCommandResponse:     userRequest.Response,
			},
		); e != nil {
			logger.ErrorContext(
				ctx,
				"error saving chat_command record",
				tint.Err(e),
			)
		}
	}
}

// executeFromPollingRun starts/resumes execution of the ChatCommand
// from the ChatCommandStepPollingRun step. The openai run should have
// been created, but not yet finished (either successfully or with an error).
func (c *ChatCommand) executeFromPollingRun(
	ctx context.Context,
	d *DisConcierge,
) {
	logger, ok := ContextLogger(ctx)
	if logger == nil || !ok {
		logger = slog.Default()
		ctx = WithLogger(ctx, logger)
	}
	pollingInterval := c.User.AssistantPollInterval
	maxInterval := c.User.AssistantMaxPollInterval

	err := d.openai.pollUpdateRunStatus(
		ctx,
		d.writeDB,
		c,
		pollingInterval.Duration,
		maxInterval.Duration,
		chatCommandPollRunStatusMaxErrors,
	)
	if err != nil && errors.Is(err, ErrPollRunInterrupted) {
		logger.WarnContext(ctx, "polling run interrupted")
		return
	}
	if err != nil && errors.Is(err, ErrPollRunMaxErrorsExceeded) {
		logger.ErrorContext(ctx, "max errors encountered", tint.Err(err))
		c.finalize(ctx, d, "", err)
		return
	}

	switch c.RunStatus {
	case openai.RunStatusCompleted:
		c.finalizeCompletedRun(ctx, d)
	case openai.RunStatusIncomplete:
		fallthrough
	case openai.RunStatusRequiresAction:
		fallthrough
	case openai.RunStatusExpired:
		fallthrough
	case openai.RunStatusCancelling:
		fallthrough
	case openai.RunStatusCancelled:
		fallthrough
	case openai.RunStatusFailed:
		c.finalize(
			ctx,
			d,
			"",
			fmt.Errorf("run status: %s", c.RunStatus),
		)
	case openai.RunStatusQueued, openai.RunStatusInProgress:
		logger.WarnContext(ctx, "exiting while still in progress")
	default:
		logger.WarnContext(
			ctx,
			fmt.Sprintf(
				"unknown run status or didn't finish (state: %s step: %s run_status: %s",
				c.State,
				c.Step,
				c.RunStatus,
			),
			columnChatCommandRunStatus,
			c.RunStatus,
		)
	}
	if err != nil {
		logger.ErrorContext(ctx, "error polling run status", tint.Err(err))
		c.finalize(ctx, d, "", err)
		return
	}
}

// finalizeWithError handles the finalization of a ChatCommand when an error occurs.
// It updates the ChatCommand state to failed, sets the error message, and performs
// necessary cleanup tasks.
//
// The function does the following:
// 1. Updates the ChatCommand state to ChatCommandStateFailed in the database.
// 2. Sets the response to the default error message from the handler's configuration.
// 3. Stores the error message in the ChatCommand's Error field.
// 4. Updates the FinishedAt timestamp.
// 5. Edits the Discord interaction response with the error message.
// 6. Notifies the Discord channel about the error if a notification channel is configured.
//
// Parameters:
//   - ctx: The context for the operation, which may include cancellation signals.
//   - d: A pointer to the DisConcierge instance, providing access to the database
//     and Discord integration.
//   - err: The error that occurred during the ChatCommand execution.
//
// The function uses goroutines to perform database updates and Discord notifications
// concurrently, improving performance for error handling.
func (c *ChatCommand) finalizeWithError(ctx context.Context, d *DisConcierge, err error) {
	logger, ok := ContextLogger(ctx)
	if !ok || logger == nil {
		logger = d.logger
	}
	acknowledged := c.Acknowledged
	config := c.handler.Config()
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		finishedAt := time.Now()

		if _, err = d.writeDB.Updates(
			c,
			map[string]any{
				columnChatCommandState:      ChatCommandStateFailed,
				columnChatCommandResponse:   &config.DiscordErrorMessage,
				columnChatCommandError:      err.Error(),
				columnChatCommandFinishedAt: &finishedAt,
			},
		); err != nil {
			logger.ErrorContext(ctx, "error updating command state", tint.Err(err))
		}
	}()

	if acknowledged {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = c.handler.Edit(
				ctx,
				&discordgo.WebhookEdit{Content: &config.DiscordErrorMessage},
			)
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		c.discordNotifyError(ctx, logger, d, err)
	}()

	wg.Wait()
}

func (c *ChatCommand) discordNotifyError(
	_ context.Context,
	logger *slog.Logger,
	d *DisConcierge,
	err error,
) {
	if err == nil {
		return
	}
	config := c.handler.Config()
	if config.DiscordNotificationChannelID == "" {
		logger.Debug("no discord notification channel set, skipping message send")
		return
	}
	if sendErr := d.discord.channelMessageSend(
		config.DiscordNotificationChannelID,
		fmt.Sprintf(
			"## Error!\n\n"+
				"- ChatCommand ID: `%d`\n"+
				"- Interaction ID: `%s`\n"+
				"- User: `%s` (`%s`)\n"+
				"- State: `%s`\n"+
				"- Step: `%s`\n"+
				"- RunStatus: `%s`\n"+
				"### Error\n"+
				"```\n"+
				"%s\n"+
				"```\n"+
				"### Prompt\n"+
				"```\n"+
				"%s\n"+
				"```\n",
			c.ID,
			c.InteractionID,
			c.UserID,
			c.User.GlobalName,
			c.State,
			c.Step,
			c.RunStatus,
			err.Error(),
			c.Prompt,
		),
	); sendErr != nil {
		logger.Error(
			"error sending error notification",
			tint.Err(sendErr),
		)
	}
}

// finalize accepts a string, from the OpenAI assistant response to forward
// to the Discord user, and an error, if the command failed. It then either
// sends the user the prompt string, or an error messages, and if the command
// succeeded, updates the discord interaction with feedback component buttons.
func (c *ChatCommand) finalize(
	ctx context.Context,
	d *DisConcierge,
	answer string,
	err error,
) {
	logger, ok := ContextLogger(ctx)
	if logger == nil || !ok {
		logger = d.logger
		if logger == nil {
			logger = slog.Default()
		}
		ctx = WithLogger(ctx, logger)
	}

	wg := &sync.WaitGroup{}

	if err != nil {
		c.finalizeWithError(ctx, d, err)
		return
	}

	finishedAt := time.Now()
	var updates map[string]any

	tokenActive := c.TokenExpires > finishedAt.UnixMilli()

	if tokenActive {
		c.setFreshButtonStates()

		updates = map[string]any{
			columnChatCommandState:                   ChatCommandStateCompleted,
			columnChatCommandStep:                    ChatCommandStepFeedbackOpen,
			columnChatCommandFinishedAt:              &finishedAt,
			columnChatCommandResponse:                &answer,
			columnChatCommandButtonStateGood:         c.FeedbackButtonStateGood,
			columnChatCommandButtonStateOutdated:     c.FeedbackButtonStateOutdated,
			columnChatCommandButtonStateHallucinated: c.FeedbackButtonStateHallucinated,
			columnChatCommandButtonStateOther:        c.FeedbackButtonStateOther,
			columnChatCommandButtonStateUndo:         c.FeedbackButtonStateReset,
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.respondToUser(ctx, d, logger, answer)
		}()
	} else {
		logger.Warn("token no longer active, will not respond to interaction")
		updates = map[string]any{
			columnChatCommandState:      ChatCommandStateCompleted,
			columnChatCommandStep:       ChatCommandStepFeedbackClosed,
			columnChatCommandFinishedAt: &finishedAt,
			columnChatCommandResponse:   &answer,
		}
	}

	if _, err = d.writeDB.Updates(c, updates); err != nil {
		logger.ErrorContext(
			ctx,
			"error updating command state",
			tint.Err(err),
		)
	}

	wg.Wait()
}

// respondToUser sends the final response to the user for a chat command.
// It handles the creation and sending of the response message, including
// feedback buttons if enabled.
//
// The function performs the following tasks:
//  1. If feedback is enabled, it creates a message with feedback buttons
//     and sends it to the user.
//  2. If feedback is disabled, it sends a simple text response.
//  3. It starts a timer to manage the lifecycle of feedback buttons.
//
// Parameters:
//   - ctx: The context for the operation, which may include cancellation signals.
//   - d: A pointer to the DisConcierge instance, providing access to bot functionalities.
//   - logger: A pointer to a slog.Logger for logging operations.
//   - answer: The string content of the response to be sent to the user.
//
// The function doesn't return any values but logs errors if they occur during
// the response sending process.
func (c *ChatCommand) respondToUser(
	ctx context.Context,
	d *DisConcierge,
	logger *slog.Logger,
	answer string,
) {
	config := c.handler.Config()

	if config.FeedbackEnabled && c.CustomID != "" {
		reportComponents := c.newReportButtons()

		if updErr := c.responseEditWithButtons(ctx, answer, &reportComponents); updErr != nil {
			logger.ErrorContext(
				ctx,
				"unable to create followup message",
				tint.Err(updErr),
			)
			return
		}
		go d.chatCommandUnselectedButtonTimer(ctx, c)
		return
	}

	if _, updErr := c.handler.Edit(
		ctx,
		&discordgo.WebhookEdit{Content: &answer},
	); updErr != nil {
		logger.ErrorContext(
			ctx,
			"unable to create followup message",
			tint.Err(updErr),
		)
	}
}

// removeButtonsAt returns the time.Time any discord interaction
// buttons should be removed or disabled
func (c *ChatCommand) removeButtonsAt() time.Time {
	removeAt := time.UnixMilli(c.TokenExpires).UTC().Add(-time.Minute)
	return removeAt
}

// getReports returns all reports associated with this ChatCommand
func (c *ChatCommand) getReports(
	ctx context.Context,
	db *gorm.DB,
) ([]UserFeedback, error) {
	var existingReports []UserFeedback
	err := db.WithContext(ctx).Where(
		"chat_command_id = ?",
		c.ID,
	).Order("id asc").Find(&existingReports).Error
	return existingReports, err
}

// userReportExists checks if a user report of a specific type exists for this ChatCommand.
//
// This method queries the database to determine if a user report of the given type
// exists for the specified user and ChatCommand.
//
// Parameters:
//   - ctx: The context for managing the lifecycle of the database query.
//   - db: A pointer to the gorm.DB instance for database operations.
//   - userID: The ID of the user whose report existence is being checked.
//   - reportType: The type of feedback report being checked.
//
// Returns:
//   - int64: The number of rows found matching the query criteria.
//   - error: An error object if the query fails, otherwise nil.
func (c *ChatCommand) userReportExists(
	ctx context.Context,
	db *gorm.DB,
	userID string,
	reportType FeedbackButtonType,
) (int64, error) {
	var userFeedback UserFeedback
	rv := db.WithContext(ctx).Where(
		"chat_command_id = ? AND user_id = ? AND type = ?",
		c.ID,
		userID,
		string(reportType),
	).Take(&userFeedback)
	return rv.RowsAffected, rv.Error
}

// setFreshButtonStates updates the Show* and Disable* button fields
// to their 'new' state if ChatCommand.CustomID is set, with all buttons
// visible and enabled (except for the undo button).
// If ChatCommand.CustomID isn't set, everything will be hidden/disabled.
func (c *ChatCommand) setFreshButtonStates() {
	if c.CustomID == "" {
		c.FeedbackButtonStateGood = FeedbackButtonStateHidden
		c.FeedbackButtonStateOutdated = FeedbackButtonStateHidden
		c.FeedbackButtonStateHallucinated = FeedbackButtonStateHidden
		c.FeedbackButtonStateOther = FeedbackButtonStateHidden
		c.FeedbackButtonStateReset = FeedbackButtonStateHidden
		return
	}

	c.FeedbackButtonStateGood = FeedbackButtonStateEnabled
	c.FeedbackButtonStateOutdated = FeedbackButtonStateEnabled
	c.FeedbackButtonStateHallucinated = FeedbackButtonStateEnabled
	c.FeedbackButtonStateOther = FeedbackButtonStateEnabled
	c.FeedbackButtonStateReset = FeedbackButtonStateHidden
}

// setExpiredButtonStates sets button states for a command which has
// a discord token that's about to expire. Buttons that have been selected
// will remain visible (but disabled), while unselected buttons will be
// removed entirely. The 'undo' button will always be removed.
// If the 'disable[Type]' field is true and the field is visible, that means
// it was previously selected.
func (c *ChatCommand) setExpiredButtonStates() {
	c.FeedbackButtonStateReset = FeedbackButtonStateHidden

	// reflects the currently selected buttons
	choices := map[FeedbackButtonType]bool{
		UserFeedbackGood:         false,
		UserFeedbackOutdated:     false,
		UserFeedbackHallucinated: false,
		UserFeedbackOther:        false,
	}

	if c.FeedbackButtonStateGood == FeedbackButtonStateDisabled {
		choices[UserFeedbackGood] = true
	}

	if c.FeedbackButtonStateHallucinated == FeedbackButtonStateDisabled {
		choices[UserFeedbackHallucinated] = true
	}

	if c.FeedbackButtonStateOutdated == FeedbackButtonStateDisabled {
		choices[UserFeedbackOutdated] = true
	}

	if c.FeedbackButtonStateOther == FeedbackButtonStateDisabled {
		choices[UserFeedbackOther] = true
	}

	// set everything as hidden and disabled, then selectively
	// set the 'show[Type]' field for any previously selected button,
	// so the only remaining buttons should be existing selections
	c.FeedbackButtonStateOutdated = FeedbackButtonStateHidden
	c.FeedbackButtonStateHallucinated = FeedbackButtonStateHidden
	c.FeedbackButtonStateOther = FeedbackButtonStateHidden
	c.FeedbackButtonStateGood = FeedbackButtonStateHidden

	if choices[UserFeedbackGood] {
		c.FeedbackButtonStateGood = FeedbackButtonStateDisabled
	}

	if choices[UserFeedbackHallucinated] {
		c.FeedbackButtonStateHallucinated = FeedbackButtonStateDisabled
	}

	if choices[UserFeedbackOutdated] {
		c.FeedbackButtonStateOutdated = FeedbackButtonStateDisabled
	}

	if choices[UserFeedbackOther] {
		c.FeedbackButtonStateOther = FeedbackButtonStateDisabled
	}
}

// setExpiredButtonStatesFromDB uses the database to determine which feedback
// buttons to show/disable for this ChatCommand, and sets the fields
// accordingly. Does not update the DB.
func (c *ChatCommand) setExpiredButtonStatesFromDB(_ context.Context, db *gorm.DB) error {
	type result struct {
		Type string
	}
	var results []result

	err := db.Table(UserFeedback{}.TableName()).Select(
		columnUserFeedbackType,
	).Group(columnUserFeedbackType).Where(
		"chat_command_id = ?", c.ID,
	).Scan(&results).Error

	if err != nil {
		return err
	}

	feedbackSeen := map[FeedbackButtonType]bool{}
	for _, r := range results {
		feedbackSeen[FeedbackButtonType(r.Type)] = true
	}

	c.FeedbackButtonStateReset = FeedbackButtonStateHidden

	c.FeedbackButtonStateGood = FeedbackButtonStateHidden
	c.FeedbackButtonStateOutdated = FeedbackButtonStateHidden
	c.FeedbackButtonStateHallucinated = FeedbackButtonStateHidden
	c.FeedbackButtonStateOther = FeedbackButtonStateHidden

	if feedbackSeen[UserFeedbackGood] {
		c.FeedbackButtonStateGood = FeedbackButtonStateDisabled
	}

	if feedbackSeen[UserFeedbackOutdated] {
		c.FeedbackButtonStateOutdated = FeedbackButtonStateDisabled
	}

	if feedbackSeen[UserFeedbackHallucinated] {
		c.FeedbackButtonStateHallucinated = FeedbackButtonStateDisabled
	}

	if feedbackSeen[UserFeedbackOther] {
		c.FeedbackButtonStateOther = FeedbackButtonStateDisabled
	}
	return nil
}

// removeUnusedFeedbackButtons 'finalizes' an interaction whose token is about
// to expire (preventing further updates), by removing any feedback buttons
// that weren't selected, and leaving those that were (albeit in a disabled
// state)
func (c *ChatCommand) removeUnusedFeedbackButtons(
	ctx context.Context,
	db DBI,
) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	logger, ok := ContextLogger(ctx)
	if logger == nil || !ok {
		logger = slog.Default()
		ctx = WithLogger(ctx, logger)
	}
	logger.InfoContext(ctx, "removing unused feedback buttons!")

	err := db.DB().Last(c).Error
	if err != nil {
		logger.ErrorContext(ctx, "unable to refresh command", tint.Err(err))
	}

	if c.hasPrivateFeedback() {
		c.setExpiredButtonStates()
	} else {
		err = c.setExpiredButtonStatesFromDB(ctx, db.DB())
		if err != nil {
			logger.ErrorContext(
				ctx,
				"unable to set expired button states",
				tint.Err(err),
			)
		}
	}
	buttons := c.discordUserFeedbackComponents()
	_, updErr := c.handler.Edit(
		ctx,
		&discordgo.WebhookEdit{
			Components: &buttons,
		},
	)
	if updErr != nil {
		logger.ErrorContext(
			ctx,
			"error updating interaction response",
			tint.Err(updErr),
		)
		return updErr
	}

	if c.Step != ChatCommandStepFeedbackOpen {
		logger.WarnContext(ctx, "command not in feedback open state")
	}
	_, saveErr := db.Updates(
		c,
		map[string]any{
			columnChatCommandButtonStateGood:         c.FeedbackButtonStateGood,
			columnChatCommandButtonStateOutdated:     c.FeedbackButtonStateOutdated,
			columnChatCommandButtonStateHallucinated: c.FeedbackButtonStateHallucinated,
			columnChatCommandButtonStateOther:        c.FeedbackButtonStateOther,
			columnChatCommandButtonStateUndo:         c.FeedbackButtonStateReset,
			columnChatCommandStep:                    ChatCommandStepFeedbackClosed,
		},
	)
	return saveErr
}

func (c ChatCommand) LogValue() slog.Value {
	interactionAttrs := []any{
		"type", c.Type,
		"context", c.CommandContext,
		"user_id", c.UserID,
	}
	if c.ChannelID != "" {
		interactionAttrs = append(interactionAttrs, "channel_id", c.ChannelID)
	}
	if c.GuildID != "" {
		interactionAttrs = append(interactionAttrs, "guild_id", c.GuildID)
	}

	if c.TokenExpires > 0 {
		interactionAttrs = append(
			interactionAttrs,
			"token_expires",
			time.UnixMilli(c.TokenExpires).String(),
		)
	}

	attrs := []slog.Attr{
		slog.Uint64("id", uint64(c.ID)),
		slog.String(columnChatCommandState, c.State.String()),
		slog.String(columnChatCommandStep, c.Step.String()),
		slog.Bool(columnChatCommandPriority, c.Priority),
		slog.Bool(columnChatCommandClear, c.Private),
		slog.String(columnChatCommandInteractionID, c.InteractionID),
		slog.String("app_id", c.AppID),
		slog.Bool(columnChatCommandAcknowledged, c.Acknowledged),
		slog.Group("interaction", interactionAttrs...),
	}
	if c.ThreadID != "" {
		attrs = append(
			attrs,
			slog.String(columnChatCommandThreadID, c.ThreadID),
		)
	}
	if c.RunID != "" {
		attrs = append(attrs, slog.String(columnChatCommandRunID, c.RunID))
	}
	if c.MessageID != "" {
		attrs = append(
			attrs,
			slog.String(columnChatCommandMessageID, c.MessageID),
		)
	}
	if c.RunStatus != "" {
		attrs = append(
			attrs,
			slog.String(columnChatCommandRunStatus, string(c.RunStatus)),
		)
	}

	return slog.GroupValue(
		attrs...,
	)
}

// Age returns the time elapsed since the command was created
func (c *ChatCommand) Age() time.Duration {
	return time.Since(time.UnixMilli(c.CreatedAt))
}

// finalizeExpiredButtons updates the button states of an ChatCommand when its
// interaction token is about to expire.
// It sets the button states according to the command's
// context (private or DM), or based on the database state for public interactions.
//
// After updating the button states, it updates the ChatCommand record in the database.
//
// Parameters:
//   - ctx: The context for the operation, which may include logging information.
//   - dc: A pointer to the DisConcierge instance, which provides access to
//     the database and other services.
//   - c: A pointer to the ChatCommand whose buttons need to be finalized.
//
// The function performs the following steps:
//  1. If the command is a private or DM, it calls setExpiredButtonStates()
//     directly on the ChatCommand.
//  2. For public interactions, it calls setExpiredButtonStatesFromDB() to
//     update button states based on existing feedback.
//  3. It sets the ChatCommand's Step to ChatCommandStepFeedbackClosed.
//  4. It updates the ChatCommand record in the database with the new button states and step.
//
// If any errors occur during the database update, they are logged but not returned.
//
// This function is typically called when an interaction's token is about to
// expire, ensuring that the UI reflects the final state of user feedback options,
// and so users can see that the buttons are no longer functional.
func (c *ChatCommand) finalizeExpiredButtons(ctx context.Context, db DBI) {
	// TODO add a config for the expiration timer for testing
	logger, ok := ContextLogger(ctx)
	if logger == nil || !ok {
		logger = slog.Default()
		ctx = WithLogger(ctx, logger)
	}

	if c.hasPrivateFeedback() {
		c.setExpiredButtonStates()
	} else {
		if err := c.setExpiredButtonStatesFromDB(ctx, db.DB()); err != nil {
			logger.ErrorContext(
				ctx,
				"error setting expired buttons",
				tint.Err(err),
			)
			return
		}
	}

	c.Step = ChatCommandStepFeedbackClosed
	_, saveErr := db.Updates(
		c,
		map[string]any{
			columnChatCommandButtonStateGood:         c.FeedbackButtonStateGood,
			columnChatCommandButtonStateOutdated:     c.FeedbackButtonStateOutdated,
			columnChatCommandButtonStateHallucinated: c.FeedbackButtonStateHallucinated,
			columnChatCommandButtonStateOther:        c.FeedbackButtonStateOther,
			columnChatCommandButtonStateUndo:         c.FeedbackButtonStateReset,
			columnChatCommandStep:                    c.Step,
		},
	)

	if saveErr != nil {
		logger.ErrorContext(
			ctx,
			"error setting feedback closed",
			tint.Err(saveErr),
		)
	}
}

// hasPrivateFeedback returns true if this command was the result
// of a `/private` slash command, or if the command was sent via DM
func (c *ChatCommand) hasPrivateFeedback() bool {
	return c.Private ||
		c.CommandContext == discordgo.InteractionContextType(
			discordgo.InteractionContextBotDM,
		).String()
}

// getOrCreateThreadID returns [ChatCommand.ThreadID], if set. Otherwise,
// it sets the field with the value in [User.ThreadID]. If neither field
// is set, a new thread is created via the OpenAI API, a new
// [OpenAICreateThread] is created, and both the [ChatCommand] and [User]
// ThreadID fields are updated.
func getOrCreateThreadID(
	ctx context.Context,
	d *DisConcierge,
	c *ChatCommand,
) (string, error) {
	if c.ThreadID != "" {
		return c.ThreadID, nil
	}
	user := c.User
	started := time.Now()

	if user.ThreadID != "" {
		threadID := user.ThreadID
		if threadID != "" {
			c.ThreadID = threadID
			if _, err := d.writeDB.Update(
				c,
				columnChatCommandThreadID,
				threadID,
			); err != nil {
				return "", err
			}
			return threadID, nil
		}
	}

	logger, ok := ContextLogger(ctx)
	if logger == nil || !ok {
		logger = d.logger
		if logger == nil {
			logger = slog.Default()
		}
		ctx = WithLogger(ctx, logger)
	}

	threadID, err := d.openai.CreateThread(ctx, d.writeDB, c)
	ended := time.Now()
	if err != nil {
		logger.ErrorContext(
			ctx,
			"error creating thread", tint.Err(err),
			"started", started,
			"ended", ended,
			"duration", ended.Sub(started),
		)
		return "", err
	}
	d.logger.InfoContext(
		ctx, "created new user thread",
		columnChatCommandThreadID, threadID,
		"started", started,
		"ended", ended,
		"duration", ended.Sub(started),
	)

	if threadID == "" {
		return "", fmt.Errorf("empty thread ID")
	}

	var errs []error

	user.ThreadID = threadID
	if _, err = d.writeDB.Update(
		user,
		columnChatCommandThreadID,
		threadID,
	); err != nil {
		errs = append(errs, err)
	}

	c.ThreadID = threadID
	if _, err = d.writeDB.Update(
		c,
		columnChatCommandThreadID,
		threadID,
	); err != nil {
		errs = append(errs, err)
	}

	return c.ThreadID, errors.Join(errs...)
}

func validateOpenAIRunSettings(field reflect.Value) any {
	if value, ok := field.Interface().(OpenAIRunSettings); ok {
		pollDuration := value.AssistantPollInterval.Duration
		if pollDuration < 100*time.Millisecond {
			return fmt.Errorf("poll interval must be at least 100ms")
		}
		if pollDuration > 60*time.Second {
			return fmt.Errorf("poll interval must be at most 60s")
		}
		maxDuration := value.AssistantMaxPollInterval.Duration
		if maxDuration < pollDuration {
			return fmt.Errorf("max poll interval must be greater than or equal to poll interval")
		}
	}
	return nil
}

// discordNotifyCommandPanicked logs and notifies about a command that has panicked.
// If [RuntimeConfig.DiscordNotificationChannelID] is not set, or
// [RuntimeConfig.DiscordGatewayEnabled] is not true, this is a no-op.
func discordNotifyCommandPanicked(
	ctx context.Context,
	log *slog.Logger,
	req *ChatCommand,
	d *Discord,
) {
	opts := req.handler.Config()
	if opts.DiscordNotificationChannelID == "" {
		return
	}
	if sendErr := d.channelMessageSend(
		opts.DiscordNotificationChannelID,
		fmt.Sprintf(
			"# **Panic in ChatCommand!**\n"+
				"- User ID: `%s`\n"+
				"- Username: `%s`\n"+
				"- ChatCommand ID: `%d`\n"+
				"- Interaction ID: `%s`\n"+
				"- Prompt: `%s`\n",
			req.UserID,
			req.User.Username,
			req.ID,
			req.InteractionID,
			req.Prompt,
		),
		discordgo.WithRestRetries(1),
		discordgo.WithRetryOnRatelimit(true),
	); sendErr != nil {
		log.ErrorContext(
			ctx,
			"error sending panic notification",
			tint.Err(sendErr),
		)
	}
}

// ChatCommandUsage represents usage statistics for chat commands over different time periods.
// It provides information about command limits, attempts, and various metrics related to
// chat command usage for both 24-hour and 6-hour time frames.
type ChatCommandUsage struct {
	// Limit6h is the maximum number of chat commands allowed in a 6-hour period.
	Limit6h int `json:"limit_6h"`

	// Attempted6h is the number of chat commands attempted in the last 6 hours.
	Attempted6h int `json:"attempted_6h"`

	// Billable6h is the number of billable chat commands in the last 6 hours.
	Billable6h int `json:"billable_6h"`

	// Remaining6h is the number of chat commands remaining within the 6-hour limit.
	Remaining6h int `json:"remaining_6h"`

	// PromptTokens6h is the total number of prompt tokens used in the last 6 hours.
	PromptTokens6h int `json:"prompt_tokens_6h"`

	// CompletionTokens6h is the total number of completion tokens used in the last 6 hours.
	CompletionTokens6h int `json:"completion_tokens_6h"`

	// TotalTokens6h is the total number of tokens (prompt + completion) used in the last 6 hours.
	TotalTokens6h int `json:"total_tokens_6h"`

	// State6h maps ChatCommandState to the count of commands in that state over the last 6 hours.
	State6h map[ChatCommandState]int `json:"state_6h"`

	// Private6h is the number of /private commands used in the last 6 hours.
	Private6h int `json:"private_6h"`

	// Threads6h is the number of unique threads used in the last 6 hours.
	Threads6h int `json:"threads_6h"`

	// CommandsAvailable indicates whether the user can currently issue more commands.
	CommandsAvailable bool `json:"commands_available"`

	// CommandsAvailableAt is the time when commands will next become available
	// if currently unavailable.
	CommandsAvailableAt time.Time `json:"commands_available_at"`
}

func (a ChatCommandUsage) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Group(
			"6h",
			slog.Int("limit", a.Limit6h),
			slog.Int("attempted", a.Attempted6h),
			slog.Int("billable", a.Billable6h),
			slog.Int("remaining", a.Remaining6h),
			slog.Int("prompt_tokens", a.PromptTokens6h),
			slog.Int("completion_tokens", a.CompletionTokens6h),
			slog.Int("total_tokens", a.TotalTokens6h),
			slog.Any(columnChatCommandState, a.State6h),
		),
		slog.Bool("commands_available", a.CommandsAvailable),
		slog.Time("commands_available_at", a.CommandsAvailableAt),
	)
}

// GetCommandUsage6h returns a ChatCommandUsage reflecting overall
// ChatCommand usage for the previous 6 hours
func GetCommandUsage6h(
	ctx context.Context,
	db *gorm.DB,
	u *User,
	endingAt time.Time,
) (ChatCommandUsage, error) {
	logger, ok := ContextLogger(ctx)
	if !ok || logger == nil {
		logger = slog.Default().With("user", u)
	}
	c := ChatCommandUsage{
		Limit6h:     u.UserChatCommandLimit6h,
		Remaining6h: u.UserChatCommandLimit6h,
		State6h:     map[ChatCommandState]int{},
	}

	endingAt = endingAt.UTC()
	startingAt := endingAt.Add(-6 * time.Hour)

	var requests6h []*ChatCommand
	err := db.Model(&ChatCommand{}).Where(
		"user_id = ? AND created_at >= ? AND created_at <= ?",
		u.ID,
		startingAt.UnixMilli(),
		endingAt.UnixMilli(),
	).Find(&requests6h).Error

	if err != nil {
		return c, err
	}
	logger.InfoContext(
		ctx,
		fmt.Sprintf(
			"found %d requests since %s",
			len(requests6h),
			startingAt.String(),
		),
	)

	slices.SortFunc(
		requests6h, func(i, j *ChatCommand) int {
			return cmp.Compare(i.CreatedAt, j.CreatedAt)
		},
	)

	threads6h := map[string]bool{}

	for _, chatCommand := range requests6h {
		c.Attempted6h++
		c.PromptTokens6h += chatCommand.UsagePromptTokens
		c.CompletionTokens6h += chatCommand.UsageCompletionTokens
		c.TotalTokens6h += chatCommand.UsageTotalTokens
		c.State6h[chatCommand.State]++
		if chatCommand.UsageTotalTokens > 0 || chatCommand.RunStatus == openai.RunStatusCompleted {
			c.Billable6h++
			c.Remaining6h--
		}
		if chatCommand.Private {
			c.Private6h++
		}
		if chatCommand.ThreadID != "" {
			threads6h[chatCommand.ThreadID] = true
		}
	}

	c.Threads6h = len(threads6h)

	switch {
	case c.Remaining6h > 0:
		c.CommandsAvailable = true
	default:
		availableAt6h, _ := chatCommandAvailable(
			ctx,
			requests6h,
			c.Limit6h,
			6*time.Hour,
			endingAt,
		)
		c.CommandsAvailableAt = availableAt6h
	}
	return c, nil
}

// GetCommandUsagePrevious6h is a convenience function that calls
// [GetCommandUsage6h] with the current time
func GetCommandUsagePrevious6h(
	ctx context.Context,
	db *gorm.DB,
	u *User,
) (ChatCommandUsage, error) {
	now := time.Now().UTC()
	return GetCommandUsage6h(ctx, db, u, now)
}

// UsageMessage returns a message to be sent to a user that's either approaching
// or has exceeded their allowed /chat and /private commands for the past
// 6 hours
func (a ChatCommandUsage) UsageMessage() string {
	if a.CommandsAvailable {
		if a.Remaining6h <= 2 {
			return fmt.Sprintf(
				"-# :warning: Commands used: **%d/%d (6h)**",
				a.Billable6h,
				a.Limit6h,
			)
		}
		return fmt.Sprintf(
			"-# Commands used: **%d/%d (6h)**",
			a.Billable6h,
			a.Limit6h,
		)
	}

	availableAt := a.CommandsAvailableAt
	if availableAt.Weekday() != time.Now().Weekday() {
		return fmt.Sprintf(
			":warning: Command limit reached! **Next available at: %s %s**",
			availableAt.Weekday().String(),
			availableAt.Format(time.Kitchen),
		)
	}
	return fmt.Sprintf(
		":warning: Command limit reached! **Next available at: %s**",
		availableAt.Format(time.Kitchen),
	)
}
