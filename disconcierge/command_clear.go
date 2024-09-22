package disconcierge

import (
	"context"
	"github.com/bwmarrin/discordgo"
	"github.com/lmittmann/tint"
	"log/slog"
	"sync"
	"time"
)

const (
	ClearCommandStateReceived  ClearCommandState = "received"
	ClearCommandStateFailed    ClearCommandState = "failed"
	ClearCommandStateCompleted ClearCommandState = "completed"
	ClearCommandStateIgnored   ClearCommandState = "ignored"
)

var (
	// clearCommandResponseForgotten is the response message sent to the user when
	// their /clear command succeeds.
	// TODO set this via RuntimeConfig
	clearCommandResponseForgotten = "I've forgotten all your threads!"

	// clearCommandResponseTooSoon is the response message sent to the user
	// when they attempt a /clear command, but another command is already
	// in progress.
	// TODO set this via RuntimeConfig
	clearCommandResponseTooSoon = "I just did that!"

	columnClearCommandState      = "state"
	columnClearCommandFinishedAt = "finished_at"
	columnClearCommandResponse   = "response"
	columnClearCommandError      = "error"
	columnClearCommandStartedAt  = "started_at"
)

type ClearCommandState string

// ClearCommand represents a '/clear' slash command execution in the DisConcierge bot.
//
// This struct encapsulates the details of a clear command, including its state,
// associated user interaction, and execution results. It is used to manage and
// track the lifecycle of a clear command from receipt to completion.
//
// Fields:
//   - ModelUintID: Embedded struct providing a uint ID field.
//   - ModelUnixTime: Embedded struct providing created_at, updated_at, and deleted_at fields.
//   - Interaction: Embedded struct containing details of the Discord interaction.
//   - logger: A slog.Logger for logging command-specific information.
//   - State: The current state of the clear command (e.g., received, completed, failed).
//   - Error: A pointer to a string containing any error message if the command fails.
//   - Response: A pointer to a string containing the response message for the command.
//   - handler: An InteractionHandler for managing Discord interactions.
//
// The ClearCommand is typically created when a user issues a '/clear' command
// and is processed to reset the user's conversation context with the bot.
type ClearCommand struct {
	ModelUintID
	ModelUnixTime
	Interaction
	logger   *slog.Logger
	State    ClearCommandState
	Error    *string `json:"error" gorm:"type:string"`
	Response *string `json:"response" gorm:"type:string"`
	handler  InteractionHandler
}

func NewUserClearCommand(
	d *DisConcierge,
	u *User,
	i *discordgo.InteractionCreate,
) *ClearCommand {
	interaction := NewUserInteraction(i, u)

	rec := &ClearCommand{
		Interaction: *interaction,
		State:       ClearCommandStateReceived,
	}
	rec.logger = d.logger.With("clear_command", rec)
	return rec
}

func (c *ClearCommand) Deadline() time.Time {
	return time.UnixMilli(c.TokenExpires).UTC()
}

func (c ClearCommand) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Any("interaction", c.Interaction),
		slog.String("error", stringPointerValue(c.Error)),
		slog.String("response", stringPointerValue(c.Response)),
	)
}

// execute processes the ClearCommand, resetting the user's conversation context
// (aka clearing [User.ThreadID] so a new thread is created the next time
// they invoke the /chat or /private commands)
//
// This method performs the core functionality of the '/clear' command. It updates
// the user's ThreadID to null, effectively resetting their conversation history
// with the bot. The method handles the entire lifecycle of the command execution,
// including updating the command's state, managing database operations, and
// responding to the user via Discord.
//
// The method performs the following main tasks:
// 1. Increments a metric counter for clear commands in progress.
// 2. Records the start time of the command execution.
// 3. Attempts to update the user's ThreadID to null in the database.
// 4. Handles any errors that occur during the database update.
// 5. Responds to the user with an appropriate message based on the operation's success or failure.
// 6. Updates the ClearCommand record in the database with the final state and response.
//
// Parameters:
//   - ctx: A context.Context for managing the lifecycle of the execution.
//   - dc: A pointer to the DisConcierge instance, providing access to bot-wide
//     resources and configurations.
//
// Returns:
//   - error: An error if any part of the execution fails, or nil if successful.
//
// The method uses goroutines for concurrent operations like database updates
// and Discord message editing to improve performance.
func (c *ClearCommand) execute(
	ctx context.Context,
	dc *DisConcierge,
) error {
	dc.clearCommandsInProgress.Add(1)
	defer dc.clearCommandsInProgress.Add(-1)

	started := time.Now()

	config := c.handler.Config()

	cmdLogger := c.logger
	if cmdLogger == nil {
		cmdLogger = slog.Default()
	}

	updates := map[string]any{
		columnClearCommandStartedAt: &started,
		columnClearCommandState:     ClearCommandStateCompleted,
	}
	originalThreadID := c.User.ThreadID
	_, err := dc.writeDB.Update(context.TODO(), c.User, columnUserThreadID, nil)

	wg := &sync.WaitGroup{}
	defer wg.Wait()

	switch {
	case err != nil:
		cmdLogger.ErrorContext(ctx, "error updating user", tint.Err(err))
		updates[columnClearCommandResponse] = config.DiscordErrorMessage
		updates[columnClearCommandError] = err.Error()
		updates[columnClearCommandState] = ClearCommandStateFailed
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, editErr := c.handler.Edit(
				ctx,
				&discordgo.WebhookEdit{Content: &config.DiscordErrorMessage},
				discordgo.WithContext(ctx),
			)
			if editErr != nil {
				cmdLogger.ErrorContext(ctx, "error updating interaction", tint.Err(editErr))
			}
		}()
	default:
		updates[columnClearCommandResponse] = clearCommandResponseForgotten
		if originalThreadID != "" {
			wg.Add(1)
			go func() {
				defer wg.Done()
				dc.dbNotifier.UserUpdated(ctx, c.UserID)
			}()
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			_, editErr := c.handler.Edit(
				ctx,
				&discordgo.WebhookEdit{Content: &clearCommandResponseForgotten},
				discordgo.WithContext(ctx),
			)
			if editErr != nil {
				cmdLogger.ErrorContext(ctx, "error updating interaction", tint.Err(editErr))
			}
		}()
	}

	ended := time.Now()
	updates[columnClearCommandFinishedAt] = &ended

	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, e := dc.writeDB.Updates(context.TODO(), c, updates); e != nil {
			cmdLogger.ErrorContext(ctx, "error updating clear command", tint.Err(e))
		}
	}()

	return err
}
