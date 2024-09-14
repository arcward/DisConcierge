package disconcierge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bwmarrin/discordgo"
	"github.com/sashabaranov/go-openai"
	"gorm.io/gorm"
	"log/slog"
	"time"
)

var (
	columnUserThreadID   = "thread_id"
	columnUserIgnored    = "ignored"
	columnUserContent    = "content"
	columnUserUsername   = "username"
	columnUserGlobalName = "global_name"
	columnUserLastSeen   = "last_seen"
)

// User is a record of a Discord user, and their current state.
// See: https://discord.com/developers/docs/resources/user
//
//nolint:lll // struct tags can't be split
type User struct {
	//
	// The first set of fields are set from the Discord user object
	//

	// ID is the Discord user ID
	ID string `json:"id" gorm:"primaryKey;unique;type:string"`

	// Username, not unique
	Username string `json:"username" gorm:"type:string"`

	// User's display name - for bots, the application name
	GlobalName string `json:"global_name" gorm:"type:string"`

	// Indicates this user is a Discord bot user. Bots will be ignored
	// by default.
	Bot bool `json:"bot" gorm:"type:bool"`

	// JSON content of the discord user object
	Content string `json:"content" gorm:"type:string"`

	//
	// The fields below are DisConcierge-specific
	//

	// Current thread ID to use for ChatCommand / OpenAI requests
	ThreadID string `json:"thread_id" gorm:"column:thread_id"`

	// If true, ChatCommand requests from this user will be
	// queued, even if the app is currently paused
	Priority bool `json:"priority" gorm:"type:bool;default:false"`

	// If true, ChatCommand and ClearCommand requests from this user
	// will be ignored
	Ignored bool `json:"ignored" gorm:"type:bool;default:false"`

	// Maximum number of ChatCommand requests allowed for this user over
	// six hours. Only counts completed requests.
	UserChatCommandLimit6h int `json:"user_chat_command_limit_6h" gorm:"column:user_chat_command_limit_6h"`

	// LastSeen is the last time this user was seen in a Discord interaction
	// (whether it was from a slash command, clicking a button, etc.)
	LastSeen int64 `json:"last_seen" gorm:"column:last_seen"`

	// User-specific OpenAI settings
	OpenAIRunSettings

	ModelUnixTime
}

func NewUser(u discordgo.User) (*User, error) {
	content, err := json.Marshal(u)
	user := User{
		ID:         u.ID,
		Username:   u.Username,
		Ignored:    false,
		Content:    string(content),
		GlobalName: u.GlobalName,
		Bot:        u.Bot,
		LastSeen:   time.Now().UTC().UnixMilli(),
	}
	if u.Bot {
		user.Ignored = true
	}

	return &user, err
}

func (u *User) String() string {
	return fmt.Sprintf("%s [%s]", u.Username, u.ID)
}

// TokenUsageSince returns the sum of ChatCommand.UsageTotalTokens since
// the given time
func (u *User) TokenUsageSince(db *gorm.DB, since time.Time) (int64, error) {
	ts := since.UnixMilli()
	var total int64
	err := db.Model(&ChatCommand{}).Select("sum(usage_total_tokens) as total").Where(
		"user_id = ? AND created_at >= ?",
		u.ID,
		ts,
	).First(&total).Error
	return total, err
}

func (u *User) ChatCommandsWithCostSince(
	db *gorm.DB,
	at time.Time,
) ([]*ChatCommand, error) {
	var requests []*ChatCommand
	err := db.Model(&ChatCommand{}).Where(
		"user_id = ? AND created_at >= ? AND (run_status = ? OR usage_total_tokens > 0)",
		u.ID,
		at.UTC().UnixMilli(),
		string(openai.RunStatusCompleted),
	).Find(&requests).Error
	return requests, err
}

// ChatCommandsWithCost6h returns an ChatCommand slice with all completed
// (either via openai.RunStatusCompleted, or another status where tokens
// were used and billed) ChatCommand requests for the user within the last
// 24 hours
func (u *User) ChatCommandsWithCost6h(db *gorm.DB) ([]*ChatCommand, error) {
	return u.ChatCommandsWithCostSince(db, time.Now().Add(-6*time.Hour))
}

func (u *User) LogValue() slog.Value {
	if u == nil {
		return slog.Value{}
	}
	attrs := []slog.Attr{
		slog.String(columnUserID, u.ID),
		slog.String("username", u.Username),
		slog.String("global_name", u.GlobalName),
		slog.Bool("ignored", u.Ignored),
		slog.Bool(columnChatCommandPriority, u.Priority),
		slog.Int("user_chat_command_limit_6h", u.UserChatCommandLimit6h),
	}
	if u.ThreadID != "" {
		attrs = append(
			attrs,
			slog.String(columnChatCommandThreadID, u.ThreadID),
		)
	}

	return slog.GroupValue(attrs...)
}

// userChangedDiscordUsername compares [User.Username] and [User.GlobalName] with
// the given discordgo.User, and returns a bool indicating whether either
// field has changed (true) or not (false). This helps avoid 'drift'
// if the user updates their Discord profile.
func (u *User) userChangedDiscordUsername(d discordgo.User) bool {
	return (d.Username != u.Username) || (d.GlobalName != u.GlobalName)
}

// getStats retrieves various statistics for the user.
//
// This method collects and returns different types of usage data and statistics
// associated with the user, including ChatCommand usage, ClearCommand count,
// and feedback reports.
//
// Parameters:
//   - ctx: A context.Context for managing the database query lifecycle.
//   - db: A pointer to the gorm.DB database connection.
//
// Returns:
//   - UserStats: A struct containing the collected statistics:
//   - ChatCommandUsage: Usage statistics for ChatCommands over the last 24 hours.
//   - ClearCommands: The total number of ClearCommands executed by the user.
//   - UserFeedback: A map of feedback report types to their respective counts.
//   - error: An error if any database queries fail, or nil if successful.
//
// The method performs the following operations:
// 1. Retrieves ChatCommand usage for the last 24 hours.
// 2. Counts the total number of ClearCommands.
// 3. Collects and categorizes feedback reports submitted by the user.
//
// If any of these operations fail, the error is captured and returned along with
// any successfully retrieved data.
func (u *User) getStats(ctx context.Context, db *gorm.DB) (UserStats, error) {
	s := UserStats{Reports: map[string]int{}}

	var errs []error

	chatCommandUsage, err := GetCommandUsage6h(ctx, db, u, time.Now().UTC())
	if err != nil {
		errs = append(
			errs,
			fmt.Errorf("error getting chat command usage: %w", err),
		)
	}
	s.ChatCommandUsage = chatCommandUsage

	var clearCommandCount int64
	err = db.Unscoped().Model(&ClearCommand{}).Where(
		"user_id = ?",
		u.ID,
	).Count(&clearCommandCount).Error
	if err != nil {
		errs = append(
			errs,
			fmt.Errorf("error getting clear command stats: %w", err),
		)
	}
	s.ClearCommands = int(clearCommandCount)

	var reports []UserFeedback
	err = db.Unscoped().Select(
		"description",
	).Where("user_id = ?", u.ID).Find(&reports).Error
	if err != nil {
		errs = append(errs, fmt.Errorf("error getting report stats: %w", err))
	}
	for _, r := range reports {
		s.Reports[r.Description]++
	}

	return s, errors.Join(errs...)
}

type UserStats struct {
	ChatCommandUsage ChatCommandUsage `json:"chat_command_usage"`
	ClearCommands    int              `json:"clear_commands"`
	Reports          map[string]int   `json:"reports"`
}
