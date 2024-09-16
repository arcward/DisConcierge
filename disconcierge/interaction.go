package disconcierge

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bwmarrin/discordgo"
	"github.com/lmittmann/tint"
	"log/slog"
	"time"
)

//nolint:lll // struct tags can't be split
type InteractionLog struct {
	ModelUintID
	Method        DiscordInteractionReceiveMethod `json:"method" gorm:"type:string"` // webhook or gateway
	InteractionID string                          `json:"interaction_id" gorm:"not null"`
	Type          string                          `json:"type" gorm:"type:string"`
	UserID        string                          `json:"user_id" gorm:"not null"`
	Username      string                          `json:"username" gorm:"type:string"`
	AppID         string                          `json:"application_id" gorm:"type:string"`
	GuildID       string                          `json:"guild_id" gorm:"type:string"`
	ChannelID     string                          `json:"channel_id" gorm:"type:string"`
	Context       string                          `json:"context" gorm:"type:string"`
	Payload       string                          `json:"payload" gorm:"type:string"`
	CreatedAt     int64                           `gorm:"autoCreateTime:milli" json:"created_at,omitempty"`
}

func newInteractionLog(
	i *discordgo.InteractionCreate,
	u *discordgo.User,
	handler InteractionHandler,
) (*InteractionLog, error) {
	p, err := json.Marshal(i)
	if err != nil {
		return nil, fmt.Errorf("error marshaling interaction: %w", err)
	}

	interactionLog := &InteractionLog{
		InteractionID: i.ID,
		Type:          i.Type.String(),
		UserID:        u.ID,
		Username:      u.String(),
		GuildID:       i.GuildID,
		ChannelID:     i.ChannelID,
		Context:       i.Context.String(),
		Payload:       string(p),
		Method:        handler.InteractionReceiveMethod(),
	}
	return interactionLog, nil
}

// Interaction is a 'base' struct of fields for Discord interactions, shared
// across interaction types
type Interaction struct {
	UserID           string     `json:"user_id" gorm:"index;not null;default:null"`
	InteractionID    string     `json:"interaction_id" gorm:"not null;default:null;uniqueIndex"`
	DiscordMessageID string     `json:"discord_message_id" gorm:"type:string"`
	Token            string     `json:"token" gorm:"type:string"`
	TokenExpires     int64      `json:"token_expires"`
	AppID            string     `json:"application_id"`
	Type             string     `json:"type"`
	GuildID          string     `json:"guild_id"`
	ChannelID        string     `json:"channel_id"`
	CommandContext   string     `json:"context" gorm:"type:string"`
	Content          string     `json:"content" gorm:"type:string"`
	User             *User      `json:"user" gorm:"->"`
	StartedAt        *time.Time `json:"started_at" gorm:"type:timestamp"`

	FinishedAt   *time.Time `json:"finished_at" gorm:"type:timestamp"`
	Acknowledged bool       `json:"acknowledged"`

	// Response is the content of the final message returned
	// to the other, either the successful 'answer' response,
	// or possibly an error/warning message
	Response *string `json:"response" gorm:"type:string"`

	// Error is a string representation of error(s) encountered
	// while processing the request
	Error NullableString `json:"error"` // gorm:"default:null"`
}

func NewUserInteraction(i *discordgo.InteractionCreate, u *User) *Interaction {
	created := time.Now().UTC()
	r := &Interaction{
		InteractionID:  i.ID,
		Token:          i.Token,
		TokenExpires:   created.Add(discordInteractionTokenLifespan).UnixMilli(),
		AppID:          i.AppID,
		Type:           i.Type.String(),
		GuildID:        i.GuildID,
		ChannelID:      i.ChannelID,
		CommandContext: i.Context.String(),
	}
	if u != nil {
		r.User = u
		r.UserID = u.ID
	}

	content, err := json.Marshal(i)
	if err != nil {
		slog.Default().Error(
			"error marshaling json",
			tint.Err(err),
			"interaction", r,
		)
	}
	r.Content = string(content)

	return r
}

func (i Interaction) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String(columnUserID, i.UserID),
		slog.String(columnChatCommandInteractionID, i.InteractionID),
		slog.Int64("token_expires", i.TokenExpires),
		slog.String("app_id", i.AppID),
		slog.String("type", i.Type),
		slog.String("command_context", i.CommandContext),
	)
}

type NullableString string

//goland:noinspection GoMixedReceiverTypes
func (ns *NullableString) Scan(value any) error {
	if value == nil {
		*ns = ""
		return nil
	}
	strVal, ok := value.(string)
	if !ok {
		return errors.New("failed to cast to string")
	}
	*ns = NullableString(strVal)
	return nil
}

//goland:noinspection GoMixedReceiverTypes
func (ns NullableString) Value() (driver.Value, error) {
	if ns == "" {
		return nil, nil
	}
	return string(ns), nil
}

//goland:noinspection GoMixedReceiverTypes
func (ns NullableString) MarshalJSON() ([]byte, error) {
	if ns == "" {
		return []byte("null"), nil
	}
	return json.Marshal(string(ns))
}

//goland:noinspection GoMixedReceiverTypes
func (ns *NullableString) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*ns = ""
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	*ns = NullableString(s)
	return nil
}

//goland:noinspection GoMixedReceiverTypes
func (ns NullableString) GoString() string {
	return string(ns)
}

//goland:noinspection GoMixedReceiverTypes
func (ns NullableString) String() string {
	return string(ns)
}
