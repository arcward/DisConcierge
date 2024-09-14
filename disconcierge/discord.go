package disconcierge

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/bwmarrin/discordgo"
	"github.com/lmittmann/tint"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"
)

const (
	// feedbackModalCustomID is the custom ID used for the feedback modal in
	// Discord interactions.
	feedbackModalCustomID = "report_modal"

	// discordInteractionTokenLifespan defines the lifespan of a Discord interaction token.
	// Discord interaction tokens currently expire after 15 minutes.
	discordInteractionTokenLifespan = 15 * time.Minute

	// chatCommandQuestionOption is the option name used for the chat command
	// question in Discord interactions.
	chatCommandQuestionOption = "prompt"

	// discordModalInputLabelMaxLength defines the maximum length for the label of a modal
	// input in Discord interactions.
	discordModalInputLabelMaxLength = 45

	// discordMaxButtonsPerActionRow defines the maximum number of buttons
	// allowed per action row in Discord interactions.
	discordMaxButtonsPerActionRow = 5
)

var (
	// discordComponentCustomIDLength defines the length of the custom ID for
	// Discord components. Discord currently has a 100-character limit, but
	// we don't need to use that much.
	discordComponentCustomIDLength = 25
)

// Discord represents the Discord integration for DisConcierge.
//
// It manages the Discord session, handles interactions, and provides
// methods for interacting with the Discord API.
//
// Fields:
//   - session: The Discord session handler.
//   - config: Configuration for Discord integration.
//   - logger: Logger for Discord-related events.
//   - publicKey: Ed25519 public key for verifying webhook requests.
//   - metricMessagesHandled: Counter for handled messages.
//   - metricConnects: Counter for Discord connection events.
//   - metricDisconnects: Counter for Discord disconnection events.
//   - metricReports: Counters for different types of user feedback reports.
//   - connected: Atomic boolean indicating if the Discord connection is active.
//   - discordgoRemoveHandlerFuncs: Slice of functions to remove Discord event handlers.
//
// The Discord struct is responsible for managing the connection to Discord,
// handling incoming interactions, registering commands, and providing utility
// methods for Discord-related operations.
type Discord struct {
	session                     DiscordSessionHandler
	config                      *DiscordConfig
	logger                      *slog.Logger
	publicKey                   ed25519.PublicKey
	metricConnects              atomic.Int64
	metricDisconnects           atomic.Int64
	connected                   atomic.Bool
	discordgoRemoveHandlerFuncs []func()
	dc                          *DisConcierge
}

// ackResponseFlag returns the appropriate discordgo.MessageFlags based on the given command.
func (*Discord) ackResponseFlag(command string) discordgo.MessageFlags {
	switch command {
	case DiscordSlashCommandChat:
		return discordgo.MessageFlagsLoading
	case DiscordSlashCommandPrivate:
		return discordgo.MessageFlagsEphemeral
	case DiscordSlashCommandClear:
		return discordgo.MessageFlagsEphemeral
	default:
		return discordgo.MessageFlagsEphemeral
	}
}

// newDiscord initializes a new Discord instance with the provided configuration
func newDiscord(config *DiscordConfig) (*Discord, error) {
	d := &Discord{
		config:                      config,
		discordgoRemoveHandlerFuncs: []func(){},
	}

	if config.WebhookServer.PublicKey != "" {
		publicKey, err := hex.DecodeString(config.WebhookServer.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("error decoding public key: %w", err)
		}
		d.publicKey = ed25519.PublicKey(publicKey)
	}

	return d, nil
}

// newSession initializes a new Discord session for the Discord struct.
// It sets up the session with the appropriate logger, token, and configuration.
func (d *Discord) newSession() (DiscordSessionHandler, error) {
	session := DiscordSession{logger: d.logger.With(loggerNameKey, "discord_session_handler")}
	disc, err := discordgo.New("Bot " + d.config.Token)
	if err != nil {
		return session, fmt.Errorf("error creating discord session: %w", err)
	}
	disc.SyncEvents = true
	disc.StateEnabled = false
	session.session = disc
	if d.config.httpClient != nil {
		disc.Client = d.config.httpClient
	}

	err = session.SetLogLevel(d.config.DiscordGoLogLevel.Level())
	session.session.LogLevel = discordgo.LogDebug
	if err != nil {
		return session, err
	}

	return session, nil
}

// appCommandPrivate returns ephemeral version of the `/chat` command (from appCommandChat)
func (d *Discord) appCommandPrivate(config RuntimeConfig) *discordgo.ApplicationCommand {
	chatCmd := d.appCommandChat(config)
	chatCmd.Name = DiscordSlashCommandPrivate
	chatCmd.Description = config.PrivateCommandDescription
	return chatCmd
}

// appCommandChat creates a new ApplicationCommand for the "chat" command.
// This command is used to initiate a chat interaction in Discord.
func (*Discord) appCommandChat(config RuntimeConfig) *discordgo.ApplicationCommand {
	minLength := 1
	var maxLength int
	if config.ChatCommandMaxLength > 0 {
		maxLength = config.ChatCommandMaxLength
	}
	dmPerm := true

	contexts := []discordgo.InteractionContextType{
		discordgo.InteractionContextPrivateChannel,
		discordgo.InteractionContextGuild,
		discordgo.InteractionContextBotDM,
	}

	integrationTypes := []discordgo.ApplicationIntegrationType{
		discordgo.ApplicationIntegrationUserInstall,
		discordgo.ApplicationIntegrationGuildInstall,
	}

	return &discordgo.ApplicationCommand{
		Name:             DiscordSlashCommandChat,
		Description:      config.ChatCommandDescription,
		DMPermission:     &dmPerm,
		Type:             discordgo.ChatApplicationCommand,
		Contexts:         &contexts,
		IntegrationTypes: &integrationTypes,
		Options: []*discordgo.ApplicationCommandOption{
			{
				Type:        discordgo.ApplicationCommandOptionString,
				Name:        chatCommandQuestionOption,
				Description: config.ChatCommandOptionDescription,
				Required:    true,
				MinLength:   &minLength,
				MaxLength:   maxLength,
			},
		},
	}
}

// appCommandClear creates a new ApplicationCommand for the "clear" command.
func (*Discord) appCommandClear() *discordgo.ApplicationCommand {
	contexts := []discordgo.InteractionContextType{
		discordgo.InteractionContextPrivateChannel,
		discordgo.InteractionContextGuild,
		discordgo.InteractionContextBotDM,
	}

	integrationTypes := []discordgo.ApplicationIntegrationType{
		discordgo.ApplicationIntegrationUserInstall,
		discordgo.ApplicationIntegrationGuildInstall,
	}

	return &discordgo.ApplicationCommand{
		Name:             DiscordSlashCommandClear,
		Type:             discordgo.ChatApplicationCommand,
		Description:      "Start a new thread",
		Contexts:         &contexts,
		IntegrationTypes: &integrationTypes,
	}
}

// channelMessageSend sends the given message to the given discord channel ID
func (d *Discord) channelMessageSend(
	channelID string,
	message string,
	opts ...discordgo.RequestOption,
) error {
	_, err := d.session.ChannelMessageSend(channelID, message, opts...)
	return err
}

func (d *Discord) handlerReady() func(
	s *discordgo.Session,
	r *discordgo.Ready,
) {
	return func(s *discordgo.Session, r *discordgo.Ready) {
		d.logger.Info(
			"Ready",
			"session_id", s.State.SessionID,
			columnUserID, s.State.User.ID,
			"username", s.State.User.Username,
		)
	}
}

func (d *Discord) handlerConnect() func(
	s *discordgo.Session,
	r *discordgo.Connect,
) {
	return func(s *discordgo.Session, r *discordgo.Connect) {
		d.metricConnects.Add(1)
		d.connected.Store(true)
		var sessionID string
		var userID string
		var username string

		if s != nil && s.State != nil {
			sessionID = s.State.SessionID
			if s.State.User != nil {
				userID = s.State.User.ID
				username = s.State.User.Username
			}
		}
		d.logger.Info(
			"Connected",
			"session_id", sessionID,
			slog.Group("user", "id", userID, "username", username),
		)
		config := d.dc.RuntimeConfig()
		if config.DiscordNotificationChannelID != "" {
			d.logger.Info("sending notification")
			if sendErr := d.channelMessageSend(
				config.DiscordNotificationChannelID,
				d.config.StartupMessage,
				discordgo.WithRetryOnRatelimit(false),
				discordgo.WithRestRetries(1),
			); sendErr != nil {
				d.logger.Error("unable to send startup message", tint.Err(sendErr))
			} else {
				d.logger.Info("sent notification")
			}
		}
	}
}

func (d *Discord) handlerDisconnect() func(
	s *discordgo.Session,
	r *discordgo.Disconnect,
) {
	return func(s *discordgo.Session, r *discordgo.Disconnect) {
		d.connected.Store(false)
		d.metricDisconnects.Add(1)

		var sessionID string
		var userID string
		var username string

		if s != nil && s.State != nil {
			sessionID = s.State.SessionID
			if s.State.User != nil {
				userID = s.State.User.ID
				username = s.State.User.Username
			}
		}
		d.logger.Info(
			"disconnected",
			"session_id", sessionID,
			slog.Group("user", "id", userID, "username", username),
		)
	}
}

func (d *Discord) updateCustomStatus(status string) error {
	return d.session.UpdateCustomStatus(status)
}

func (d *Discord) updateStatusComplex(data discordgo.UpdateStatusData) error {
	return d.session.UpdateStatusComplex(data)
}

// registerCommands sends the bot's commands to the discord bulk overwrite
// endpoint
func (d *Discord) registerCommands(
	runtimeConfig RuntimeConfig,
	options ...discordgo.RequestOption,
) ([]*discordgo.ApplicationCommand, error) {
	commands := []*discordgo.ApplicationCommand{
		d.appCommandChat(runtimeConfig),
		d.appCommandPrivate(runtimeConfig),
		d.appCommandClear(),
	}

	created, err := d.session.ApplicationCommandBulkOverwrite(
		d.config.ApplicationID,
		d.config.GuildID,
		commands,
		options...,
	)
	if err != nil {
		d.logger.Error("error overwriting discord commands", tint.Err(err))
		return created, err
	}
	if len(created) == 0 {
		d.logger.Warn("no commands to create")
		panic("no commands to create")
	} else {
		for _, c := range created {
			d.logger.Info("Created command", "command", c)
		}
	}

	return created, nil
}

func (d *Discord) ackResponse(commandName string) *discordgo.InteractionResponse {
	return &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Flags: d.ackResponseFlag(commandName),
		},
	}
}

// DiscordSessionHandler defines the interface for handling Discord sessions.
// This is basically defines methods from `discordgo.Session` which are
// used in this application, to enable testing/mocking.
type DiscordSessionHandler interface {
	// Open creates a websocket connection to Discord
	Open() error

	// Close closes the websocket connection to Discord
	Close() error

	// ChannelMessageSend sends a message to a specified channel.
	//
	// Parameters:
	//   - channelID: The ID of the channel where the message will be sent.
	//   - message: The content of the message to be sent.
	//   - opts: Optional request options for the message send operation.
	//
	// Returns:
	//   - *discordgo.Message: The sent message object.
	//   - error: An error if the message could not be sent.
	ChannelMessageSend(
		channelID string,
		message string,
		opts ...discordgo.RequestOption,
	) (*discordgo.Message, error)

	// ApplicationCommandBulkOverwrite overwrites Discord application commands in bulk.
	//
	// Parameters:
	//   - appID: The ID of the application.
	//   - guildID: The ID of the guild where the commands will be overwritten.
	//   - commands: A slice of ApplicationCommand objects to be overwritten.
	//   - options: Optional request options for the bulk overwrite operation.
	//
	// Returns:
	//   - []*discordgo.ApplicationCommand: A slice of the created ApplicationCommand objects.
	//   - error: An error if the bulk overwrite operation fails.
	ApplicationCommandBulkOverwrite(
		appID string,
		guildID string,
		commands []*discordgo.ApplicationCommand,
		options ...discordgo.RequestOption,
	) ([]*discordgo.ApplicationCommand, error)

	// UpdateCustomStatus sets the bot's user status to the given string.
	// If empty, sets the bot user to active and removes any existing
	// custom status.
	UpdateCustomStatus(status string) error

	// UpdateStatusComplex sends the given status update, untouched
	UpdateStatusComplex(data discordgo.UpdateStatusData) error

	// AddHandler adds a discord gateway event handler
	AddHandler(handler any) func()

	// InteractionRespond sends an interaction response to Discord
	InteractionRespond(
		interaction *discordgo.Interaction,
		resp *discordgo.InteractionResponse,
		options ...discordgo.RequestOption,
	) error

	// InteractionResponse gets the response to an interaction
	InteractionResponse(
		interaction *discordgo.Interaction,
		options ...discordgo.RequestOption,
	) (*discordgo.Message, error)

	// InteractionResponseEdit modifies the given interaction
	InteractionResponseEdit(
		interaction *discordgo.Interaction,
		newresp *discordgo.WebhookEdit,
		options ...discordgo.RequestOption,
	) (*discordgo.Message, error)

	// InteractionResponseDelete deletes the given interaction
	InteractionResponseDelete(
		interaction *discordgo.Interaction,
		options ...discordgo.RequestOption,
	) error

	// ChannelMessageSendReply sends a message to the given channel, as a
	// reply to the referenced message
	ChannelMessageSendReply(
		channelID string,
		content string,
		reference *discordgo.MessageReference,
		options ...discordgo.RequestOption,
	) (*discordgo.Message, error)

	// SetHTTPClient sets the HTTP client for the session
	SetHTTPClient(client *http.Client)

	// SetIdentify sets the identify object that's sent during the initial
	// handshake with the discord gateway
	SetIdentify(discordgo.Identify)

	// SetLogLevel modifies the session's log level
	SetLogLevel(lvl slog.Level) error

	GatewayBot(options ...discordgo.RequestOption) (st *discordgo.GatewayBotResponse, err error)
}

// DiscordSession implements DiscordSessionHandler, wrapping a
// [discordgo.Session](https://pkg.go.dev/github.com/bwmarrin/discordgo#Session)
type DiscordSession struct {
	session *discordgo.Session
	logger  *slog.Logger
}

func (d DiscordSession) GatewayBot(options ...discordgo.RequestOption) (
	st *discordgo.GatewayBotResponse,
	err error,
) {
	d.logger.Info("retrieving gateway bot")
	gb, err := d.session.GatewayBot(options...)
	if err != nil {
		d.logger.Error("error retrieving gateway bot", tint.Err(err))
	} else {
		d.logger.Info("retrieved gateway bot", "gateway_bot", structToSlogValue(gb))
	}
	return gb, err
}

func (d DiscordSession) ChannelMessageSendReply(
	channelID string,
	content string,
	reference *discordgo.MessageReference,
	options ...discordgo.RequestOption,
) (*discordgo.Message, error) {
	msg, err := d.session.ChannelMessageSendReply(
		channelID, content, reference, options...,
	)
	if err != nil {
		d.logger.Error(
			"error sending message reply",
			tint.Err(err),
			"channel_id", channelID,
			"content", content,
			"reference", reference,
		)
	} else {
		d.logger.Info(
			"sent message reply",
			"channel_id", channelID,
			"content", content,
			"reference", reference,
			"msg", msg,
		)
	}
	return msg, err
}

func (d DiscordSession) SetLogLevel(lvl slog.Level) error {
	switch lvl.Level() {
	case slog.LevelInfo:
		d.session.LogLevel = discordgo.LogInformational
	case slog.LevelWarn:
		d.session.LogLevel = discordgo.LogWarning
	case slog.LevelDebug:
		d.session.LogLevel = discordgo.LogDebug
	case slog.LevelError:
		d.session.LogLevel = discordgo.LogError
	default:
		return fmt.Errorf("invalid log level: %s", lvl)
	}
	return nil
}

func (d DiscordSession) SetHTTPClient(client *http.Client) {
	d.session.Client = client
}

func (d DiscordSession) SetIdentify(i discordgo.Identify) {
	d.session.Identify = i
}

func (d DiscordSession) InteractionRespond(
	interaction *discordgo.Interaction,
	resp *discordgo.InteractionResponse,
	options ...discordgo.RequestOption,
) error {
	return d.session.InteractionRespond(interaction, resp, options...)
}

func (d DiscordSession) InteractionResponse(
	interaction *discordgo.Interaction,
	options ...discordgo.RequestOption,
) (*discordgo.Message, error) {
	msg, err := d.session.InteractionResponse(interaction, options...)
	if err != nil {
		d.logger.Error("error getting interaction response", tint.Err(err))
	} else {
		d.logger.Info("got interaction response", columnChatCommandMessageID, msg.ID)
	}
	return msg, err
}

func (d DiscordSession) InteractionResponseEdit(
	interaction *discordgo.Interaction,
	newresp *discordgo.WebhookEdit,
	options ...discordgo.RequestOption,
) (*discordgo.Message, error) {
	return d.session.InteractionResponseEdit(interaction, newresp, options...)
}

func (d DiscordSession) InteractionResponseDelete(
	interaction *discordgo.Interaction,
	options ...discordgo.RequestOption,
) error {
	return d.session.InteractionResponseDelete(interaction, options...)
}

func (d DiscordSession) AddHandler(handler any) func() {
	return d.session.AddHandler(handler)
}

func (d DiscordSession) Open() error {
	return d.session.Open()
}

func (d DiscordSession) Close() error {
	return d.session.Close()
}

func (d DiscordSession) ChannelMessageSend(
	channelID string,
	message string,
	opts ...discordgo.RequestOption,
) (*discordgo.Message, error) {
	return d.session.ChannelMessageSend(channelID, message, opts...)
}

func (d DiscordSession) ApplicationCommandBulkOverwrite(
	appID string,
	guildID string,
	commands []*discordgo.ApplicationCommand,
	options ...discordgo.RequestOption,
) ([]*discordgo.ApplicationCommand, error) {
	created, err := d.session.ApplicationCommandBulkOverwrite(
		appID,
		guildID,
		commands,
		options...,
	)
	if err != nil {
		d.logger.Error("error overwriting discord commands", tint.Err(err))
		return created, err
	}
	for _, c := range created {
		d.logger.Info("Created command", "command", c)
	}

	return created, nil
}

func (d DiscordSession) UpdateCustomStatus(
	status string,
) error {
	return d.session.UpdateCustomStatus(status)
}

func (d DiscordSession) UpdateStatusComplex(
	data discordgo.UpdateStatusData,
) error {
	return d.session.UpdateStatusComplex(data)
}

// DiscordMessage is a DB model which logs details about an incoming discord message
// received via the discordgo.MessageCreate handler.
// These are generally limited to messages that solely mention
// the bot user, reference a known interaction ID (for a slash command),
type DiscordMessage struct {
	ModelUintID
	ModelUnixTime
	MessageID           string `json:"message_id"`
	Content             string `json:"content"`
	ChannelID           string `json:"channel_id"`
	GuildID             string `json:"guild_id"`
	UserID              string `json:"user_id"`
	Username            string `json:"username"`
	GlobalName          string `json:"global_name"`
	InteractionID       string `json:"interaction_id"`
	ReferencedMessageID string `json:"referenced_message_id"`
	Payload             string `json:"payload"`
}

func NewDiscordMessage(m *discordgo.Message) DiscordMessage {
	user := m.Author
	if user == nil && m.Member != nil {
		user = m.Member.User
	}
	dm := DiscordMessage{
		MessageID: m.ID,
		Content:   m.Content,
		ChannelID: m.ChannelID,
		GuildID:   m.GuildID,
	}

	if user != nil {
		dm.UserID = user.ID
		dm.Username = user.Username
		dm.GlobalName = user.GlobalName
	}

	if m.MessageReference != nil {
		dm.ReferencedMessageID = m.MessageReference.MessageID
	} else if m.ReferencedMessage != nil {
		dm.ReferencedMessageID = m.ReferencedMessage.ID
	}

	if m.Interaction != nil {
		dm.InteractionID = m.Interaction.ID
	}
	if dm.InteractionID == "" && m.ReferencedMessage != nil && m.ReferencedMessage.Interaction != nil {
		dm.InteractionID = m.ReferencedMessage.Interaction.ID
	}
	data, err := json.Marshal(m)
	if err != nil {
		slog.Default().Error("failed to marshal discord message", tint.Err(err))
	}
	dm.Payload = string(data)
	return dm
}

func (m DiscordMessage) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String(columnChatCommandMessageID, m.MessageID),
		slog.String("channel_id", m.ChannelID),
		slog.String("guild_id", m.GuildID),
		slog.String(columnUserID, m.UserID),
		slog.String("username", m.Username),
		slog.String("global_name", m.GlobalName),
		slog.String(columnChatCommandInteractionID, m.InteractionID),
		slog.String("referenced_message_id", m.ReferencedMessageID),
		slog.String("content", m.Content),
	)
}

// messageMentionsUser checks if a given discord message mentions the
// given user ID (does not indicate if the message content itself contains
// the user, just if the message mentions the user via @).
// Returns true if the message mentions the user, otherwise false.
func messageMentionsUser(m *discordgo.Message, userID string) bool {
	if m == nil {
		return false
	}
	if len(m.Mentions) == 0 {
		return false
	}
	for _, mention := range m.Mentions {
		if mention.ID == userID {
			return true
		}
	}
	return false
}

// getDiscordUser returns the [discordgo.User] associated with the interaction.
// Users don't always appear in the same place in the interaction object, so
// this checks known areas.
func getDiscordUser(i *discordgo.InteractionCreate) *discordgo.User {
	u := i.User
	if u == nil && i.Member != nil {
		u = i.Member.User
	}
	return u
}

// discordModalResponse returns a discordgo.InteractionResponse containing
// a modal with a text input component created using the given parameters
func discordModalResponse(
	customID string,
	title string,
	label string,
	placeholder string,
	minLength int,
	maxLength int,
) *discordgo.InteractionResponse {
	return &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseModal,
		Data: &discordgo.InteractionResponseData{
			CustomID: feedbackModalCustomID,
			Title:    title,
			Components: []discordgo.MessageComponent{
				discordgo.ActionsRow{
					Components: []discordgo.MessageComponent{
						discordgo.TextInput{
							CustomID:    customID,
							Label:       label,
							Style:       discordgo.TextInputParagraph,
							Placeholder: placeholder,
							Required:    true,
							MinLength:   minLength,
							MaxLength:   maxLength,
						},
					},
				},
			},
		},
	}
}
