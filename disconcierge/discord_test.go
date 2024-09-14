package disconcierge

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bwmarrin/discordgo"
	"github.com/lmittmann/tint"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestUserDiscordMessageReply(t *testing.T) {
	t.Parallel()
	bot, _ := newDisConcierge(t)

	ctx := context.Background()
	u := newDiscordUser(t)

	_, _, err := bot.GetOrCreateUser(ctx, *u)
	require.NoError(t, err)

	interactionID := fmt.Sprintf("i_%s", t.Name())
	i := newDiscordInteraction(t, u, interactionID, t.Name())
	go bot.handleInteraction(
		ctx,
		bot.getInteractionHandlerFunc(ctx, i),
	)
	ac := waitForChatCommandFinish(t, ctx, bot.db, interactionID)
	if ac == nil {
		t.Fatalf("nil chat command")
	}
	messageID := fmt.Sprintf("msg_%s", t.Name())
	otherUser := newDiscordUser(t)
	otherUserID := fmt.Sprintf("ou_%s", t.Name())

	otherUser.ID = otherUserID
	otherUser.Username = "otherUsername"
	otherUser.GlobalName = "otherUserGlobalName"

	appUser := newDiscordUser(t)
	appUser.ID = bot.config.Discord.ApplicationID
	appUser.Username = "DisConcierge"
	appUser.GlobalName = "DisConcierge"

	m := &discordgo.MessageCreate{
		Message: &discordgo.Message{
			ID:      messageID,
			Author:  otherUser,
			Content: "uhhh",
			Interaction: &discordgo.MessageInteraction{
				ID:   interactionID,
				Type: discordgo.InteractionApplicationCommand,
				Name: DiscordSlashCommandChat,
				User: u,
			},
			Mentions: []*discordgo.User{appUser},
		},
	}

	bot.handleDiscordMessage(ctx, m)

	msg := waitForDiscordMessage(t, ctx, bot)
	require.NotNil(t, msg)
	assert.Equal(t, "uhhh", msg.Content)
	assert.Equal(t, otherUser.ID, msg.UserID)
	assert.Equal(t, otherUser.Username, msg.Username)
	assert.Equal(t, otherUser.GlobalName, msg.GlobalName)
	assert.Equal(t, interactionID, msg.InteractionID)
	assert.Equal(t, messageID, msg.MessageID)
}

// TestClearSlashCommandInProgress validate that, when a ChatCommand is
// in progress and we try to use `/clear` while it's executing,
// we get the appropriate interaction edit response
func TestChatCommand_ClearCommandInProgress(t *testing.T) {
	ctx := context.Background()

	bot, _ := newDisConcierge(t)
	runtimeCfg := bot.RuntimeConfig()

	bot.runtimeConfig = &runtimeCfg
	u := newDiscordUser(t)

	interactionID := fmt.Sprintf("i_chatcommand_%s", t.Name())
	i := newDiscordInteraction(t, u, interactionID, t.Name())
	handler := bot.getInteractionHandlerFunc(ctx, i)

	stubHandler, ok := handler.(stubInteractionHandler)
	if !ok {
		t.Fatal("expected stub interaction handler")
	}
	go bot.handleInteraction(
		ctx,
		handler,
	)

	actx, acancel := context.WithTimeout(ctx, 10*time.Second)
	t.Cleanup(acancel)

	select {
	case <-actx.Done():
		t.Fatalf("timeout waiting for chat command")
	case <-stubHandler.callRespond:
		acancel()
	}

	clearInteractionID := fmt.Sprintf("i_clear_%s", t.Name())
	clearInteraction := &discordgo.InteractionCreate{
		Interaction: &discordgo.Interaction{
			Type:    discordgo.InteractionApplicationCommand,
			ID:      clearInteractionID,
			User:    u,
			Context: discordgo.InteractionContextBotDM,
			Data: discordgo.ApplicationCommandInteractionData{
				CommandType: discordgo.ChatApplicationCommand,
				Name:        DiscordSlashCommandClear,
			},
		},
	}

	clearHandler := bot.getInteractionHandlerFunc(ctx, clearInteraction)
	clearStubHandler, ok := clearHandler.(stubInteractionHandler)
	if !ok {
		t.Fatal("expected stub interaction handler")
	}

	ectx, ecancel := context.WithTimeout(ctx, 10*time.Second)
	t.Cleanup(ecancel)

	go bot.handleInteraction(
		ectx,
		clearHandler,
	)

	select {
	case <-ectx.Done():
		t.Fatalf("timeout waiting for response")
	case se := <-clearStubHandler.callEdit:
		t.Logf("got interaction edit: %#v", se)
		assert.NotNil(t, t, se.WebhookEdit)
		content := se.WebhookEdit.Content
		assert.NotNil(t, content)

		assert.Equal(t, clearCommandResponseForgotten, *content)
	}
}

func TestDiscordAckResponseFlag(t *testing.T) {
	discord := &Discord{config: &DiscordConfig{}}

	testCases := []struct {
		name         string
		command      string
		expectedFlag discordgo.MessageFlags
	}{
		{
			name:         "Chat command",
			command:      "chat",
			expectedFlag: discordgo.MessageFlagsLoading,
		},
		{
			name:         "Private command",
			command:      columnChatCommandClear,
			expectedFlag: discordgo.MessageFlagsEphemeral,
		},
		{
			name:         "Clear command",
			command:      "clear",
			expectedFlag: discordgo.MessageFlagsEphemeral,
		},
		{
			name:         "Unknown command",
			command:      "unknown",
			expectedFlag: discordgo.MessageFlagsEphemeral,
		},
	}

	for _, tc := range testCases {
		t.Run(
			tc.name, func(t *testing.T) {
				result := discord.ackResponseFlag(tc.command)
				assert.Equal(
					t,
					tc.expectedFlag,
					result,
					"Unexpected flag for command %s",
					tc.command,
				)
			},
		)
	}
}

func TestDiscordButtonCustomID(t *testing.T) {
	feedbackType := UserFeedbackGood
	chatCommand := &ChatCommand{
		CustomID: "custom456",
		Interaction: Interaction{
			UserID: "user123",
		},
	}
	result := discordButtonCustomID(t, feedbackType, chatCommand)
	expectedFormat := fmt.Sprintf(
		customIDFormat,
		feedbackType,
		chatCommand.CustomID,
	)
	assert.Equal(
		t,
		expectedFormat,
		result,
		"The generated custom ID should match the expected format",
	)

	t.Run(
		"Different feedback type", func(t *testing.T) {
			result := discordButtonCustomID(t, UserFeedbackOutdated, chatCommand)
			expected := fmt.Sprintf(
				customIDFormat,
				UserFeedbackOutdated,
				chatCommand.CustomID,
			)
			assert.Equal(t, expected, result)
		},
	)

	t.Run(
		"Empty UserID", func(t *testing.T) {
			emptyUserCommand := &ChatCommand{
				CustomID: "custom789",
				Interaction: Interaction{
					UserID: "",
				},
			}
			result := discordButtonCustomID(
				t,
				UserFeedbackHallucinated,
				emptyUserCommand,
			)
			expected := fmt.Sprintf(
				customIDFormat,
				UserFeedbackHallucinated,
				emptyUserCommand.CustomID,
			)
			assert.Equal(t, expected, result)
		},
	)

	t.Run(
		"Empty CustomID", func(t *testing.T) {
			emptyCustomIDCommand := &ChatCommand{
				CustomID: "",
				Interaction: Interaction{
					UserID: "user789",
				},
			}
			result := discordButtonCustomID(
				t,
				UserFeedbackOther,
				emptyCustomIDCommand,
			)
			expected := fmt.Sprintf(
				customIDFormat,
				UserFeedbackOther,
				"",
			)
			assert.Equal(t, expected, result)
		},
	)
}

func TestIgnoredClearCommand(t *testing.T) {
	bot, _ := newDisConcierge(t)
	ctx := context.Background()
	discordUser := discordgo.User{
		ID:         t.Name(),
		Username:   t.Name(),
		GlobalName: t.Name(),
	}
	u, _, err := bot.GetOrCreateUser(ctx, discordUser)
	require.NoError(t, err)

	_, err = bot.writeDB.Update(u, "ignored", true)
	require.NoError(t, err)

	i := &discordgo.InteractionCreate{
		Interaction: &discordgo.Interaction{
			Type: discordgo.InteractionApplicationCommand,
			ID:   t.Name(),
			User: &discordUser,
			Data: discordgo.ApplicationCommandInteractionData{
				CommandType: discordgo.ChatApplicationCommand,
				Name:        DiscordSlashCommandClear,
			},
		},
	}

	bot.handleInteraction(
		context.Background(),
		bot.getInteractionHandlerFunc(context.Background(), i),
	)

	pollCtx, pollCancel := context.WithTimeout(ctx, 30*time.Second)
	t.Cleanup(pollCancel)
	clearCmdCh := make(chan *ClearCommand, 1)
	clearCmdErrCh := make(chan error, 1)
	go func() {
		defer func() {
			close(clearCmdCh)
			close(clearCmdErrCh)
		}()
		for pollCtx.Err() == nil {
			var clearCmd ClearCommand
			e := bot.db.Last(&clearCmd).Error
			if e != nil {
				if !errors.Is(e, gorm.ErrRecordNotFound) {
					clearCmdErrCh <- fmt.Errorf("error getting clear command: %w", e)
					return
				}
				continue
			}
			switch clearCmd.State {
			case ClearCommandStateCompleted, ClearCommandStateFailed, ClearCommandStateIgnored:
				clearCmdCh <- &clearCmd
				return
			case ClearCommandStateReceived:
				//
			}

			time.Sleep(500 * time.Millisecond)
		}
	}()

	select {
	case <-pollCtx.Done():
		t.Fatalf("timeout waiting for clear command")
	case clearCmdErr := <-clearCmdErrCh:
		if clearCmdErr != nil {
			t.Fatalf("error getting clear command: %v", clearCmdErr)
		}
	case clearCmd := <-clearCmdCh:
		require.NotNil(t, clearCmd)
		assert.Equal(t, ClearCommandStateIgnored, clearCmd.State)
		assert.Nil(t, clearCmd.StartedAt)
		assert.Nil(t, clearCmd.FinishedAt)
	}
}

func TestFeedbackHallucinatedExpired(t *testing.T) {
	t.Parallel()
	bot, ids, _ := newTestDisConcierge(t, nil)
	chatCommand := createTestChatCommand(t, context.Background(), bot, *ids)
	require.NotNil(t, chatCommand)

	require.Equal(t, ChatCommandStateCompleted, chatCommand.State)

	buttonCustomId := fmt.Sprintf(customIDFormat, UserFeedbackHallucinated, chatCommand.CustomID)

	buttonInteraction := &discordgo.InteractionCreate{
		Interaction: &discordgo.Interaction{
			Type: discordgo.InteractionMessageComponent,
			Data: discordgo.MessageComponentInteractionData{
				CustomID: buttonCustomId,
			},
			Member: &discordgo.Member{
				User: &discordgo.User{
					ID: ids.UserID,
				},
			},
		},
	}
	iCtx, iCancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(iCancel)

	handler := bot.getInteractionHandlerFunc(
		context.Background(),
		buttonInteraction,
	)
	go bot.handleInteraction(
		context.Background(),
		handler,
	)

	rv := waitForReport(t, iCtx, bot.db, chatCommand, UserFeedbackHallucinated)
	require.NotNil(t, rv)
	assert.Equal(t, string(UserFeedbackHallucinated), rv.Type)
	assert.Equal(t, chatCommand.CustomID, rv.CustomID)
}

func TestWebhookHandler(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	bot, mockDiscord := newDisConciergeWebhookWithContext(t, ctx)

	i := newDiscordInteraction(
		t,
		&discordgo.User{
			ID:         t.Name(),
			Username:   t.Name(),
			GlobalName: t.Name(),
		},
		t.Name(),
		"foo",
	)
	rv, err := mockDiscord.InteractionPOST(ctx, i)
	require.NoError(t, err)
	assert.NotNil(t, rv)
	assert.NotNil(t, rv.Response)
	t.Logf("response: %#v", *rv.Response)
	assert.Equal(
		t,
		int(discordgo.InteractionResponseDeferredChannelMessageWithSource),
		int(rv.Response.Type),
	)

	chatCommand := waitForChatCommandCreation(t, ctx, bot.db, "foo")
	state := waitOnChatCommandFinalState(
		t,
		ctx,
		bot.db,
		500*time.Millisecond,
		chatCommand.ID,
	)
	if state == nil {
		t.Fatal("nil state")
	}
	assert.Equal(t, ChatCommandStateCompleted, *state)
}

func TestGetInteractionOptions(t *testing.T) {
	i := &discordgo.InteractionCreate{
		Interaction: &discordgo.Interaction{
			Type: discordgo.InteractionApplicationCommand,
			ID:   "123",
			Data: discordgo.ApplicationCommandInteractionData{
				CommandType: discordgo.ChatApplicationCommand,
				Options: []*discordgo.ApplicationCommandInteractionDataOption{
					{
						Name:  chatCommandQuestionOption,
						Type:  discordgo.ApplicationCommandOptionString,
						Value: t.Name(),
					},
				},
			},
		},
	}
	optionMap := discordInteractionOptions(i)
	optionValue, ok := optionMap[chatCommandQuestionOption]
	assert.True(t, ok)
	val := optionValue.StringValue()
	assert.Equal(t, t.Name(), val)
}

func TestNewDiscordMessage(t *testing.T) {
	t.Run(
		"Full message", func(t *testing.T) {
			msg := &discordgo.Message{
				ID:        "123456",
				ChannelID: "789012",
				GuildID:   "345678",
				Content:   "Hello, world!",
				Author: &discordgo.User{
					ID:         "111111",
					Username:   "testuser",
					GlobalName: "Test User",
				},
				ReferencedMessage: &discordgo.Message{
					ID: "987654",
				},
				Interaction: &discordgo.MessageInteraction{
					ID: "246810",
				},
			}

			result := NewDiscordMessage(msg)

			assert.Equal(t, "123456", result.MessageID)
			assert.Equal(t, "Hello, world!", result.Content)
			assert.Equal(t, "789012", result.ChannelID)
			assert.Equal(t, "345678", result.GuildID)
			assert.Equal(t, "111111", result.UserID)
			assert.Equal(t, "testuser", result.Username)
			assert.Equal(t, "Test User", result.GlobalName)
			assert.Equal(t, "987654", result.ReferencedMessageID)
			assert.Equal(t, "246810", result.InteractionID)
			assert.NotEmpty(t, result.Payload)
		},
	)

	t.Run(
		"Message with Member instead of Author", func(t *testing.T) {
			msg := &discordgo.Message{
				ID:        "123456",
				ChannelID: "789012",
				GuildID:   "345678",
				Content:   "Hello, world!",
				Member: &discordgo.Member{
					User: &discordgo.User{
						ID:         "111111",
						Username:   "testuser",
						GlobalName: "Test User",
					},
				},
			}

			result := NewDiscordMessage(msg)

			assert.Equal(t, "111111", result.UserID)
			assert.Equal(t, "testuser", result.Username)
			assert.Equal(t, "Test User", result.GlobalName)
		},
	)

	t.Run(
		"Message without User or Member", func(t *testing.T) {
			msg := &discordgo.Message{
				ID:        "123456",
				ChannelID: "789012",
				GuildID:   "345678",
				Content:   "Hello, world!",
			}

			result := NewDiscordMessage(msg)

			assert.Empty(t, result.UserID)
			assert.Empty(t, result.Username)
			assert.Empty(t, result.GlobalName)
		},
	)

	t.Run(
		"Message with ReferencedMessage Interaction", func(t *testing.T) {
			msg := &discordgo.Message{
				ID:        "123456",
				ChannelID: "789012",
				GuildID:   "345678",
				Content:   "Hello, world!",
				ReferencedMessage: &discordgo.Message{
					ID: "987654",
					Interaction: &discordgo.MessageInteraction{
						ID: "246810",
					},
				},
			}

			result := NewDiscordMessage(msg)

			assert.Equal(t, "987654", result.ReferencedMessageID)
			assert.Equal(t, "246810", result.InteractionID)
		},
	)
}

// discordChannelMessageSendHandler is a DiscordSessionHandler which sends
// its outgoing discord messages/replies to channels for testing purposes
type discordChannelMessageSendHandler struct {
	DiscordSessionHandler
	errorOnSend  error
	messagesSent chan stubChannelMessageSend
	repliesSent  chan stubMessageReply
	errCh        chan error
	t            testing.TB
}

func (c discordChannelMessageSendHandler) ChannelMessageSendReply(
	channelID string,
	message string,
	messageReference *discordgo.MessageReference,
	_ ...discordgo.RequestOption,
) (*discordgo.Message, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	reply := stubMessageReply{
		ChannelID:        channelID,
		Content:          message,
		MessageReference: messageReference,
	}

	select {
	case <-ctx.Done():
		slog.Default().Error("send timed out")
	case c.repliesSent <- reply:
		slog.Default().Info("sent message", "reply", reply)
	}
	return c.DiscordSessionHandler.ChannelMessageSend(channelID, message)
}

func (c discordChannelMessageSendHandler) ChannelMessageSend(
	channelID string,
	message string,
	_ ...discordgo.RequestOption,
) (*discordgo.Message, error) {
	c.t.Logf("sending channel_id: %v message: %s", channelID, message)
	c.messagesSent <- stubChannelMessageSend{
		ChannelID: channelID,
		Content:   message,
	}
	if c.errorOnSend != nil {
		c.t.Logf("sending error: %v", c.errorOnSend)
		c.errCh <- c.errorOnSend
		return nil, c.errorOnSend
	} else {
		c.t.Logf("no error to send")
	}
	return c.DiscordSessionHandler.ChannelMessageSend(channelID, message)
}

func TestDiscord_HandlersConnectDisconnect(t *testing.T) {
	mockSession := newMockDiscordSession()
	connectSession := discordChannelMessageSendHandler{
		DiscordSessionHandler: mockSession,
		messagesSent:          make(chan stubChannelMessageSend, 100),
		repliesSent:           make(chan stubMessageReply, 100),
		errCh:                 make(chan error, 100),
		t:                     t,
	}
	channelID := fmt.Sprintf("c_%s", t.Name())
	bot := &DisConcierge{runtimeConfig: &RuntimeConfig{CommandOptions: CommandOptions{DiscordNotificationChannelID: channelID}}}
	cfg := DiscordConfig{
		StartupMessage: t.Name(),
	}
	d := &Discord{
		logger:  slog.Default(),
		config:  &cfg,
		session: connectSession,
		dc:      bot,
	}
	require.False(t, d.connected.Load())
	require.Equal(t, int64(0), d.metricConnects.Load())
	require.Equal(t, int64(0), d.metricDisconnects.Load())
	handler := d.handlerConnect()

	sess := &discordgo.Session{
		State: &discordgo.State{
			Ready: discordgo.Ready{
				SessionID: t.Name(),
				User: &discordgo.User{
					ID:       t.Name(),
					Username: t.Name(),
				},
			},
		},
	}
	handler(sess, nil)
	assert.True(t, d.connected.Load())
	assert.Equal(t, int64(1), d.metricConnects.Load())
	require.Equal(t, int64(0), d.metricDisconnects.Load())

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	select {
	case <-ctx.Done():
		t.Fatal("timed out waiting for message")
	case msgSend := <-connectSession.messagesSent:
		require.NotNil(t, msgSend)
		require.Equal(
			t,
			bot.RuntimeConfig().DiscordNotificationChannelID,
			msgSend.ChannelID,
		)
		require.Equal(t, cfg.StartupMessage, msgSend.Content)
	}

	disconnectHandler := d.handlerDisconnect()
	disconnectHandler(sess, nil)
	assert.False(t, d.connected.Load())
	assert.Equal(t, int64(1), d.metricDisconnects.Load())
	assert.Equal(t, int64(1), d.metricConnects.Load())

	// pretty hacky, but this at least shows that the error handling path
	// on sending channel messages is executing
	errMsg := fmt.Sprintf("error-%s", t.Name())
	connectSession.errorOnSend = errors.New(errMsg)
	d.session = connectSession
	handler(sess, nil)

	select {
	case <-ctx.Done():
		t.Fatal("timed out waiting for message")
	case sendErr := <-connectSession.errCh:
		require.NotNil(t, sendErr)
		require.Equal(t, sendErr.Error(), errMsg)
	}
}

type stubEdits struct {
	WebhookEdit *discordgo.WebhookEdit
	Opts        []discordgo.RequestOption
}

type stubMessageReply struct {
	ChannelID        string
	Content          string
	MessageReference *discordgo.MessageReference
}

type stubChannelMessageSend struct {
	ChannelID string
	Content   string
}

func newStubInteractionHandler(t testing.TB) stubInteractionHandler {
	t.Helper()
	return stubInteractionHandler{

		callRespond:            make(chan *discordgo.InteractionResponse, 100),
		callMessageReply:       make(chan *stubMessageReply, 100),
		callGetResponse:        make(chan struct{}, 100),
		callEdit:               make(chan *stubEdits, 100),
		callDelete:             make(chan struct{}, 100),
		callGetInteraction:     make(chan struct{}, 100),
		callChannelMessageSend: make(chan *stubChannelMessageSend, 100),
		GatewayHandler: GatewayHandler{
			session: newMockDiscordSession(),
			logger:  slog.Default().With("test_name", t.Name()),
		},
	}
}

type stubInteractionHandler struct {
	GatewayHandler GatewayHandler

	callRespond            chan *discordgo.InteractionResponse
	callGetResponse        chan struct{}
	callEdit               chan *stubEdits
	callMessageReply       chan *stubMessageReply
	callDelete             chan struct{}
	callGetInteraction     chan struct{}
	callChannelMessageSend chan *stubChannelMessageSend
	config                 CommandOptions
}

func (s stubInteractionHandler) Config() CommandOptions {
	return s.config
}

func (s stubInteractionHandler) ChannelMessageSend(
	channelID string,
	message string,
) (*discordgo.Message, error) {
	s.callChannelMessageSend <- &stubChannelMessageSend{
		ChannelID: channelID,
		Content:   message,
	}
	return &discordgo.Message{}, nil
}

func (s stubInteractionHandler) InteractionReceiveMethod() DiscordInteractionReceiveMethod {
	return DiscordInteractionReceiveMethod("testcase")
}

func (s stubInteractionHandler) ChannelMessageSendReply(
	channelID string,
	content string,
	reference *discordgo.MessageReference,
	_ ...discordgo.RequestOption,
) (*discordgo.Message, error) {
	s.callMessageReply <- &stubMessageReply{
		ChannelID:        channelID,
		Content:          content,
		MessageReference: reference,
	}
	return &discordgo.Message{}, nil
}

func (s stubInteractionHandler) Respond(
	_ context.Context,
	i *discordgo.InteractionResponse,
) error {
	s.callRespond <- i
	return nil
}

func (s stubInteractionHandler) GetResponse(context.Context) (
	*discordgo.Message,
	error,
) {
	s.Logger().Info("GetResponse called")
	s.callGetResponse <- struct{}{}
	return &discordgo.Message{}, nil
}

func (s stubInteractionHandler) Edit(
	ctx context.Context,
	e *discordgo.WebhookEdit,
	opts ...discordgo.RequestOption,
) (*discordgo.Message, error) {
	s.Logger().WarnContext(ctx, "edit called")
	s.callEdit <- &stubEdits{WebhookEdit: e, Opts: opts}
	return nil, nil
}

func (s stubInteractionHandler) Delete(
	ctx context.Context,
	_ ...discordgo.RequestOption,
) {
	s.Logger().WarnContext(ctx, "delete called")
	s.callDelete <- struct{}{}
}

func (s stubInteractionHandler) GetInteraction() *discordgo.InteractionCreate {
	s.Logger().Info("GetInteraction called")
	return s.GatewayHandler.interaction
}

func (s stubInteractionHandler) Logger() *slog.Logger {
	return s.GatewayHandler.logger
}

// generateDiscordKey creates an ed25519 public/private key pair to be
// used when testing the webhook handler
func generateDiscordKey(t testing.TB) (publicKey, privateKey string) {
	t.Helper()
	pubkey, privkey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("error generating key pair: %v", err)
	}
	return hex.EncodeToString(pubkey), string(privkey)
}

// newDiscordUser creates a new discordgo.User with the test name as
// the user ID, with the user ID also included in the username and global name
func newDiscordUser(t testing.TB) *discordgo.User {
	t.Helper()
	return &discordgo.User{
		ID:         t.Name(),
		Username:   fmt.Sprintf("u_%s", t.Name()),
		GlobalName: fmt.Sprintf("g_%s", t.Name()),
	}
}

// newDiscordInteraction creates a new discordgo.InteractionCreate instance.
//
// Parameters:
//   - t: The testing object used for logging and assertions.
//   - u: The discordgo.User who initiated the interaction.
//   - interactionID: The unique identifier for the interaction.
//   - prompt: The prompt or command associated with the interaction.
//
// Returns:
//   - *discordgo.InteractionCreate: A pointer to the newly created InteractionCreate instance.
func newDiscordInteraction(
	t testing.TB,
	u *discordgo.User,
	interactionID string,
	prompt string,
) *discordgo.InteractionCreate {
	t.Helper()
	if interactionID == "" {
		interactionID = fmt.Sprintf("interaction_%s", t.Name())
	}

	return &discordgo.InteractionCreate{
		Interaction: &discordgo.Interaction{
			Type:    discordgo.InteractionApplicationCommand,
			ID:      interactionID,
			User:    u,
			Context: discordgo.InteractionContextBotDM,
			Data: discordgo.ApplicationCommandInteractionData{
				CommandType: discordgo.ChatApplicationCommand,
				Name:        DiscordSlashCommandChat,
				Options: []*discordgo.ApplicationCommandInteractionDataOption{
					{
						Name:  chatCommandQuestionOption,
						Type:  discordgo.ApplicationCommandOptionString,
						Value: prompt,
					},
				},
			},
		},
	}
}

func waitForDiscordMessage(
	t testing.TB,
	ctx context.Context,
	bot *DisConcierge,
) *DiscordMessage {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	t.Cleanup(cancel)

	msgCh := make(chan *DiscordMessage, 1)

	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		t.Cleanup(ticker.Stop)
		for {
			select {
			case <-ctx.Done():
				msgCh <- nil
				return
			case <-ticker.C:
				var dmsg DiscordMessage
				rv := bot.db.Take(&dmsg)
				if rv.RowsAffected == 1 {
					msgCh <- &dmsg
					return
				}
			}
		}
	}()

	select {
	case <-ctx.Done():
		t.Fatal("timeout waiting for discord message")
	case msg := <-msgCh:
		if msg == nil {
			t.Fatal("nil discord message")
		}
		return msg
	}

	return nil
}

func discordButtonCustomID(
	t testing.TB, feedbackType FeedbackButtonType, chatCommand *ChatCommand,
) string {
	t.Helper()
	return fmt.Sprintf(
		customIDFormat,
		feedbackType,
		chatCommand.CustomID,
	)
}

func TestNotifyDiscordUserReachedRateLimit(t *testing.T) {
	t.Parallel()

	cfg := DefaultTestConfig(t)
	// Create a new DisConcierge instance
	discord, err := newDiscord(cfg.Discord)
	require.NoError(t, err)

	// Create a mock Discord session
	mockSession := newMockDiscordSession()
	messageHandler := discordChannelMessageSendHandler{
		DiscordSessionHandler: mockSession,
		messagesSent:          make(chan stubChannelMessageSend, 1),
		repliesSent:           make(chan stubMessageReply, 1),
		errCh:                 make(chan error, 1),
		t:                     t,
	}
	discord.session = messageHandler

	// Set up test data
	user := &User{
		ID:         "testuser123",
		GlobalName: "Test User",
	}
	usage := ChatCommandUsage{
		Billable6h:          10,
		Limit6h:             10,
		Attempted6h:         15,
		CommandsAvailableAt: time.Now().Add(1 * time.Hour),
	}
	prompt := "This is a test prompt"

	// Set up the notification channel
	notificationChannelID := "notification-channel-123"

	testLogger := slog.Default().With("test", t.Name())
	// Call the function
	ctx := context.Background()
	notifyDiscordUserReachedRateLimit(
		ctx,
		testLogger,
		discord,
		user,
		usage,
		prompt,
		notificationChannelID,
	)

	// Check if the message was sent
	select {
	case msg := <-messageHandler.messagesSent:
		assert.Equal(t, notificationChannelID, msg.ChannelID)
		assert.Contains(
			t,
			msg.Content,
			"User `Test User` (`testuser123`) reached their rate limit.",
		)
		assert.Contains(
			t,
			msg.Content,
			"**6h**: Attempted: 15 / Billable: 10 / Limit: 10",
		)

		assert.Contains(t, msg.Content, usage.CommandsAvailableAt.String())
		assert.Contains(t, msg.Content, prompt)
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for message to be sent")
	}

	// Test case when usage is below limits
	usageBelowLimit := ChatCommandUsage{
		Billable6h: 5,
		Limit6h:    10,
	}
	notifyDiscordUserReachedRateLimit(
		ctx,
		testLogger,
		discord,
		user,
		usageBelowLimit,
		prompt,
		notificationChannelID,
	)

	// Ensure no message was sent
	select {
	case <-messageHandler.messagesSent:
		t.Fatal("Message was sent when it shouldn't have been")
	case <-time.After(1 * time.Second):
		// This is the expected behavior
	}

	// Test case when notification channel is not set
	notifyDiscordUserReachedRateLimit(
		ctx,
		testLogger,
		discord,
		user,
		usageBelowLimit,
		prompt,
		"",
	)

	// Ensure no message was sent
	select {
	case <-messageHandler.messagesSent:
		t.Fatal("Message was sent when notification channel was not set")
	case <-time.After(1 * time.Second):
		// This is the expected behavior
	}
}

func TestDisConcierge_NotifyDiscordUserFeedback(t *testing.T) {
	t.Parallel()
	bot, _ := newDisConcierge(t)

	mockSession := newMockDiscordSession()
	connectSession := discordChannelMessageSendHandler{
		DiscordSessionHandler: mockSession,
		messagesSent:          make(chan stubChannelMessageSend, 100),
		repliesSent:           make(chan stubMessageReply, 100),
		errCh:                 make(chan error, 100),
		t:                     t,
	}
	bot.discord.session = connectSession

	channelID := fmt.Sprintf("c_%s", t.Name())
	bot.runtimeConfig.DiscordNotificationChannelID = channelID

	discordUser := newDiscordUser(t)
	user, _, err := bot.GetOrCreateUser(context.Background(), *discordUser)
	require.NoError(t, err)

	ids := newCommandData(t)
	interaction := newDiscordInteraction(t, discordUser, ids.InteractionID, t.Name())

	chatCommand, err := NewChatCommand(user, interaction)
	require.NoError(t, err)

	chatCommandResponse := "Foo!"
	chatCommand.Response = &chatCommandResponse

	require.NoError(t, bot.db.Create(chatCommand).Error)
	require.NoError(t, bot.hydrateChatCommand(context.Background(), chatCommand))

	var receivedMessages []stubChannelMessageSend

	wg := &sync.WaitGroup{}

	report := UserFeedback{
		ChatCommandID: &chatCommand.ID,
		UserID:        &user.ID,
		Type:          string(UserFeedbackOther),
		Description:   feedbackTypeDescription[UserFeedbackOther],
		Detail:        "The information provided is incorrect.",
	}

	ctx := context.Background()
	bot.notifyDiscordUserFeedback(ctx, *chatCommand, report)

	// Test with UserFeedbackGood
	report.Type = string(UserFeedbackGood)
	report.Description = "Good"
	report.Detail = ""

	bot.notifyDiscordUserFeedback(ctx, *chatCommand, report)

	wg.Add(3)
	go func() {
		for i := 0; i < 3; i++ {
			select {
			case msg := <-connectSession.messagesSent:
				receivedMessages = append(receivedMessages, msg)
				wg.Done()
			case <-time.After(10 * time.Second):
				t.Error("Timeout waiting for message")
				wg.Done()
			}
		}
	}()

	wg.Wait()
	require.Len(t, receivedMessages, 3)
	assert.True(t, messageContains(t, receivedMessages, "# Received feedback: **Good**"))
	assert.True(t, messageContains(t, receivedMessages, "New user seen!"))
	assert.True(t, messageContains(t, receivedMessages, ":warning: Received feedback: **Other**"))

	// Test with empty notification channel
	ct, err := bot.writeDB.Update(
		bot.runtimeConfig,
		columnRuntimeConfigDiscordNotificationChannelID,
		"",
	)
	require.Equal(t, int64(1), ct)
	require.NoError(t, err)
	require.Empty(t, bot.runtimeConfig.DiscordNotificationChannelID)
	handler := bot.getInteractionHandlerFunc(context.Background(), interaction)
	chatCommand.handler = handler
	bot.notifyDiscordUserFeedback(ctx, *chatCommand, report)

	ct, err = bot.writeDB.Update(
		bot.runtimeConfig,
		columnRuntimeConfigDiscordNotificationChannelID,
		channelID,
	)
	require.Equal(t, int64(1), ct)
	require.NoError(t, err)
	require.Equal(t, bot.runtimeConfig.DiscordNotificationChannelID, channelID)

	connectSession.errorOnSend = errors.New("failed to send message")
	bot.discord.session = connectSession
	chatCommand.handler = bot.getInteractionHandlerFunc(context.Background(), interaction)
	t.Log("sending message with error")
	bot.notifyDiscordUserFeedback(ctx, *chatCommand, report)

	select {
	case err := <-connectSession.errCh:
		assert.Error(t, err)
		assert.Equal(t, "failed to send message", err.Error())
	case <-time.After(300 * time.Second):
		t.Fatal("Timeout waiting for error")
	}
}

func messageContains(t testing.TB, messages []stubChannelMessageSend, substr string) bool {
	t.Helper()
	for _, msg := range messages {
		if strings.Contains(msg.Content, substr) {
			return true
		}
	}
	return false
}

type interactionLoadTest struct {
	user        discordgo.User
	prompt      string
	Interaction *discordgo.InteractionCreate
	Response    *discordgo.InteractionResponse
	Error       error
	StartedAt   time.Time
	FinishedAt  time.Time
}

// MockDiscord mocks the discord service itself, so we can test interactions
// received via webhook rather than websocket/gateway
type MockDiscord struct {
	PrivateKey string
	URL        string
	httpClient *http.Client
	logger     *slog.Logger
}

func (m *MockDiscord) InteractionPOST(
	ctx context.Context,
	i *discordgo.InteractionCreate,
) (*interactionLoadTest, error) {
	data, err := json.Marshal(i)
	if err != nil {
		panic(err)
	}
	m.logger.Info("sending interaction from discord", "interaction", i)
	req, err := http.NewRequest(http.MethodPost, m.URL, bytes.NewReader(data))
	if err != nil {
		panic(err)
	}
	interactionTest := &interactionLoadTest{Interaction: i}
	defer func() {
		interactionTest.FinishedAt = time.Now()
	}()
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	message := append([]byte(timestamp), data...)

	req.Header.Set("X-Signature-Timestamp", timestamp)

	signedData := ed25519.Sign(ed25519.PrivateKey(m.PrivateKey), message)
	sd := hex.EncodeToString(signedData[:])
	req.Header.Set("X-Signature-Ed25519", sd)

	req.Header.Set("Content-Type", "application/json")
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	doneCh := make(chan *http.Response, 1)
	errCh := make(chan error, 1)
	interactionTest.StartedAt = time.Now()
	go func() {
		response, e := m.httpClient.Do(req)
		if e != nil {
			errCh <- e
			_ = response.Body.Close()
		} else {
			doneCh <- response
		}
	}()

	var httpResponse *http.Response
	select {
	case <-ctx.Done():
		m.logger.Warn("timeout sending interaction", "interaction", i)
		interactionTest.Error = ctx.Err()
		return interactionTest, fmt.Errorf("timeout")
	case rv := <-doneCh:
		httpResponse = rv
	case err = <-errCh:
		m.logger.Error(
			"error sending interaction",
			"interaction",
			i,
			"error",
			err,
		)
		interactionTest.Error = err
		return interactionTest, err
	}

	var interactionResponse discordgo.InteractionResponse
	if httpResponse != nil {
		defer func() {
			_ = httpResponse.Body.Close()
		}()
	}

	err = json.NewDecoder(httpResponse.Body).Decode(&interactionResponse)
	if err != nil {
		m.logger.Error(
			"error sending interaction",
			"interaction",
			i,
			"error",
			err,
		)
		interactionTest.Error = err
		return interactionTest, err
	}
	m.logger.Info("interaction response", "response", interactionResponse)
	interactionTest.Response = &interactionResponse
	return interactionTest, nil
}

// mockDiscordSession is a mock implementation of the DiscordSessionHandler interface.
//
// This is used for testing to simulate the behavior of a real Discord session.
// It logs actions instead of performing actual operations.
type mockDiscordSession struct {
	logger   *slog.Logger
	logLevel *slog.LevelVar
}

func newMockDiscordSession() mockDiscordSession {
	m := mockDiscordSession{
		logLevel: &slog.LevelVar{},
	}
	m.logLevel.Set(slog.LevelDebug)
	m.logger = slog.New(
		tint.NewHandler(
			os.Stdout, &tint.Options{
				Level:     m.logLevel,
				AddSource: true,
			},
		),
	).With(loggerNameKey, "discord_session_handler")
	return m
}

func (d mockDiscordSession) GatewayBot(opts ...discordgo.RequestOption) (
	*discordgo.GatewayBotResponse,
	error,
) {
	d.logger.Info("gateway bot called", "options", opts)
	return &discordgo.GatewayBotResponse{}, nil
}

func (d mockDiscordSession) Open() error {
	d.logger.Info("opened session")
	return nil
}

func (d mockDiscordSession) Close() error {
	d.logger.Info("closed session")
	return nil
}

func (d mockDiscordSession) ChannelMessageSend(
	channelID string,
	message string,
	_ ...discordgo.RequestOption,
) (*discordgo.Message, error) {
	d.logger.Info(
		"saw message send",
		"channel_id", channelID,
		"content", message,
	)
	return &discordgo.Message{}, nil
}

func (d mockDiscordSession) ChannelMessageSendReply(
	channelID string,
	content string,
	reference *discordgo.MessageReference,
	_ ...discordgo.RequestOption,
) (*discordgo.Message, error) {
	d.logger.Info(
		"channel reply send",
		"channel_id", channelID,
		"message_reference", reference,
		"content", content,
	)
	return &discordgo.Message{
		Content:   content,
		ChannelID: channelID,
		GuildID:   reference.GuildID,
	}, nil
}

func (d mockDiscordSession) ApplicationCommandBulkOverwrite(
	appID string,
	guildID string,
	commands []*discordgo.ApplicationCommand,
	_ ...discordgo.RequestOption,
) ([]*discordgo.ApplicationCommand, error) {
	d.logger.Info(
		"overwrite application commands",
		"app_id",
		appID,
		"guild_id",
		guildID,
		"commands",
		commands,
	)
	cmds := make([]*discordgo.ApplicationCommand, len(commands))
	for i, c := range commands {
		cmds[i] = &discordgo.ApplicationCommand{
			Name:        c.Name,
			Description: c.Description,
		}
	}
	return cmds, nil
}

func (d mockDiscordSession) UpdateCustomStatus(status string) error {
	d.logger.Info("updating custom status", "status", status)
	return nil
}

func (d mockDiscordSession) UpdateStatusComplex(data discordgo.UpdateStatusData) error {
	d.logger.Info("updating complex status", "data", data)
	return nil
}

func (d mockDiscordSession) AddHandler(_ any) func() {
	d.logger.Info("added handler")
	return func() {
		d.logger.Info("mock-removed handler function")
	}
}

func (d mockDiscordSession) InteractionRespond(
	interaction *discordgo.Interaction,
	resp *discordgo.InteractionResponse,
	_ ...discordgo.RequestOption,
) error {
	d.logger.Info(
		"mock responding to interaction",
		"interaction", interaction,
		"response", resp,
	)
	return nil
}

func (d mockDiscordSession) InteractionResponse(
	interaction *discordgo.Interaction,
	_ ...discordgo.RequestOption,
) (*discordgo.Message, error) {
	d.logger.Info("mock getting interaction", "interaction", interaction)
	return &discordgo.Message{}, nil
}

func (d mockDiscordSession) InteractionResponseEdit(
	interaction *discordgo.Interaction,
	newresp *discordgo.WebhookEdit,
	_ ...discordgo.RequestOption,
) (*discordgo.Message, error) {
	d.logger.Info(
		"mock editing interaction",
		"interaction",
		interaction,
		"webhook_edit",
		newresp,
	)
	return &discordgo.Message{}, nil
}

func (d mockDiscordSession) InteractionResponseDelete(
	interaction *discordgo.Interaction,
	_ ...discordgo.RequestOption,
) error {
	d.logger.Info("mock deleting interaction", "interaction", interaction)
	return nil
}

func (d mockDiscordSession) SetHTTPClient(_ *http.Client) {
	d.logger.Info("mock setting http client")
}

func (d mockDiscordSession) SetIdentify(_ discordgo.Identify) {
	d.logger.Info("mock setting identify")
}

func (d mockDiscordSession) SetLogLevel(lvl slog.Level) error {
	d.logLevel.Set(lvl)
	return nil
}
