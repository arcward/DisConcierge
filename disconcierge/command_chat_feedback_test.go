package disconcierge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bwmarrin/discordgo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestNewButtons(t *testing.T) {
	tmpdir := t.TempDir()
	dbfile := filepath.Join(tmpdir, fmt.Sprintf("%s.sqlite3", t.Name()))

	db, err := CreateDB(context.Background(), "sqlite", dbfile)
	if err != nil {
		t.Fatalf("error creating db: %v", err)
	}

	u := &User{ID: "foo", Username: "bar", GlobalName: "bar"}
	err = db.Create(u).Error
	require.NoError(t, err)
	u.Username = "baz"

	customID, err := generateRandomHexString(25)
	require.NoError(t, err)
	t.Logf("custom id: %s", customID)
	assert.NotEqual(t, "", customID)
	cmd := &ChatCommand{
		CustomID: customID,
		Interaction: Interaction{
			User:   u,
			UserID: u.ID,

			InteractionID: "foo",
		},
	}
	err = db.Create(cmd).Error
	require.NoError(t, err)
	assert.Equal(t, customID, cmd.CustomID)
	reports := []UserFeedback{
		{
			ChatCommandID: &cmd.ID,
			UserID:        &u.ID,
			CustomID:      customID,
			Type:          string(UserFeedbackOutdated),
		},
		{
			ChatCommandID: &cmd.ID,
			UserID:        &u.ID,
			CustomID:      customID,
			Type:          string(UserFeedbackGood),
		},
	}
	err = db.Create(&reports).Error
	require.NoError(t, err)
}

func TestInteraction_ReportGood(t *testing.T) {
	t.Parallel()
	bot, _ := newDisConcierge(t)
	ctx := context.Background()

	handlerMu := sync.Mutex{}
	handlersCreated := map[string]stubInteractionHandler{}
	originalFunc := bot.getInteractionHandlerFunc
	bot.getInteractionHandlerFunc = func(
		funcCtx context.Context,
		funcInteraction *discordgo.InteractionCreate,
	) InteractionHandler {
		h := originalFunc(funcCtx, funcInteraction)
		handlerMu.Lock()
		defer handlerMu.Unlock()
		stubHandler, ok := h.(stubInteractionHandler)
		require.True(t, ok)
		handlersCreated[funcInteraction.ID] = stubHandler
		return h
	}

	u := newDiscordUser(t)
	interactionID := fmt.Sprintf("i_%s", t.Name())
	i := newDiscordInteraction(t, u, interactionID, t.Name())

	bot.handleInteraction(
		context.Background(),
		bot.getInteractionHandlerFunc(ctx, i),
	)

	chatCommand := waitForChatCommandFinish(t, ctx, bot.db, interactionID)
	require.NotNil(t, chatCommand)
	assert.Equal(t, ChatCommandStateCompleted, chatCommand.State)
	assert.Equal(t, ChatCommandStepFeedbackOpen, chatCommand.Step)
	t.Logf("chat command finished")

	// send 'Good' button click

	goodCustomID := discordButtonCustomID(t, UserFeedbackGood, chatCommand)

	msgContent := "foo"
	interactionMsg := &discordgo.Message{Content: msgContent}
	buttonInteractionID := fmt.Sprintf("button_%s", t.Name())
	buttonInteraction := &discordgo.InteractionCreate{
		Interaction: &discordgo.Interaction{
			Type:    discordgo.InteractionMessageComponent,
			ID:      buttonInteractionID,
			User:    u,
			Message: interactionMsg,
			Data: discordgo.MessageComponentInteractionData{
				CustomID:      goodCustomID,
				ComponentType: discordgo.ButtonComponent,
			},
		},
	}
	t.Logf("sending button interaction")
	interactionHandler := bot.getInteractionHandlerFunc(ctx, buttonInteraction)
	stubHandler, ok := interactionHandler.(stubInteractionHandler)
	require.True(t, ok)

	cctx, ccancel := context.WithTimeout(ctx, time.Minute)
	t.Cleanup(ccancel)

	bctx, bcancel := context.WithTimeout(ctx, time.Minute)
	t.Cleanup(bcancel)

	bot.handleInteraction(cctx, interactionHandler)

	var buttonResponse *discordgo.InteractionResponse

	for bctx.Err() == nil {
		rv := <-stubHandler.callRespond
		idata, err := json.Marshal(rv)
		require.NoError(t, err)
		t.Logf("interaction data: %s", string(idata))
		if rv.Type == discordgo.InteractionResponseUpdateMessage {
			buttonResponse = rv
			bcancel()
		}
	}

	require.NotNil(t, buttonResponse)
	t.Logf("got button response, waiting for button edit")

	require.NotNil(t, buttonResponse.Data)
	assert.Equal(t, discordgo.InteractionResponseUpdateMessage, buttonResponse.Type)
	buttonEdit := buttonResponse.Data

	fctx, fcancel := context.WithTimeout(ctx, 150*time.Second)
	t.Cleanup(fcancel)
	userFeedback := waitForReport(t, fctx, bot.db, chatCommand, UserFeedbackGood)
	assert.NotNil(t, userFeedback)

	assert.Equal(t, string(UserFeedbackGood), userFeedback.Type)

	goodButton := getButtonComponent(t, buttonEdit.Components, UserFeedbackGood)
	require.NotNil(t, goodButton)

	assert.Contains(t, goodButton.CustomID, userFeedback.CustomID)
	assert.Equalf(
		t,
		fmt.Sprintf("%s [%d]", feedbackTypeDescription[UserFeedbackGood], 1),
		goodButton.Label,
		"button: %#v", goodButton,
	)

	assert.Equal(t, msgContent, buttonResponse.Data.Content)

	// Send button click again, different user
	otherUser := &discordgo.User{
		ID:         "user2",
		Username:   "user2",
		GlobalName: "user2",
	}
	buttonInteractionID = fmt.Sprintf("button2_%s", t.Name())
	buttonInteraction = &discordgo.InteractionCreate{
		Interaction: &discordgo.Interaction{
			Message: interactionMsg,
			Type:    discordgo.InteractionMessageComponent,
			ID:      buttonInteractionID,
			User:    otherUser,
			Data: discordgo.MessageComponentInteractionData{
				CustomID:      goodCustomID,
				ComponentType: discordgo.ButtonComponent,
			},
		},
	}
	t.Logf("sending button interaction")
	interactionHandler = bot.getInteractionHandlerFunc(ctx, buttonInteraction)
	stubHandler, ok = interactionHandler.(stubInteractionHandler)
	require.True(t, ok)

	cctx, ccancel = context.WithTimeout(ctx, 15*time.Second)
	t.Cleanup(ccancel)

	bctx, bcancel = context.WithTimeout(ctx, 15*time.Second)
	t.Cleanup(bcancel)

	bot.handleInteraction(cctx, interactionHandler)

	buttonResponse = nil

	for bctx.Err() == nil {
		rv := <-stubHandler.callRespond
		idata, err := json.Marshal(rv)
		require.NoError(t, err)
		t.Logf("interaction data: %s", string(idata))
		if rv.Type == discordgo.InteractionResponseUpdateMessage {
			buttonResponse = rv
			bcancel()
		}
	}

	require.NotNil(t, buttonResponse)
	t.Logf("got button response, waiting for button edit")
	require.NotNil(t, buttonResponse.Data)
	buttonEdit = buttonResponse.Data
	require.NotNil(t, buttonEdit.Components)

	fctx, fcancel = context.WithTimeout(ctx, 150*time.Second)
	t.Cleanup(fcancel)
	userFeedback = waitForReport(t, fctx, bot.db, chatCommand, UserFeedbackGood)
	assert.NotNil(t, userFeedback)

	assert.Equal(t, string(UserFeedbackGood), userFeedback.Type)

	goodButton = getButtonComponent(t, buttonEdit.Components, UserFeedbackGood)
	require.NotNil(t, goodButton)

	assert.Contains(t, goodButton.CustomID, userFeedback.CustomID)
	assert.Equalf(
		t,
		fmt.Sprintf("%s [%d]", feedbackTypeDescription[UserFeedbackGood], 2),
		goodButton.Label,
		"button: %#v", goodButton,
	)

	assert.Equal(t, msgContent, buttonResponse.Data.Content)

	// Send button click again, same user as last time

	buttonInteractionID = fmt.Sprintf("button3_%s", t.Name())
	buttonInteraction = &discordgo.InteractionCreate{
		Interaction: &discordgo.Interaction{
			Message: interactionMsg,
			Type:    discordgo.InteractionMessageComponent,
			ID:      buttonInteractionID,
			User:    otherUser,
			Data: discordgo.MessageComponentInteractionData{
				CustomID:      goodCustomID,
				ComponentType: discordgo.ButtonComponent,
			},
		},
	}
	t.Logf("sending button interaction")
	interactionHandler = bot.getInteractionHandlerFunc(ctx, buttonInteraction)
	stubHandler, ok = interactionHandler.(stubInteractionHandler)
	require.True(t, ok)

	cctx, ccancel = context.WithTimeout(ctx, 15*time.Second)
	t.Cleanup(ccancel)

	bctx, bcancel = context.WithTimeout(ctx, 15*time.Second)
	t.Cleanup(bcancel)

	bot.handleInteraction(
		cctx,
		interactionHandler,
	)

	buttonResponse = nil

	for bctx.Err() == nil {
		rv := <-stubHandler.callRespond
		if rv.Type == discordgo.InteractionResponseDeferredMessageUpdate {
			buttonResponse = rv
			bcancel()
		}
	}
	require.NotNil(t, buttonResponse)

}

// waitForReport waits for a specific user feedback report to be created.
//
// This function periodically checks the database for a user feedback report
// that matches the given chat command and feedback type. It returns the
// user feedback report once it is found or fails the test if the context
// is canceled before the report is found.
func waitForReport(
	t testing.TB,
	ctx context.Context,
	db *gorm.DB,
	chatCommand *ChatCommand,
	feedbackType FeedbackButtonType,
) *UserFeedback {
	t.Helper()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			t.Fatal("timeout waiting for feedback")
		case <-ticker.C:
			var userFeedback UserFeedback
			err := db.Where(
				"chat_command_id = ? AND type = ?",
				chatCommand.ID,
				string(feedbackType),
			).First(&userFeedback).Error
			if err == nil && FeedbackButtonType(userFeedback.Type) == feedbackType {
				return &userFeedback
			}
		}
	}
}

// waitForReports waits for at least one UserFeedback report
// to be created for the given ChatCommand ID
func waitForReports(
	t testing.TB,
	ctx context.Context,
	db *gorm.DB,
	chatCommandID uint,
) []UserFeedback {
	t.Helper()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			t.Fatalf("timeout waiting for report creation: %v", ctx.Err())
		case <-ticker.C:
			t.Logf("checking reports")
			reports := []UserFeedback{}
			err := db.Where(
				"chat_command_id = ?",
				chatCommandID,
			).Find(&reports).Error
			if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
				t.Fatalf("error getting chat command: %v", err)
			}
			if len(reports) > 0 {
				return reports
			}
		}
	}
}
