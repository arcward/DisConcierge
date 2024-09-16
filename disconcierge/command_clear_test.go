package disconcierge

import (
	"context"
	"errors"
	"fmt"
	"github.com/bwmarrin/discordgo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"testing"
	"time"
)

func TestClearCommand(t *testing.T) {
	ctx := context.Background()
	bot, _ := newDisConcierge(t)
	u := newDiscordUser(t)

	user, _, err := bot.GetOrCreateUser(ctx, *u)
	require.NoError(t, err)

	require.NoError(t, err)
	threadID := fmt.Sprintf("thread_%s", t.Name())
	_, err = bot.writeDB.Update(context.TODO(), user, columnChatCommandThreadID, threadID)
	require.NoError(t, err)
	assert.Equal(t, threadID, user.ThreadID)

	interactionID := fmt.Sprintf("i_%s", t.Name())
	clearInteraction := &discordgo.InteractionCreate{
		Interaction: &discordgo.Interaction{
			Type:    discordgo.InteractionApplicationCommand,
			ID:      interactionID,
			User:    u,
			Context: discordgo.InteractionContextBotDM,
			Data: discordgo.ApplicationCommandInteractionData{
				CommandType: discordgo.ChatApplicationCommand,
				Name:        DiscordSlashCommandClear,
			},
		},
	}

	handler := bot.getInteractionHandlerFunc(ctx, clearInteraction)
	stubHandler, ok := handler.(stubInteractionHandler)
	if !ok {
		t.Fatal("expected stub interaction handler")
	}

	ectx, ecancel := context.WithTimeout(ctx, 10*time.Second)
	t.Cleanup(ecancel)

	go bot.handleInteraction(
		ectx,
		handler,
	)

	select {
	case <-ectx.Done():
		t.Fatalf("timeout waiting for response")
	case se := <-stubHandler.callEdit:
		assert.NotNil(t, t, se.WebhookEdit)
		content := se.WebhookEdit.Content
		assert.NotNil(t, content)
		expected := "I've forgotten all your threads!"
		assert.Equal(t, expected, *content)
	}

	require.NoError(t, bot.db.Last(user).Error)
	assert.Equal(t, "", user.ThreadID)

	// if we immediately try `/clear` again, validate the edited interaction message
	clearTooSoonInteractionID := fmt.Sprintf("i_clear_too_soon_%s", t.Name())
	clearTooSoonInteraction := &discordgo.InteractionCreate{
		Interaction: &discordgo.Interaction{
			Type:    discordgo.InteractionApplicationCommand,
			ID:      clearTooSoonInteractionID,
			User:    u,
			Context: discordgo.InteractionContextBotDM,
			Data: discordgo.ApplicationCommandInteractionData{
				CommandType: discordgo.ChatApplicationCommand,
				Name:        DiscordSlashCommandClear,
			},
		},
	}

	clearTooSoonHandler := bot.getInteractionHandlerFunc(
		ctx,
		clearTooSoonInteraction,
	)
	clearTooSoonStubHandler, ok := clearTooSoonHandler.(stubInteractionHandler)
	if !ok {
		t.Fatal("expected stub interaction handler")
	}

	cctx, ccancel := context.WithTimeout(ctx, 10*time.Second)
	t.Cleanup(ccancel)

	go bot.handleInteraction(cctx, clearTooSoonHandler)

	select {
	case <-cctx.Done():
		t.Fatalf("timeout waiting for response")
	case se := <-clearTooSoonStubHandler.callEdit:
		assert.NotNil(t, t, se.WebhookEdit)
		content := se.WebhookEdit.Content
		assert.NotNil(t, content)

		assert.Equal(t, clearCommandResponseTooSoon, *content)
	}

	var clearCommand ClearCommand
	err = bot.db.Where("interaction_id = ?", interactionID).First(&clearCommand).Error
	require.NoError(t, err)
	assert.Equal(t, ClearCommandStateCompleted, clearCommand.State)
	assert.True(t, clearCommand.Acknowledged)
	assert.NotNil(t, clearCommand.FinishedAt)

}

func TestClearCommand_UpdateUserError(t *testing.T) {
	t.Parallel()

	bot, _ := newDisConcierge(t)
	ids := newCommandData(t)
	u := &discordgo.User{
		ID:         ids.UserID,
		Username:   ids.Username,
		GlobalName: ids.Username,
	}
	interaction := newClearInteraction(t, ids.InteractionID, u)
	ctx := context.Background()
	user, _, err := bot.GetOrCreateUser(ctx, *u)
	require.NoError(t, err)
	clearCommand := NewUserClearCommand(bot, user, interaction)
	_, err = bot.writeDB.Create(context.TODO(), clearCommand)
	require.NoError(t, err)

	handler := bot.getInteractionHandlerFunc(ctx, interaction)
	clearCommand.handler = handler

	df := &dbiFailedUpdate{DBI: bot.writeDB, t: t}
	bot.writeDB = df

	err = clearCommand.execute(ctx, bot)
	require.NotNil(t, t, err)

	assert.Equal(t, ClearCommandStateFailed, clearCommand.State)

	require.NotNil(t, clearCommand.Error)
	assert.Equal(t, t.Name(), *clearCommand.Error)

	require.NotNil(t, clearCommand.Response)
	assert.Equal(
		t,
		handler.Config().DiscordErrorMessage,
		*clearCommand.Response,
	)

	require.NotNil(t, clearCommand.FinishedAt)
	finishedAt := *clearCommand.FinishedAt
	assert.False(t, finishedAt.IsZero())

}

func TestClearCommandFinished(t *testing.T) {
	t.Parallel()
	bot, _ := newDisConcierge(t)

	u := newDiscordUser(t)
	interactionID := fmt.Sprintf("interaction_%s", t.Name())

	interaction := &discordgo.InteractionCreate{
		Interaction: &discordgo.Interaction{
			Type:    discordgo.InteractionApplicationCommand,
			ID:      interactionID,
			User:    u,
			Context: discordgo.InteractionContextBotDM,
			Data: discordgo.ApplicationCommandInteractionData{
				CommandType: discordgo.ChatApplicationCommand,
				Name:        DiscordSlashCommandClear,
			},
		},
	}
	ctx := context.Background()
	handler := bot.getInteractionHandlerFunc(ctx, interaction)

	go bot.handleInteraction(ctx, handler)

	pollCtx, pollCancel := context.WithTimeout(ctx, 15*time.Second)
	t.Cleanup(pollCancel)

	nowCmd := waitForClearCommandFinish(
		t,
		pollCtx,
		bot.db,
		interactionID,
	)
	require.NotNil(t, nowCmd)
	require.NotNil(t, nowCmd.FinishedAt)
	require.NotNil(t, nowCmd.Response)
	assert.NotEmpty(t, *nowCmd.Response)
}

func TestClearCommand_Run(t *testing.T) {
	ctx := context.Background()
	bot, _ := newDisConciergeWithContext(t, ctx)

	u := newDiscordUser(t)

	user, _, err := bot.GetOrCreateUser(ctx, *u)
	require.NoError(t, err)

	require.NoError(t, err)
	threadID := fmt.Sprintf("thread_%s", t.Name())
	_, err = bot.writeDB.Update(context.TODO(), user, columnChatCommandThreadID, threadID)
	require.NoError(t, err)
	assert.Equal(t, threadID, user.ThreadID)

	// verify we complete our interaction and the user's thread ID is cleared

	interactionID := fmt.Sprintf("i_%s", t.Name())
	clearInteraction := &discordgo.InteractionCreate{
		Interaction: &discordgo.Interaction{
			Type:    discordgo.InteractionApplicationCommand,
			ID:      interactionID,
			User:    u,
			Context: discordgo.InteractionContextBotDM,
			Data: discordgo.ApplicationCommandInteractionData{
				CommandType: discordgo.ChatApplicationCommand,
				Name:        DiscordSlashCommandClear,
			},
		},
	}

	handler := bot.getInteractionHandlerFunc(ctx, clearInteraction)

	clearCmd := NewUserClearCommand(bot, user, clearInteraction)
	clearCmd.handler = handler
	doneCh := make(chan struct{}, 1)

	startedCh := make(chan struct{}, 1)
	go func() {
		bot.runClearCommand(ctx, handler, clearCmd)
		startedCh <- struct{}{}
	}()

	select {
	case <-ctx.Done():
		t.Fatal("timed out")
	case <-startedCh:
		t.Logf("created command")
	}

	go func() {
		for ctx.Err() == nil {
			fv := bot.db.Last(clearCmd)
			if fv.Error != nil && !errors.Is(fv.Error, gorm.ErrRecordNotFound) {
				t.Logf("error: %v", fv.Error)
				return
			}
			if clearCmd.FinishedAt != nil {
				doneCh <- struct{}{}
				return
			}
			time.Sleep(250 * time.Millisecond)
		}
	}()
	select {
	case <-ctx.Done():
		t.Fatal("timed out")
	case <-doneCh:
		t.Logf("ran clear command")
	}
	assert.NotNil(t, clearCmd.FinishedAt)
}

func newClearInteraction(
	t testing.TB,
	interactionID string,
	u *discordgo.User,
) *discordgo.InteractionCreate {
	t.Helper()

	return &discordgo.InteractionCreate{
		Interaction: &discordgo.Interaction{
			Type:    discordgo.InteractionApplicationCommand,
			ID:      interactionID,
			User:    u,
			Context: discordgo.InteractionContextBotDM,
			Data: discordgo.ApplicationCommandInteractionData{
				CommandType: discordgo.ChatApplicationCommand,
				Name:        DiscordSlashCommandClear,
			},
		},
	}
}
