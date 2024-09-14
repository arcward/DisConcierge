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

func TestUndoCount(t *testing.T) {
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
			Type:          string(UserFeedbackReset),
		},
		{
			ChatCommandID: &cmd.ID,
			UserID:        &u.ID,
			CustomID:      customID,
			Type:          string(UserFeedbackReset),
		},
		{
			ChatCommandID: &cmd.ID,
			UserID:        &u.ID,
			CustomID:      customID,
			Type:          string(UserFeedbackReset),
		},
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
			Type:          string(UserFeedbackReset),
		},
		{
			ChatCommandID: &cmd.ID,
			UserID:        &u.ID,
			CustomID:      customID,
			Type:          string(UserFeedbackReset),
		},
		{
			ChatCommandID: &cmd.ID,
			UserID:        &u.ID,
			CustomID:      customID,
			Type:          string(UserFeedbackReset),
		},
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

func TestStateButtons(t *testing.T) {
	t.Parallel()
	bot, _ := newDisConcierge(t)
	u := &discordgo.User{ID: "foo", Username: "bar"}

	user, _, err := bot.GetOrCreateUser(context.Background(), *u)
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, u.ID, user.ID)

	interactionID := "123"

	commandPrompt := "foo"
	interaction := &discordgo.InteractionCreate{
		Interaction: &discordgo.Interaction{
			Type: discordgo.InteractionApplicationCommand,
			ID:   interactionID,
			User: u,
			Data: discordgo.ApplicationCommandInteractionData{
				CommandType: discordgo.ChatApplicationCommand,
				Name:        DiscordSlashCommandChat,
				Options: []*discordgo.ApplicationCommandInteractionDataOption{
					{
						Name:  chatCommandQuestionOption,
						Type:  discordgo.ApplicationCommandOptionString,
						Value: commandPrompt,
					},
				},
			},
		},
	}

	go bot.handleInteraction(
		context.Background(),
		bot.getInteractionHandlerFunc(context.Background(), interaction),
	)
	checkCtx, checkCancel := context.WithTimeout(
		context.Background(),
		15*time.Second,
	)
	t.Cleanup(checkCancel)

	chatCommand := waitForChatCommandCreation(
		t,
		checkCtx,
		bot.db,
		interactionID,
	)
	require.NotNil(t, chatCommand)
	checkCancel()
	require.NotNil(t, chatCommand.User)
	assert.Equal(t, user.ID, chatCommand.UserID)
	assert.NotEqual(t, "", chatCommand.CustomID)
	assert.Equal(t, commandPrompt, chatCommand.Prompt)

	pollCtx, pollCancel := context.WithTimeout(
		context.Background(),
		10*time.Second,
	)
	t.Cleanup(pollCancel)
	finalStatus := waitOnChatCommandFinalState(
		t,
		pollCtx,
		bot.db,
		500*time.Millisecond,
		chatCommand.ID,
	)
	if finalStatus == nil {
		t.Fatalf("expected final status to not be nil")
	}
	assert.Equal(t, ChatCommandStateCompleted, *finalStatus)

	cmd := chatCommand

	checkCancel()
	require.NoError(t, bot.hydrateChatCommand(context.Background(), cmd))

	assert.Equal(t, FeedbackButtonStateEnabled, cmd.FeedbackButtonStateGood)
	assert.Equal(t, FeedbackButtonStateEnabled, cmd.FeedbackButtonStateHallucinated)
	assert.Equal(t, FeedbackButtonStateEnabled, cmd.FeedbackButtonStateOther)
	assert.Equal(t, FeedbackButtonStateEnabled, cmd.FeedbackButtonStateOutdated)
	assert.Equal(t, FeedbackButtonStateHidden, cmd.FeedbackButtonStateReset)

	assert.NotNil(t, cmd.OtherButton())
	assert.NotNil(t, cmd.HallucinatedButton())
	assert.NotNil(t, cmd.GoodButton())
	assert.NotNil(t, cmd.OutdatedButton())
	assert.Nil(t, cmd.UndoButton())

	goodReport := cmd.createReport(UserFeedbackGood, "")

	err = cmd.newDMReport(
		context.Background(),
		bot.writeDB,
		&goodReport,
	)
	require.NoError(t, err)

	assert.Equal(t, FeedbackButtonStateDisabled, cmd.FeedbackButtonStateGood)
	assert.Equal(t, FeedbackButtonStateHidden, cmd.FeedbackButtonStateHallucinated)
	assert.Equal(t, FeedbackButtonStateHidden, cmd.FeedbackButtonStateOther)
	assert.Equal(t, FeedbackButtonStateHidden, cmd.FeedbackButtonStateOutdated)
	assert.Equal(t, FeedbackButtonStateEnabled, cmd.FeedbackButtonStateReset)

	assert.Nil(t, cmd.OtherButton())
	assert.Nil(t, cmd.HallucinatedButton())
	assert.NotNil(t, cmd.GoodButton())
	assert.Nil(t, cmd.OutdatedButton())
	assert.NotNil(t, cmd.UndoButton())

	undoReport := cmd.createReport(UserFeedbackReset, "")
	err = cmd.newDMReport(
		context.Background(),
		bot.writeDB,
		&undoReport,
	)
	require.NoError(t, err)

	assert.Equal(t, FeedbackButtonStateEnabled, cmd.FeedbackButtonStateOutdated)
	assert.Equal(t, FeedbackButtonStateEnabled, cmd.FeedbackButtonStateHallucinated)
	assert.Equal(t, FeedbackButtonStateEnabled, cmd.FeedbackButtonStateOther)
	assert.Equal(t, FeedbackButtonStateHidden, cmd.FeedbackButtonStateReset)
	assert.Equal(t, FeedbackButtonStateEnabled, cmd.FeedbackButtonStateGood)

	assert.NotNil(t, cmd.OtherButton())
	assert.NotNil(t, cmd.HallucinatedButton())
	assert.NotNil(t, cmd.GoodButton())
	assert.NotNil(t, cmd.OutdatedButton())
	assert.Nil(t, cmd.UndoButton())

	outdatedReport := cmd.createReport(UserFeedbackOutdated, "")

	err = cmd.newDMReport(
		context.Background(),
		bot.writeDB,
		&outdatedReport,
	)
	require.NoError(t, err)

	assert.Equal(t, FeedbackButtonStateDisabled, cmd.FeedbackButtonStateOutdated)
	assert.Equal(t, FeedbackButtonStateEnabled, cmd.FeedbackButtonStateHallucinated)
	assert.Equal(t, FeedbackButtonStateEnabled, cmd.FeedbackButtonStateOther)
	assert.Equal(t, FeedbackButtonStateEnabled, cmd.FeedbackButtonStateReset)
	assert.Equal(t, FeedbackButtonStateHidden, cmd.FeedbackButtonStateGood)

	assert.NotNil(t, cmd.OtherButton())
	assert.NotNil(t, cmd.HallucinatedButton())
	assert.Nil(t, cmd.GoodButton())
	assert.NotNil(t, cmd.OutdatedButton())
	assert.NotNil(t, cmd.UndoButton())

	otherReport := cmd.createReport(UserFeedbackOther, "asdf")

	err = cmd.newDMReport(
		context.Background(),
		bot.writeDB,
		&otherReport,
	)
	require.NoError(t, err)

	assert.Equal(t, FeedbackButtonStateDisabled, cmd.FeedbackButtonStateOutdated)
	assert.Equal(t, FeedbackButtonStateEnabled, cmd.FeedbackButtonStateHallucinated)
	assert.Equal(t, FeedbackButtonStateDisabled, cmd.FeedbackButtonStateOther)
	assert.Equal(t, FeedbackButtonStateEnabled, cmd.FeedbackButtonStateReset)
	assert.Equal(t, FeedbackButtonStateHidden, cmd.FeedbackButtonStateGood)

	assert.NotNil(t, cmd.OtherButton())
	assert.NotNil(t, cmd.HallucinatedButton())
	assert.Nil(t, cmd.GoodButton())
	assert.NotNil(t, cmd.OutdatedButton())
	assert.NotNil(t, cmd.UndoButton())
}

func TestInteraction_ReportOther(t *testing.T) {
	t.Parallel()
	bot, _ := newDisConcierge(t)
	ctx := context.Background()

	u := newDiscordUser(t)
	interactionID := fmt.Sprintf("i_%s", t.Name())
	i := newDiscordInteraction(t, u, interactionID, t.Name())

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
		if !ok {
			t.Fatalf("sdfsdf")
		}
		_, ok = handlersCreated[funcInteraction.ID]
		if ok {
			t.Logf("handler already created")
		}
		handlersCreated[funcInteraction.ID] = stubHandler
		return h
	}

	bot.handleInteraction(
		context.Background(),
		bot.getInteractionHandlerFunc(ctx, i),
	)

	chatCommand := waitForChatCommandFinish(t, ctx, bot.db, interactionID)
	require.NotNil(t, chatCommand)
	assert.Equal(t, ChatCommandStateCompleted, chatCommand.State)
	assert.Equal(t, ChatCommandStepFeedbackOpen, chatCommand.Step)

	buttonInteractionID := fmt.Sprintf("button_%s", t.Name())
	otherCustomID := discordButtonCustomID(t, UserFeedbackOther, chatCommand)
	buttonInteraction := &discordgo.InteractionCreate{
		Interaction: &discordgo.Interaction{
			Type: discordgo.InteractionMessageComponent,
			ID:   buttonInteractionID,
			User: u,
			Data: discordgo.MessageComponentInteractionData{
				CustomID:      otherCustomID,
				ComponentType: discordgo.ButtonComponent,
			},
		},
	}

	interactionHandler := bot.getInteractionHandlerFunc(ctx, buttonInteraction)
	stubHandler, ok := interactionHandler.(stubInteractionHandler)
	if !ok {
		t.Fatal("expected stub interaction handler")
	}
	bot.handleInteraction(
		context.Background(),
		interactionHandler,
	)

	bctx, bcancel := context.WithTimeout(ctx, 10*time.Second)
	t.Cleanup(bcancel)

	var buttonResponse *discordgo.InteractionResponse

	for bctx.Err() == nil {
		rv := <-stubHandler.callRespond
		idata, err := json.Marshal(rv)
		require.NoError(t, err)
		t.Logf("interaction data: %s", string(idata))
		if rv.Type == discordgo.InteractionResponseModal {
			buttonResponse = rv
			bcancel()
		}
	}

	require.NotNil(t, buttonResponse)

	buttonData := buttonResponse.Data
	require.NotNil(t, buttonData)

	assert.Equal(t, feedbackModalCustomID, buttonData.CustomID)
	assert.Equal(
		t,
		bot.RuntimeConfig().FeedbackModalTitle,
		buttonData.Title,
	)
	assert.Len(t, buttonData.Components, 1)
	actionsRow, ok := buttonData.Components[0].(discordgo.ActionsRow)
	if !ok {
		t.Fatalf("wrong type")
	}

	assert.Len(t, actionsRow.Components, 1)
	textInput, ok := actionsRow.Components[0].(discordgo.TextInput)
	if !ok {
		t.Fatalf("wrong type")
	}
	assert.Equal(t, otherCustomID, textInput.CustomID)
	assert.Equal(
		t,
		bot.RuntimeConfig().FeedbackModalInputLabel,
		textInput.Label,
	)
	assert.Equal(
		t,
		bot.RuntimeConfig().FeedbackModalPlaceholder,
		textInput.Placeholder,
	)
	assert.True(t, textInput.Required)
	assert.Equal(
		t,
		bot.RuntimeConfig().FeedbackModalMinLength,
		textInput.MinLength,
	)
	assert.Equal(
		t,
		bot.RuntimeConfig().FeedbackModalMaxLength,
		textInput.MaxLength,
	)

	reportContent := t.Name()

	row := &discordgo.ActionsRow{
		Components: []discordgo.MessageComponent{
			&discordgo.TextInput{
				CustomID: otherCustomID,
				Value:    reportContent,
			},
		},
	}

	submitData := discordgo.ModalSubmitInteractionData{
		CustomID: feedbackModalCustomID,
		Components: []discordgo.MessageComponent{
			row,
		},
	}

	modalInteractionID := fmt.Sprintf("modal_%s", t.Name())
	modalInteraction := &discordgo.InteractionCreate{
		Interaction: &discordgo.Interaction{
			ID:     modalInteractionID,
			Type:   discordgo.InteractionModalSubmit,
			Data:   submitData,
			Member: &discordgo.Member{User: u},
		},
	}

	modalHandler := bot.getInteractionHandlerFunc(ctx, modalInteraction)
	modalStubHandler, ok := modalHandler.(stubInteractionHandler)
	if !ok {
		t.Fatal("expected stub interaction handler")
	}
	bot.handleInteraction(
		context.Background(),
		modalHandler,
	)

	mctx, mcancel := context.WithTimeout(ctx, 10*time.Second)
	t.Cleanup(mcancel)

	var modalResponse *discordgo.InteractionResponse
	for mctx.Err() == nil {
		rv := <-modalStubHandler.callRespond
		idata, err := json.Marshal(rv)
		require.NoError(t, err)
		t.Logf("interaction data: %s", string(idata))
		if rv.Type == discordgo.InteractionResponseDeferredMessageUpdate {
			modalResponse = rv
			mcancel()
		}
	}

	if modalResponse == nil {
		t.Fatal("nil response")
	}

	innerHandler, ok := handlersCreated[interactionID]
	if !ok {
		t.Fatalf("no handler found")
	}

	var buttonEdit *stubEdits
	ectx, ecancel := context.WithTimeout(ctx, 10*time.Second)
	t.Cleanup(ecancel)

	for ectx.Err() == nil {
		rv := <-innerHandler.callEdit
		buttonEdit = rv
		ecancel()
	}
	require.NotNil(t, buttonEdit)
	require.NotNil(t, buttonEdit.WebhookEdit)
	require.NotNil(t, buttonEdit.WebhookEdit.Components)

	fctx, fcancel := context.WithTimeout(ctx, 10*time.Second)
	t.Cleanup(fcancel)
	userFeedback := waitForReport(t, fctx, bot.db, chatCommand, UserFeedbackOther)
	assert.NotNil(t, userFeedback)

	assert.Equal(t, reportContent, userFeedback.Detail)

	otherButton := getButtonComponent(
		t,
		*buttonEdit.WebhookEdit.Components,
		UserFeedbackOther,
	)

	if assert.NotNil(t, otherButton) {
		assert.True(t, otherButton.Disabled)
		assert.Contains(t, otherButton.CustomID, userFeedback.CustomID)
	}
	undoButton := getButtonComponent(
		t,
		*buttonEdit.WebhookEdit.Components,
		UserFeedbackReset,
	)
	if assert.NotNil(t, undoButton) {
		assert.False(t, undoButton.Disabled)
	}
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
		if !ok {
			t.Fatalf("sdfsdf")
		}
		_, ok = handlersCreated[funcInteraction.ID]
		if ok {
			t.Logf(
				"handler already created for interaction '%s'",
				funcInteraction.ID,
			)
		}
		t.Logf(
			"added handler for interaction '%s': %#v",
			funcInteraction.ID,
			handlersCreated,
		)
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
	goodCustomID := discordButtonCustomID(t, UserFeedbackGood, chatCommand)

	buttonInteractionID := fmt.Sprintf("button_%s", t.Name())
	buttonInteraction := &discordgo.InteractionCreate{
		Interaction: &discordgo.Interaction{
			Type: discordgo.InteractionMessageComponent,
			ID:   buttonInteractionID,
			User: u,
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

	cctx, ccancel := context.WithTimeout(ctx, 15*time.Second)
	t.Cleanup(ccancel)

	bctx, bcancel := context.WithTimeout(ctx, 15*time.Second)
	t.Cleanup(bcancel)

	bot.handleInteraction(
		cctx,
		interactionHandler,
	)

	var buttonResponse *discordgo.InteractionResponse

	for bctx.Err() == nil {
		rv := <-stubHandler.callRespond
		idata, err := json.Marshal(rv)
		require.NoError(t, err)
		t.Logf("interaction data: %s", string(idata))
		if rv.Type == discordgo.InteractionResponseDeferredMessageUpdate {
			buttonResponse = rv
			bcancel()
		}
	}

	require.NotNil(t, buttonResponse)
	t.Logf("got button response, waiting for button edit")

	innerHandler, ok := handlersCreated[interactionID]
	require.True(t, ok)

	var buttonEdit *stubEdits
	ectx, ecancel := context.WithTimeout(ctx, 10*time.Second)
	t.Cleanup(ecancel)

	select {
	case rv := <-innerHandler.callEdit:
		buttonEdit = rv
		ecancel()
	case <-ectx.Done():
		t.Fatalf("timed out waiting for button edit")
	}

	require.NotNil(t, buttonEdit)
	require.NotNil(t, buttonEdit.WebhookEdit)
	require.NotNil(t, buttonEdit.WebhookEdit.Components)

	fctx, fcancel := context.WithTimeout(ctx, 150*time.Second)
	t.Cleanup(fcancel)
	userFeedback := waitForReport(t, fctx, bot.db, chatCommand, UserFeedbackGood)
	assert.NotNil(t, userFeedback)

	assert.Equal(t, string(UserFeedbackGood), userFeedback.Type)

	goodButton := getButtonComponent(
		t,
		*buttonEdit.WebhookEdit.Components,
		UserFeedbackGood,
	)
	if assert.NotNil(t, goodButton) {
		assert.True(t, goodButton.Disabled)
		assert.Contains(t, goodButton.CustomID, userFeedback.CustomID)
	}
	undoButton := getButtonComponent(
		t,
		*buttonEdit.WebhookEdit.Components,
		UserFeedbackReset,
	)
	if assert.NotNil(t, undoButton) {
		assert.False(t, undoButton.Disabled)
	}

	assert.Nil(
		t,
		getButtonComponent(
			t,
			*buttonEdit.WebhookEdit.Components,
			UserFeedbackHallucinated,
		),
	)
	assert.Nil(
		t,
		getButtonComponent(t, *buttonEdit.WebhookEdit.Components, UserFeedbackOther),
	)
	assert.Nil(
		t,
		getButtonComponent(
			t,
			*buttonEdit.WebhookEdit.Components,
			UserFeedbackOutdated,
		),
	)

	err := bot.db.Last(chatCommand).Error
	require.NoError(t, err)

	assert.Equal(t, FeedbackButtonStateDisabled, chatCommand.FeedbackButtonStateGood)
}

func TestInteraction_ReportGoodGuild(t *testing.T) {
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
		if !ok {
			t.Fatalf("expected stub interaction handler")
		}
		handlersCreated[funcInteraction.ID] = stubHandler
		return h
	}

	// Create two different users
	commandUser := newDiscordUser(t)
	feedbackUser := &discordgo.User{
		ID:         fmt.Sprintf("other_%s", t.Name()),
		Username:   fmt.Sprintf("u_other_%s", t.Name()),
		GlobalName: fmt.Sprintf("g_other_%s", t.Name()),
	}
	require.NotEqual(t, commandUser.ID, feedbackUser.ID)

	interactionID := fmt.Sprintf("i_%s", t.Name())
	i := newDiscordInteraction(t, commandUser, interactionID, t.Name())
	i.GuildID = "test_guild_id" // Set a guild ID to simulate a guild interaction
	i.Context = discordgo.InteractionContextGuild
	bot.handleInteraction(
		context.Background(),
		bot.getInteractionHandlerFunc(ctx, i),
	)

	chatCommand := waitForChatCommandFinish(t, ctx, bot.db, interactionID)
	assert.Equal(t, ChatCommandStateCompleted, chatCommand.State)
	assert.Equal(t, ChatCommandStepFeedbackOpen, chatCommand.Step)

	goodCustomID := discordButtonCustomID(t, UserFeedbackGood, chatCommand)

	buttonInteractionID := fmt.Sprintf("button_%s", t.Name())
	buttonInteraction := &discordgo.InteractionCreate{
		Interaction: &discordgo.Interaction{
			Type:    discordgo.InteractionMessageComponent,
			ID:      buttonInteractionID,
			User:    feedbackUser, // Use the different user here
			GuildID: "test_guild_id",
			Data: discordgo.MessageComponentInteractionData{
				CustomID:      goodCustomID,
				ComponentType: discordgo.ButtonComponent,
			},
		},
	}

	interactionHandler := bot.getInteractionHandlerFunc(ctx, buttonInteraction)
	stubHandler, ok := interactionHandler.(stubInteractionHandler)
	if !ok {
		t.Fatal("expected stub interaction handler")
	}
	bot.handleInteraction(
		context.Background(),
		interactionHandler,
	)

	bctx, bcancel := context.WithTimeout(ctx, 10*time.Second)
	t.Cleanup(bcancel)

	var buttonResponse *discordgo.InteractionResponse

	for bctx.Err() == nil {
		rv := <-stubHandler.callRespond
		idata, err := json.Marshal(rv)
		require.NoError(t, err)
		t.Logf("interaction data: %s", string(idata))
		if rv.Type == discordgo.InteractionResponseDeferredMessageUpdate {
			buttonResponse = rv
			bcancel()
		} else {
			t.Logf("interaction type: %#v", rv.Type)
		}
	}

	if buttonResponse == nil {
		t.Fatalf("didn't get button response")
	}

	// Unlike the BOT_DM or /private commands, /chat commands in a
	// guild do not have their buttons disabled until the token is
	// about to expire, and may be submitted from different users
	fctx, fcancel := context.WithTimeout(ctx, 240*time.Second)
	t.Cleanup(fcancel)
	userFeedback := waitForReport(t, fctx, bot.db, chatCommand, UserFeedbackGood)
	assert.NotNil(t, userFeedback)

	assert.Equal(t, string(UserFeedbackGood), userFeedback.Type)
	assert.Equal(
		t,
		feedbackUser.ID,
		*userFeedback.UserID,
	) // Check that the feedback is from the correct user

	err := bot.db.Last(chatCommand).Error
	require.NoError(t, err)

	assert.Equal(t, FeedbackButtonStateEnabled, chatCommand.FeedbackButtonStateGood)
	assert.Equal(t, FeedbackButtonStateHidden, chatCommand.FeedbackButtonStateReset)
	assert.Equal(t, FeedbackButtonStateEnabled, chatCommand.FeedbackButtonStateOutdated)
	assert.Equal(t, FeedbackButtonStateEnabled, chatCommand.FeedbackButtonStateHallucinated)
	assert.Equal(t, FeedbackButtonStateEnabled, chatCommand.FeedbackButtonStateOther)
}

func TestInteraction_ReportOtherGuild(t *testing.T) {
	t.Parallel()
	bot, _ := newDisConcierge(t)
	ctx := context.Background()
	u := newDiscordUser(t)
	interactionID := fmt.Sprintf("i_%s", t.Name())
	i := newDiscordInteraction(t, u, interactionID, t.Name())
	i.Context = discordgo.InteractionContextGuild

	feedbackUser := &discordgo.User{
		ID:         fmt.Sprintf("other_%s", t.Name()),
		Username:   fmt.Sprintf("u_other_%s", t.Name()),
		GlobalName: fmt.Sprintf("g_other_%s", t.Name()),
	}

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
		if !ok {
			t.Fatalf("sdfsdf")
		}
		_, ok = handlersCreated[funcInteraction.ID]
		if ok {
			t.Logf("handler already created")
		}
		handlersCreated[funcInteraction.ID] = stubHandler
		return h
	}

	bot.handleInteraction(
		context.Background(),
		bot.getInteractionHandlerFunc(ctx, i),
	)

	chatCommand := waitForChatCommandFinish(t, ctx, bot.db, interactionID)
	require.NotNil(t, chatCommand)
	assert.Equal(t, ChatCommandStateCompleted, chatCommand.State)
	assert.Equal(t, ChatCommandStepFeedbackOpen, chatCommand.Step)

	buttonInteractionID := fmt.Sprintf("button_%s", t.Name())
	otherCustomID := discordButtonCustomID(t, UserFeedbackOther, chatCommand)
	buttonInteraction := &discordgo.InteractionCreate{
		Interaction: &discordgo.Interaction{
			Type: discordgo.InteractionMessageComponent,
			ID:   buttonInteractionID,
			User: feedbackUser,
			Data: discordgo.MessageComponentInteractionData{
				CustomID:      otherCustomID,
				ComponentType: discordgo.ButtonComponent,
			},
		},
	}

	interactionHandler := bot.getInteractionHandlerFunc(ctx, buttonInteraction)
	stubHandler, ok := interactionHandler.(stubInteractionHandler)
	if !ok {
		t.Fatal("expected stub interaction handler")
	}
	bot.handleInteraction(
		context.Background(),
		interactionHandler,
	)

	bctx, bcancel := context.WithTimeout(ctx, 10*time.Second)
	t.Cleanup(bcancel)

	var buttonResponse *discordgo.InteractionResponse

	for bctx.Err() == nil {
		select {
		case rv := <-stubHandler.callRespond:
			idata, err := json.Marshal(rv)
			require.NoError(t, err)
			t.Logf("interaction data: %s", string(idata))
			if rv.Type == discordgo.InteractionResponseModal {
				buttonResponse = rv
				bcancel()
			}
		}
	}
	require.NotNil(t, buttonResponse)

	buttonData := buttonResponse.Data
	require.NotNil(t, buttonData)
	assert.Equal(t, feedbackModalCustomID, buttonData.CustomID)
	assert.Equal(
		t,
		bot.RuntimeConfig().FeedbackModalTitle,
		buttonData.Title,
	)
	assert.Equal(t, 1, len(buttonData.Components))
	actionsRow, ok := buttonData.Components[0].(discordgo.ActionsRow)
	if !ok {
		t.Fatalf("wrong type")
	}

	assert.Equal(t, 1, len(actionsRow.Components))
	textInput, ok := actionsRow.Components[0].(discordgo.TextInput)
	if !ok {
		t.Fatalf("wrong type")
	}
	assert.Equal(t, otherCustomID, textInput.CustomID)
	assert.Equal(
		t,
		bot.RuntimeConfig().FeedbackModalInputLabel,
		textInput.Label,
	)
	assert.Equal(
		t,
		bot.RuntimeConfig().FeedbackModalPlaceholder,
		textInput.Placeholder,
	)
	assert.True(t, textInput.Required)
	assert.Equal(
		t,
		bot.RuntimeConfig().FeedbackModalMinLength,
		textInput.MinLength,
	)
	assert.Equal(
		t,
		bot.RuntimeConfig().FeedbackModalMaxLength,
		textInput.MaxLength,
	)

	reportContent := t.Name()

	row := &discordgo.ActionsRow{
		Components: []discordgo.MessageComponent{
			&discordgo.TextInput{
				CustomID: otherCustomID,
				Value:    reportContent,
			},
		},
	}

	submitData := discordgo.ModalSubmitInteractionData{
		CustomID: feedbackModalCustomID,
		Components: []discordgo.MessageComponent{
			row,
		},
	}

	modalInteractionID := fmt.Sprintf("modal_%s", t.Name())
	modalInteraction := &discordgo.InteractionCreate{
		Interaction: &discordgo.Interaction{
			ID:     modalInteractionID,
			Type:   discordgo.InteractionModalSubmit,
			Data:   submitData,
			Member: &discordgo.Member{User: feedbackUser},
		},
	}

	modalHandler := bot.getInteractionHandlerFunc(ctx, modalInteraction)
	modalStubHandler, ok := modalHandler.(stubInteractionHandler)
	if !ok {
		t.Fatal("expected stub interaction handler")
	}
	bot.handleInteraction(
		context.Background(),
		modalHandler,
	)

	mctx, mcancel := context.WithTimeout(ctx, 10*time.Second)
	t.Cleanup(mcancel)

	var modalResponse *discordgo.InteractionResponse
	for mctx.Err() == nil {
		select {
		case rv := <-modalStubHandler.callRespond:
			idata, err := json.Marshal(rv)
			require.NoError(t, err)
			t.Logf("interaction data: %s", string(idata))
			if rv.Type == discordgo.InteractionResponseDeferredMessageUpdate {
				modalResponse = rv
				mcancel()
			}
		}
	}

	if modalResponse == nil {
		t.Fatal("nil response")
	}

	// 'other' modal submissions from users other than the one that triggered
	// the command (ex: /chat in a guild) should not disable any buttons
	fctx, fcancel := context.WithTimeout(ctx, 10*time.Second)
	t.Cleanup(fcancel)
	userFeedback := waitForReport(t, fctx, bot.db, chatCommand, UserFeedbackOther)
	assert.NotNil(t, userFeedback)
	assert.Equal(t, reportContent, userFeedback.Detail)
	require.NotNil(t, userFeedback.UserID)
	assert.Equal(t, feedbackUser.ID, *userFeedback.UserID)

	require.NoError(t, bot.db.Last(chatCommand).Error)

	assert.Equal(t, FeedbackButtonStateEnabled, chatCommand.FeedbackButtonStateGood)
	assert.Equal(t, FeedbackButtonStateHidden, chatCommand.FeedbackButtonStateReset)
	assert.Equal(t, FeedbackButtonStateEnabled, chatCommand.FeedbackButtonStateOutdated)
	assert.Equal(t, FeedbackButtonStateEnabled, chatCommand.FeedbackButtonStateHallucinated)
	assert.Equal(t, FeedbackButtonStateEnabled, chatCommand.FeedbackButtonStateOther)
}

func TestUserFeedback_DeleteOldGuild(t *testing.T) {
	t.Parallel()
	bot, _ := newDisConcierge(t)

	discordUser := newDiscordUser(t)
	ids := newCommandData(t)

	question := "where is the beef?"
	interaction := newDiscordInteraction(
		t,
		discordUser,
		ids.InteractionID,
		question,
	)
	interaction.Context = discordgo.InteractionContextGuild

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)

	go bot.handleInteraction(
		context.Background(),
		bot.getInteractionHandlerFunc(ctx, interaction),
	)

	t.Cleanup(cancel)
	chatCommand := waitForChatCommandCreation(
		t,
		ctx,
		bot.db,
		interaction.ID,
	)
	require.NotNil(t, chatCommand)

	chatCommand = waitForChatCommandFinish(
		t,
		ctx,
		bot.db,
		chatCommand.InteractionID,
	)
	require.NotNil(t, chatCommand)

	assert.Equal(t, ChatCommandStateCompleted, chatCommand.State)
	assert.Equal(t, ChatCommandStepFeedbackOpen, chatCommand.Step)

	buttonInteractionID := fmt.Sprintf("button_%s", t.Name())
	goodCustomID := discordButtonCustomID(t, UserFeedbackGood, chatCommand)
	buttonInteraction := &discordgo.InteractionCreate{
		Interaction: &discordgo.Interaction{
			Type:    discordgo.InteractionMessageComponent,
			ID:      buttonInteractionID,
			User:    discordUser,
			Context: discordgo.InteractionContextGuild,
			Data: discordgo.MessageComponentInteractionData{
				CustomID:      goodCustomID,
				ComponentType: discordgo.ButtonComponent,
			},
		},
	}

	interactionHandler := bot.getInteractionHandlerFunc(ctx, buttonInteraction)
	stubHandler, ok := interactionHandler.(stubInteractionHandler)
	if !ok {
		t.Fatal("expected stub interaction handler")
	}
	bot.handleInteraction(ctx, interactionHandler)

	var buttonResponse *discordgo.InteractionResponse

	buttonCtx, buttonCancel := context.WithCancel(ctx)
	t.Cleanup(buttonCancel)
	for buttonCtx.Err() == nil {
		select {
		case rv := <-stubHandler.callRespond:
			idata, err := json.Marshal(rv)
			require.NoError(t, err)
			t.Logf("interaction data: %s", string(idata))
			if rv.Type == discordgo.InteractionResponseDeferredMessageUpdate {
				buttonResponse = rv
				buttonCancel()
			}
		}
	}
	require.NotNil(t, buttonResponse)

	goodFeedback := waitForReport(t, ctx, bot.db, chatCommand, UserFeedbackGood)
	require.NotNil(t, goodFeedback)

	outdatedInteractionID := fmt.Sprintf("button_outdated_%s", t.Name())
	outdatedCustomID := discordButtonCustomID(t, UserFeedbackOutdated, chatCommand)
	outdatedInteraction := &discordgo.InteractionCreate{
		Interaction: &discordgo.Interaction{
			Type:    discordgo.InteractionMessageComponent,
			ID:      outdatedInteractionID,
			User:    discordUser,
			Context: discordgo.InteractionContextGuild,
			Data: discordgo.MessageComponentInteractionData{
				CustomID:      outdatedCustomID,
				ComponentType: discordgo.ButtonComponent,
			},
		},
	}

	interactionHandler = bot.getInteractionHandlerFunc(ctx, outdatedInteraction)
	stubHandler, ok = interactionHandler.(stubInteractionHandler)
	if !ok {
		t.Fatal("expected stub interaction handler")
	}
	bot.handleInteraction(ctx, interactionHandler)

	var outdatedResponse *discordgo.InteractionResponse

	buttonCtx, buttonCancel = context.WithCancel(ctx)
	t.Cleanup(buttonCancel)
	for buttonCtx.Err() == nil {
		select {
		case rv := <-stubHandler.callRespond:
			idata, err := json.Marshal(rv)
			require.NoError(t, err)
			t.Logf("interaction data: %s", string(idata))
			if rv.Type == discordgo.InteractionResponseDeferredMessageUpdate {
				outdatedResponse = rv
				buttonCancel()
			}
		}
	}
	require.NotNil(t, outdatedResponse)

	outdatedFeedback := waitForReport(t, ctx, bot.db, chatCommand, UserFeedbackOutdated)
	require.NotNil(t, outdatedFeedback)

	rv := bot.db.First(goodFeedback)
	require.Equal(t, 1, int(rv.RowsAffected))
	require.NoError(t, rv.Error)
}

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

func TestChatCommand_setButtonStates(t *testing.T) {
	tests := []struct {
		name       string
		reportType FeedbackButtonType
		initial    ChatCommand
		expected   ChatCommand
		wantErr    bool
	}{
		{
			name:       "UserFeedbackReset",
			reportType: UserFeedbackReset,
			initial: ChatCommand{
				FeedbackButtonStateGood:         FeedbackButtonStateDisabled,
				FeedbackButtonStateReset:        FeedbackButtonStateEnabled,
				FeedbackButtonStateOutdated:     FeedbackButtonStateHidden,
				FeedbackButtonStateHallucinated: FeedbackButtonStateHidden,
				FeedbackButtonStateOther:        FeedbackButtonStateHidden,

				CustomID: "foo",
			},
			expected: ChatCommand{
				FeedbackButtonStateGood:         FeedbackButtonStateEnabled,
				FeedbackButtonStateReset:        FeedbackButtonStateHidden,
				FeedbackButtonStateOutdated:     FeedbackButtonStateEnabled,
				FeedbackButtonStateHallucinated: FeedbackButtonStateEnabled,
				FeedbackButtonStateOther:        FeedbackButtonStateEnabled,
				CustomID:                        "foo",
			},
		},
		{
			name:       "UserFeedbackGood",
			reportType: UserFeedbackGood,
			initial:    ChatCommand{},
			expected: ChatCommand{
				FeedbackButtonStateGood:         FeedbackButtonStateDisabled,
				FeedbackButtonStateReset:        FeedbackButtonStateEnabled,
				FeedbackButtonStateOutdated:     FeedbackButtonStateHidden,
				FeedbackButtonStateHallucinated: FeedbackButtonStateHidden,
				FeedbackButtonStateOther:        FeedbackButtonStateHidden,
			},
		},
		{
			name:       "UserFeedbackOutdated",
			reportType: UserFeedbackOutdated,
			initial: ChatCommand{
				FeedbackButtonStateGood:         FeedbackButtonStateEnabled,
				FeedbackButtonStateHallucinated: FeedbackButtonStateEnabled,
				FeedbackButtonStateOther:        FeedbackButtonStateEnabled,
			},
			expected: ChatCommand{
				FeedbackButtonStateGood:         FeedbackButtonStateHidden,
				FeedbackButtonStateReset:        FeedbackButtonStateEnabled,
				FeedbackButtonStateOutdated:     FeedbackButtonStateDisabled,
				FeedbackButtonStateHallucinated: FeedbackButtonStateEnabled,
				FeedbackButtonStateOther:        FeedbackButtonStateEnabled,
			},
		},
		{
			name:       "UserFeedbackHallucinated",
			reportType: UserFeedbackHallucinated,
			initial:    ChatCommand{FeedbackButtonStateGood: FeedbackButtonStateEnabled},
			expected: ChatCommand{
				FeedbackButtonStateGood:         FeedbackButtonStateHidden,
				FeedbackButtonStateReset:        FeedbackButtonStateEnabled,
				FeedbackButtonStateOutdated:     FeedbackButtonStateEnabled,
				FeedbackButtonStateHallucinated: FeedbackButtonStateDisabled,
				FeedbackButtonStateOther:        FeedbackButtonStateEnabled,
			},
		},
		{
			name:       "UserFeedbackOther",
			reportType: UserFeedbackOther,
			initial:    ChatCommand{FeedbackButtonStateGood: FeedbackButtonStateEnabled},
			expected: ChatCommand{
				FeedbackButtonStateGood:         FeedbackButtonStateHidden,
				FeedbackButtonStateReset:        FeedbackButtonStateEnabled,
				FeedbackButtonStateOutdated:     FeedbackButtonStateEnabled,
				FeedbackButtonStateHallucinated: FeedbackButtonStateEnabled,
				FeedbackButtonStateOther:        FeedbackButtonStateDisabled,
			},
		},
		{
			name:       "Unknown report type",
			reportType: FeedbackButtonType("UnknownType"),
			initial:    ChatCommand{},
			expected:   ChatCommand{},
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				err := tt.initial.setButtonStates(tt.reportType)
				if tt.wantErr {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
				}
				assert.Equalf(
					t,
					tt.expected.FeedbackButtonStateGood,
					tt.initial.FeedbackButtonStateGood,
					"%s / %s",
					tt.expected.FeedbackButtonStateGood,
					tt.initial.FeedbackButtonStateGood,
				)
				assert.Equalf(
					t,
					tt.expected.FeedbackButtonStateReset,
					tt.initial.FeedbackButtonStateReset,
					"%s / %s",
					tt.expected.FeedbackButtonStateReset,
					tt.initial.FeedbackButtonStateReset,
				)
				assert.Equalf(
					t,
					tt.expected.FeedbackButtonStateOutdated,
					tt.initial.FeedbackButtonStateOutdated,
					"%s / %s",
					tt.expected.FeedbackButtonStateOutdated,
					tt.initial.FeedbackButtonStateOutdated,
				)
				assert.Equalf(
					t,
					tt.expected.FeedbackButtonStateHallucinated,
					tt.initial.FeedbackButtonStateHallucinated,
					"%s / %s",
					tt.expected.FeedbackButtonStateHallucinated,
					tt.initial.FeedbackButtonStateHallucinated,
				)
				assert.Equalf(
					t,
					tt.expected.FeedbackButtonStateOther,
					tt.initial.FeedbackButtonStateOther,
					"%s / %s",
					tt.expected.FeedbackButtonStateOther,
					tt.initial.FeedbackButtonStateOther,
				)
			},
		)
	}
}
