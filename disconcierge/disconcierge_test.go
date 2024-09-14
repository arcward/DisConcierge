package disconcierge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/bwmarrin/discordgo"
	"github.com/sashabaranov/go-openai"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRun(t *testing.T) {
	t.Parallel()
	bot, _ := newDisConcierge(t)
	ctx := context.Background()
	discordUser := newDiscordUser(t)
	ids := newCommandData(t)

	question := "where is the beef?"
	mockOpenAI := bot.openai.client.(*mockOpenAIClient)
	expectResponse := mockOpenAI.PromptResponses[question]
	require.NotEmpty(t, expectResponse)
	interaction := newDiscordInteraction(
		t,
		discordUser,
		ids.InteractionID,
		question,
	)

	go bot.handleInteraction(
		context.Background(),
		bot.getInteractionHandlerFunc(context.Background(), interaction),
	)

	doneCtx, doneCancel := context.WithTimeout(
		context.Background(),
		300*time.Second,
	)
	t.Cleanup(doneCancel)
	discordMessage := waitForChatCommandCreation(
		t,
		doneCtx,
		bot.db,
		interaction.ID,
	)

	pollCtx, pollCancel := context.WithTimeout(
		ctx,
		150*time.Second,
	)
	t.Cleanup(pollCancel)

	discordMessage = waitForChatCommandFinish(
		t,
		pollCtx,
		bot.db,
		discordMessage.InteractionID,
	)
	require.NotNil(t, discordMessage)

	require.Equal(t, ChatCommandStateCompleted, discordMessage.State)

	assert.Equal(t, discordUser.ID, discordMessage.UserID)

	assert.Equal(t, interaction.ID, discordMessage.InteractionID)
	assert.Equal(t, interaction.Token, discordMessage.Token)
	assert.Equal(t, interaction.AppID, discordMessage.AppID)

	require.NotNil(t, discordMessage.Response)

	assert.Equal(t, question, discordMessage.Prompt)

	assert.NotNil(t, discordMessage.Response)

	response := *discordMessage.Response
	before, after, found := strings.Cut(response, "\n\n-# Commands used:")
	expectResponse = shortenString(
		removeCitations(expectResponse),
		discordMaxMessageLength,
	)
	if assert.True(t, found) {
		assert.Equal(t, expectResponse, before)
	}
	t.Logf("after: %s", after)

	require.Emptyf(
		t,
		discordMessage.Error,
		"error response: %s (step: %s)",
		discordMessage.Error,
		discordMessage.Step.String(),
	)

	var createRunRequests []*OpenAICreateRun
	db := bot.db
	err := db.Find(&createRunRequests).Error
	require.NoError(t, err)

	assert.Len(t, createRunRequests, 1)

	createRunReq := createRunRequests[0]

	var chatCommandRec ChatCommand
	err = db.Last(&chatCommandRec).Error
	if err != nil {
		t.Fatalf("error getting last chat command: %v", err)
	}
	require.NoError(t, bot.hydrateChatCommand(ctx, &chatCommandRec))

	assert.Equal(t, chatCommandRec.ID, *createRunReq.ChatCommandID)
	var runResponse openai.Run
	err = json.Unmarshal([]byte(createRunReq.ResponseBody), &runResponse)
	require.NoError(t, err)
	assert.NotEmpty(t, chatCommandRec.ThreadID)
	assert.Equal(t, chatCommandRec.ThreadID, runResponse.ThreadID)
	assert.NotEmpty(t, chatCommandRec.RunID)
	threadID := chatCommandRec.ThreadID
	runID := chatCommandRec.RunID
	var runRequestData openai.Run
	err = json.Unmarshal([]byte(createRunReq.ResponseBody), &runRequestData)
	require.NoError(t, err)
	assert.Equal(t, runID, runRequestData.ID)

	assert.Equal(t, threadID, runResponse.ThreadID)

	assert.Equal(t, "", createRunReq.Error)

	var retrieveRunReq OpenAIRetrieveRun
	var retrieveRunResponse openai.Run

	err = db.Last(&retrieveRunReq).Error
	if err != nil {
		t.Fatalf("error getting last chat command: %v", err)
	}
	err = json.Unmarshal(
		[]byte(retrieveRunReq.ResponseBody),
		&retrieveRunResponse,
	)
	require.NoError(t, err)

	assert.Equal(t, chatCommandRec.ID, *retrieveRunReq.ChatCommandID)
	assert.Equal(t, chatCommandRec.ThreadID, retrieveRunResponse.ThreadID)

	assert.Equal(t, chatCommandRec.RunID, retrieveRunResponse.ID)
	assert.Equal(t, threadID, retrieveRunResponse.ThreadID)
	assert.Equal(t, "", retrieveRunReq.Error)

	var listMsgReq OpenAIListMessages
	err = db.Last(&listMsgReq).Error
	if err != nil {
		t.Fatalf("error getting last chat command: %v", err)
	}

	runSteps := []OpenAIListRunSteps{}
	err = db.Find(&runSteps, "chat_command_id", chatCommandRec.ID).Error
	require.NoError(t, err)
	if !assert.Equal(t, 1, len(runSteps)) {
		t.Fatalf("expected 1 run step, got: %#v", runSteps)
	}

	customID := chatCommandRec.CustomID
	fullCustomID := fmt.Sprintf(
		customIDFormat,
		UserFeedbackOther,
		customID,
	)

	require.NoError(t, err)
	assert.NotEqual(t, "", customID)
	textValue := "bc reasons"
	row := &discordgo.ActionsRow{
		Components: []discordgo.MessageComponent{
			&discordgo.TextInput{
				CustomID: fullCustomID,
				Value:    textValue,
			},
		},
	}
	submitData := discordgo.ModalSubmitInteractionData{
		CustomID: feedbackModalCustomID,
		Components: []discordgo.MessageComponent{
			row,
		},
	}
	modalInteraction := &discordgo.InteractionCreate{
		Interaction: &discordgo.Interaction{
			Type:   discordgo.InteractionModalSubmit,
			Data:   submitData,
			Member: &discordgo.Member{User: discordUser},
		},
	}

	reportData, err := getFeedbackTextInput(
		db,
		modalInteraction.ModalSubmitData(),
	)
	require.NoError(t, err)
	require.NotNil(t, reportData)

	assert.Equal(t, reportData.CustomID.String(), fullCustomID)

	reportCh := make(chan struct{}, 1)
	go func() {
		bot.handleInteraction(
			context.Background(),
			bot.getInteractionHandlerFunc(
				context.Background(),
				modalInteraction,
			),
		)

		reportCh <- struct{}{}
	}()

	reportCtx, reportCancel := context.WithTimeout(
		ctx,
		240*time.Second,
	)
	t.Cleanup(reportCancel)
	select {
	case <-reportCh:
		//
	case <-reportCtx.Done():
		t.Fatalf("timeout waiting for report")
	}
	feedback := waitForReports(t, reportCtx, db, chatCommandRec.ID)
	reportCancel()
	if feedback == nil {
		t.Fatalf("expected feedback to not be nil")
	}

	require.Len(t, feedback, 1)
	report := feedback[0]
	assert.Equal(t, string(UserFeedbackOther), report.Type)
	assert.Equal(t, feedbackTypeDescription[UserFeedbackOther], report.Description)
	assert.Equal(t, textValue, report.Detail)
	assert.Equal(t, customID, report.CustomID)
	if report.UserID == nil {
		t.Error("expected user id to not be nil")
	} else {
		assert.Equal(t, chatCommandRec.UserID, *report.UserID)
	}
	err = db.Last(&chatCommandRec).Error
	require.NoError(t, err)

	assert.Equal(t, chatCommandRec.ID, *report.ChatCommandID)

	assert.Equal(t, FeedbackButtonStateEnabled, chatCommandRec.FeedbackButtonStateHallucinated)
	assert.Equal(t, FeedbackButtonStateDisabled, chatCommandRec.FeedbackButtonStateOther)
	assert.Equal(t, FeedbackButtonStateEnabled, chatCommandRec.FeedbackButtonStateOutdated)
	assert.Equal(t, FeedbackButtonStateHidden, chatCommandRec.FeedbackButtonStateGood)
	assert.Equal(t, FeedbackButtonStateEnabled, chatCommandRec.FeedbackButtonStateReset)

	assert.NotNil(t, chatCommandRec.HallucinatedButton())
	assert.NotNil(t, chatCommandRec.OtherButton())
	assert.NotNil(t, chatCommandRec.OutdatedButton())
	assert.NotNil(t, chatCommandRec.UndoButton())
	assert.Nil(t, chatCommandRec.GoodButton())

	err = chatCommandRec.removeUnusedFeedbackButtons(ctx, bot.writeDB)
	require.NoError(t, err)

	assert.Nil(t, chatCommandRec.HallucinatedButton())
	assert.NotNil(t, chatCommandRec.OtherButton())
	assert.Nil(t, chatCommandRec.OutdatedButton())
	assert.Nil(t, chatCommandRec.UndoButton())
	assert.Nil(t, chatCommandRec.GoodButton())
	assert.Equal(t, FeedbackButtonStateHidden, chatCommandRec.FeedbackButtonStateHallucinated)
	assert.Equal(t, FeedbackButtonStateDisabled, chatCommandRec.FeedbackButtonStateOther)
	assert.Equal(t, FeedbackButtonStateHidden, chatCommandRec.FeedbackButtonStateOutdated)
	assert.Equal(t, FeedbackButtonStateHidden, chatCommandRec.FeedbackButtonStateGood)
	assert.Equal(t, FeedbackButtonStateHidden, chatCommandRec.FeedbackButtonStateReset)

	affected, err := bot.writeDB.Delete(&report)

	require.NoError(t, err)
	if affected != 1 {
		t.Fatalf("expected 1 affected row, got: %d", affected)
	}
}

func TestInteractionLog(t *testing.T) {
	t.Parallel()
	bot, _ := newDisConcierge(t)
	bot.paused.Store(true)

	discordUser := &discordgo.User{
		ID:       "999",
		Username: "foo",
	}
	question := "where is the beef?"

	interaction := &discordgo.InteractionCreate{
		Interaction: &discordgo.Interaction{
			Type: discordgo.InteractionApplicationCommand,
			ID:   "123",
			User: discordUser,
			Data: discordgo.ApplicationCommandInteractionData{
				CommandType: discordgo.ChatApplicationCommand,
				Name:        DiscordSlashCommandChat,
				Options: []*discordgo.ApplicationCommandInteractionDataOption{
					{
						Name:  chatCommandQuestionOption,
						Type:  discordgo.ApplicationCommandOptionString,
						Value: question,
					},
				},
			},
		},
	}
	bot.handleInteraction(
		context.Background(),
		bot.getInteractionHandlerFunc(context.Background(), interaction),
	)

	time.Sleep(5 * time.Second)

	var cmdChat ChatCommand
	err := bot.db.Last(&cmdChat).Error
	require.NoError(t, err)

	pollCtx, pollCancel := context.WithTimeout(
		context.Background(),
		240*time.Second,
	)
	t.Cleanup(pollCancel)
	rv := waitOnChatCommandFinalState(
		t,
		pollCtx,
		bot.db,
		500*time.Millisecond,
		cmdChat.ID,
	)
	if rv == nil {
		t.Fatalf("expected final state to not be nil")
	}
	assert.Equal(t, ChatCommandStateIgnored, *rv)

	var ilog InteractionLog
	err = bot.db.Last(&ilog).Error
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	assert.Equal(t, "999", ilog.UserID)
	assert.Equal(t, "foo#", ilog.Username)
}

func TestLoggerCtx(t *testing.T) {
	logger := slog.Default()
	ctx := context.Background()

	foundLogger, ok := ContextLogger(ctx)
	assert.Nil(t, foundLogger)
	assert.False(t, ok)

	logCtx := WithLogger(ctx, logger)
	foundLogger, ok = ContextLogger(logCtx)
	assert.True(t, ok)
	assert.NotNil(t, foundLogger)
	assert.Equal(t, logger, foundLogger)
}

func TestMidQueueIgnore(t *testing.T) {
	t.Parallel()
	// Tests a potential scenario where we have multiple queued
	// commands, where `User.Ignored` was set true between the time the
	// command was queued and the time the command began executing.
	//
	// To ensure no requests enqueue executing until the test commands are
	// queued, the bot is queued and the users are set as priority users.
	//
	// Then, the bot's unpaused - when all commands are done, commands
	// A and B should have completed normally, and command C should
	// indicate it's in an ignored state.
	originalTimeout := UserWorkerSendTimeout
	UserWorkerSendTimeout = 10 * time.Second
	t.Cleanup(
		func() {
			UserWorkerSendTimeout = originalTimeout
		},
	)
	bot, _ := newDisConcierge(t)
	ctx := context.Background()

	bot.paused.Store(true)
	mockClient := newMockOpenAIAssistantHandler(t)
	bot.openai.client = mockClient

	// User A setup
	discordUserA := &discordgo.User{
		ID:         "USER_A",
		Username:   "USER_A",
		GlobalName: "USER_A",
	}
	userA, _, err := bot.GetOrCreateUser(ctx, *discordUserA)
	require.NoError(t, err)

	_, err = bot.writeDB.Update(userA, columnChatCommandPriority, true)
	require.NoError(t, err)

	interactionA := newDiscordInteraction(
		t,
		discordUserA,
		"INTERACTION_A",
		t.Name(),
	)
	interactionACh := make(chan ChatCommand, 1)

	// User B setup
	discordUserB := &discordgo.User{
		ID:         "USER_B",
		Username:   "USER_B",
		GlobalName: "USER_B",
	}
	userB, _, err := bot.GetOrCreateUser(ctx, *discordUserB)
	require.NoError(t, err)

	_, err = bot.writeDB.Update(userB, columnChatCommandPriority, true)
	require.NoError(t, err)

	interactionB := newDiscordInteraction(
		t,
		discordUserB,
		"INTERACTION_B",
		t.Name(),
	)
	interactionBCh := make(chan ChatCommand, 1)

	// User C setup
	discordUserC := &discordgo.User{
		ID:         "USER_C",
		Username:   "USER_C",
		GlobalName: "USER_C",
	}
	userC, _, err := bot.GetOrCreateUser(ctx, *discordUserC)
	require.NoError(t, err)

	_, err = bot.writeDB.Update(userC, columnChatCommandPriority, true)
	require.NoError(t, err)

	interactionC := newDiscordInteraction(
		t,
		discordUserC,
		"INTERACTION_C",
		t.Name(),
	)
	interactionCCh := make(chan ChatCommand, 1)

	// Wait for all commands to be created
	var chatCommandA ChatCommand
	var chatCommandB ChatCommand
	var chatCommandC ChatCommand

	// A
	go bot.handleInteraction(
		context.Background(),
		bot.getInteractionHandlerFunc(context.Background(), interactionA),
	)
	go func() {
		interactionACh <- *waitForChatCommandCreation(
			t,
			ctx,
			bot.db,
			interactionA.ID,
		)
	}()
	select {
	case acmd := <-interactionACh:
		chatCommandA = acmd
	case <-ctx.Done():
		t.Fatal("timed out")
	}

	// B

	go bot.handleInteraction(
		context.Background(),
		bot.getInteractionHandlerFunc(context.Background(), interactionB),
	)
	go func() {
		interactionBCh <- *waitForChatCommandCreation(
			t,
			ctx,
			bot.db,
			interactionB.ID,
		)
	}()
	select {
	case acmd := <-interactionBCh:
		chatCommandB = acmd
	case <-ctx.Done():
		t.Fatal("timed out")
	}

	// C
	// go bot.gatewayHandler(bot.discord.session, interactionC)
	go bot.handleInteraction(
		context.Background(),
		bot.getInteractionHandlerFunc(context.Background(), interactionC),
	)
	go func() {
		interactionCCh <- *waitForChatCommandCreation(
			t,
			ctx,
			bot.db,
			interactionC.ID,
		)
	}()
	select {
	case acmd := <-interactionCCh:
		chatCommandC = acmd
	case <-ctx.Done():
		t.Fatal("timed out")
	}

	// After creation, wait for commands to be queued
	aQueued := make(chan bool, 1)
	bQueued := make(chan bool, 1)
	cQueued := make(chan bool, 1)

	// A
	go func() {
		aQueued <- waitForChatCommandState(
			t,
			ctx,
			bot.db,
			chatCommandA.ID,
			ChatCommandStateQueued,
		)
	}()
	select {
	case <-aQueued:
		//
	case <-ctx.Done():
		t.Fatal("timed out")
	}

	// B
	go func() {
		bQueued <- waitForChatCommandState(
			t,
			ctx,
			bot.db,
			chatCommandB.ID,
			ChatCommandStateQueued,
		)
	}()
	select {
	case <-bQueued:
	case <-ctx.Done():
		t.Fatal("timed out")
	}

	// C
	go func() {
		cQueued <- waitForChatCommandState(
			t,
			ctx,
			bot.db,
			chatCommandC.ID,
			ChatCommandStateQueued,
		)
	}()
	select {
	case <-cQueued:
		//
	case <-ctx.Done():
		t.Fatal("timed out")
	}

	assert.Equal(t, ChatCommandStepEnqueue, chatCommandA.Step)
	assert.Equal(t, ChatCommandStepEnqueue, chatCommandB.Step)
	assert.Equal(t, ChatCommandStepEnqueue, chatCommandC.Step)

	// Now that everything's queued while the bot is paused, we set
	// User.Ignored for user C, then unpause the bot to allow commands
	// to begin to process
	_, err = bot.writeDB.Update(userC, "ignored", true)
	require.NoError(t, err)

	bot.paused.Store(false)

	finishedA := make(chan *ChatCommandState, 1)
	finishedB := make(chan *ChatCommandState, 1)
	finishedC := make(chan *ChatCommandState, 1)

	go func() {
		finishedA <- waitOnChatCommandFinalState(
			t,
			ctx,
			bot.db,
			500*time.Millisecond,
			chatCommandA.ID,
		)
	}()

	go func() {
		finishedB <- waitOnChatCommandFinalState(
			t,
			ctx,
			bot.db,
			500*time.Millisecond,
			chatCommandB.ID,
		)
	}()

	go func() {
		finishedC <- waitOnChatCommandFinalState(
			t,
			ctx,
			bot.db,
			500*time.Millisecond,
			chatCommandC.ID,
		)
	}()

	select {
	case finalState := <-finishedA:
		require.NotNil(t, finalState)
		assert.Equal(t, ChatCommandStateCompleted, *finalState)
	case <-ctx.Done():
		t.Fatal("timed out")
	}

	select {
	case finalState := <-finishedB:
		require.NotNil(t, finalState)
		assert.Equal(t, ChatCommandStateCompleted, *finalState)
	case <-ctx.Done():
		t.Fatal("timed out")
	}

	select {
	case finalState := <-finishedC:
		if finalState == nil {
			t.Fatal("got nil state")
		}
		assert.Equal(t, ChatCommandStateIgnored, *finalState)
	case <-ctx.Done():
		t.Fatal("timed out")
	}
}

func TestCancelContext(t *testing.T) {
	t.Parallel()
	// Validates bot shutdown, startup and how ChatCommand
	// execution is (or isn't) resumed
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	bot, _ := newDisConciergeWithContext(t, ctx)

	assert.True(t, bot.Pause(ctx))

	// Set up the initial user, whose command will be completed after resume
	discordUserA := discordgo.User{
		ID:         t.Name(),
		Username:   t.Name(),
		GlobalName: t.Name(),
	}
	userA, _, err := bot.GetOrCreateUser(ctx, discordUserA)
	require.NoError(t, err)

	_, err = bot.writeDB.Update(userA, columnChatCommandPriority, true)
	require.NoError(t, err)

	interactionA := newDiscordInteraction(
		t,
		&discordUserA,
		"123-A",
		t.Name(),
	)

	cmdCtx, cmdCancel := context.WithTimeout(
		context.Background(),
		320*time.Second,
	)
	t.Cleanup(cmdCancel)

	chatCommandCh := make(chan ChatCommand, 1)

	go bot.handleInteraction(
		context.Background(),
		bot.getInteractionHandlerFunc(context.Background(), interactionA),
	)
	go func() {
		chatCommandCh <- *waitForChatCommandCreation(
			t,
			ctx,
			bot.db,
			interactionA.ID,
		)
	}()

	var chatCommand ChatCommand
	select {
	case cmd := <-chatCommandCh:
		chatCommand = cmd
	case <-cmdCtx.Done():
		t.Fatal("timed out")
	}

	queueCh := make(chan bool, 1)
	go func() {
		queueCh <- waitForChatCommandState(
			t,
			ctx,
			bot.db,
			chatCommand.ID,
			ChatCommandStateQueued,
		)
	}()
	select {
	case rv := <-queueCh:
		if !rv {
			t.Fatal("unexpected state")
		}
	case <-cmdCtx.Done():
		t.Fatal("timed out")
	}

	// Set up user B, whose command will be expired when we resume
	discordUserB := discordgo.User{
		ID:         "USER_B",
		Username:   "USER_B",
		GlobalName: "USER_B",
	}
	userB, _, err := bot.GetOrCreateUser(ctx, discordUserB)
	require.NoError(t, err)
	assert.NotEqual(t, userA.ID, userB.ID)

	_, err = bot.writeDB.Update(userB, columnChatCommandPriority, true)
	require.NoError(t, err)

	interactionB := newDiscordInteraction(
		t,
		&discordUserB,
		"123-B",
		t.Name(),
	)

	chatCommandBCh := make(chan ChatCommand, 1)

	go bot.handleInteraction(
		context.Background(),
		bot.getInteractionHandlerFunc(context.Background(), interactionB),
	)
	go func() {
		chatCommandBCh <- *waitForChatCommandCreation(
			t,
			ctx,
			bot.db,
			interactionB.ID,
		)
	}()

	var chatCommandB ChatCommand
	select {
	case cmd := <-chatCommandBCh:
		chatCommandB = cmd
	case <-cmdCtx.Done():
		t.Fatal("timed out")
	}

	queueBCh := make(chan bool, 1)

	go func() {
		queueBCh <- waitForChatCommandState(
			t,
			ctx,
			bot.db,
			chatCommandB.ID,
			ChatCommandStateQueued,
		)
	}()
	select {
	case rv := <-queueBCh:
		if !rv {
			t.Fatal("unexpected state")
		}
	case <-cmdCtx.Done():
		t.Fatal("timed out")
	}
	// Now that both requests are queued, set the second request's
	// expiration an hour back, so that when we resume, it's set as expired
	tokenExpires := time.UnixMilli(chatCommandB.TokenExpires)
	newExpiration := tokenExpires.Add(-time.Hour)
	t.Logf(
		"setting token expiry from '%s' to '%s'",
		tokenExpires,
		newExpiration,
	)
	_, err = bot.writeDB.Update(
		&chatCommandB,
		"token_expires",
		newExpiration.UnixMilli(),
	)
	require.NoError(t, err)

	// Stop the bot!
	shutdownCtx, shutdownCancel := context.WithTimeout(
		context.Background(),
		320*time.Second,
	)
	t.Cleanup(shutdownCancel)
	cancel()
	shutdownComplete := make(chan struct{}, 1)

	go func() {
		<-bot.eventShutdown
		shutdownComplete <- struct{}{}
	}()

	select {
	case <-shutdownComplete:
		t.Logf("shutdown complete")
	case <-shutdownCtx.Done():
		t.Fatal("shutdown not complete")
	}

	// If we set the bot as unpaused/resumed, the value shouldn't stick.
	// Pausing it previously should have saved the 'paused' state with
	// RuntimeConfig, whose 'paused' column value should overwrite what we
	// store right here, as the bot starts.
	bot.paused.Store(false)

	// Start the bot again
	startupCtx, startupCancel := context.WithTimeout(
		context.Background(),
		320*time.Second,
	)
	t.Cleanup(startupCancel)
	botErr := make(chan error, 1)
	go func() {
		botErr <- bot.Run(startupCtx)
	}()

	select {
	case <-bot.signalReady:
		t.Logf("bot restarted")

	case <-startupCtx.Done():
		t.Fatal("startup timed out")
	case e := <-botErr:
		t.Fatalf("startup error: %s", e.Error())
	}

	// After startup, `RuntimeConfig.Paused` should have set this back to true
	assert.True(t, bot.paused.Load())

	resumeCtx, resumeCancel := context.WithTimeout(
		context.Background(),
		600*time.Second,
	)
	t.Cleanup(resumeCancel)

	// resumes and verifies the bot was paused at the time
	assert.True(t, bot.Resume(resumeCtx))

	// The catchup functions called by Run() should have found
	// the ChatCommand record in state=ChatCommandStateQueued, and
	// re-queued it for normal execution.
	finalState := waitOnChatCommandFinalState(
		t,
		resumeCtx,
		bot.db,
		500*time.Millisecond,
		chatCommand.ID,
	)
	if finalState == nil {
		t.Fatalf("nil final state")
	}
	assert.Equal(t, ChatCommandStateCompleted, *finalState)

	// The other ChatCommand, where we moved back the token expiration,
	// should have been set as expired and not executed.
	expiredCh := make(chan bool, 1)
	go func() {
		expiredCh <- waitForChatCommandState(
			t,
			resumeCtx,
			bot.db,
			chatCommandB.ID,
			ChatCommandStateExpired,
		)
	}()
	select {
	case rv := <-expiredCh:
		if !rv {
			t.Fatal("not expected state")
		}
	case <-resumeCtx.Done():
		t.Fatal("timed out")
	}
}

func TestResumeFromQueuedRunStatus(t *testing.T) {
	bot, _ := newDisConcierge(t)

	discordUser := discordgo.User{
		ID: t.Name(), Username: t.Name(), GlobalName: t.Name(),
	}
	u, _, err := bot.GetOrCreateUser(context.Background(), discordUser)
	require.NoError(t, err)

	_, err = bot.writeDB.Update(u, "ignored", true)
	require.NoError(t, err)

	i := newDiscordInteraction(t, &discordUser, t.Name(), "foo")
	chatCommand, err := NewChatCommand(u, i)
	require.NoError(t, err)
	assert.Equal(t, ChatCommandStateIgnored, chatCommand.State)
	chatCommand.Acknowledged = true
	_, err = bot.writeDB.Create(chatCommand)
	require.NoError(t, err)

	ctx := context.Background()
	handler := bot.getInteractionHandlerFunc(ctx, i)

	stubHandler, ok := handler.(stubInteractionHandler)
	if !ok {
		t.Fatalf("expected handler to be stubInteractionHandler")
	}
	chatCommand.handler = stubHandler

	go chatCommand.enqueue(ctx, bot)

	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	t.Cleanup(cancel)

	select {
	case <-ctx.Done():
		t.Fatalf("timeout waiting for chat command to finish")
	case <-stubHandler.callDelete:
		t.Logf("got delete!")
	}
	assert.Equal(t, ChatCommandStateIgnored, chatCommand.State)
	assert.True(t, chatCommand.Acknowledged)
}

func TestBotPendingSetup(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	bot, _ := newDisConciergePendingSetup(t, ctx)

	if !bot.pendingSetup.Load() {
		t.Fatalf("expected pending setup")
	}

	handlers := NewAPIHandlers(bot)

	username := fmt.Sprintf("user_%s", t.Name())
	password := fmt.Sprintf("password_%s", t.Name())

	runtimeConfig := bot.RuntimeConfig()
	assert.Empty(t, runtimeConfig.AdminPassword)
	assert.Empty(t, runtimeConfig.AdminUsername)

	rv := handleTestRequest(
		t,
		handlers.setupStatus,
		http.MethodGet,
		http.NoBody,
	)
	assert.Equal(t, http.StatusOK, rv.StatusCode)

	var setupStatus setupResponse
	require.NoError(t, json.NewDecoder(rv.Body).Decode(&setupStatus))

	assert.True(t, setupStatus.Required)

	payload := adminSetupPayload{
		Username:        username,
		Password:        password,
		ConfirmPassword: fmt.Sprintf("%s-asdf", password),
	}
	data, err := json.Marshal(payload)
	require.NoError(t, err)
	rv = handleTestRequest(
		t,
		handlers.adminSetup,
		http.MethodPost,
		bytes.NewReader(data),
	)
	assert.Equal(t, http.StatusBadRequest, rv.StatusCode)

	payload.ConfirmPassword = payload.Password

	data, err = json.Marshal(payload)
	require.NoError(t, err)
	rv = handleTestRequest(
		t,
		handlers.adminSetup,
		http.MethodPost,
		bytes.NewReader(data),
	)
	assert.Equal(t, http.StatusCreated, rv.StatusCode)

	tctx, tcancel := context.WithTimeout(ctx, 15*time.Second)

	go func() {
		defer tcancel()
		for tctx.Err() == nil {
			if !bot.pendingSetup.Load() {
				return
			}
			time.Sleep(250 * time.Millisecond)
		}
	}()

	select {
	case <-tctx.Done():
		if bot.pendingSetup.Load() {
			t.Fatalf("still pending setup")
		}
	}

	botState := bot.RuntimeConfig()
	assert.Equal(t, payload.Username, botState.AdminUsername)
	assert.NotEqual(t, botState.AdminPassword, password)
	assert.NotEmpty(t, botState.AdminPassword)

	login := userLogin{
		Username: payload.Username,
		Password: password,
	}

	data, err = json.Marshal(login)
	require.NoError(t, err)

	rv = handleTestRequest(
		t,
		handlers.loginHandler,
		http.MethodPost,
		bytes.NewReader(data),
	)
	assert.Equal(t, http.StatusOK, rv.StatusCode)
}

func TestHandleRecover(t *testing.T) {
	t.Parallel()
	bot, _ := newDisConcierge(t)

	_, err := bot.writeDB.Update(bot.runtimeConfig, "recover_panic", true)
	require.NoError(t, err)

	handler := &mockOpenAIClientServer{
		t:                t,
		threads:          make(map[string]openai.Thread),
		messages:         make(map[string]openai.Message),
		runs:             make(map[string]*openai.Run),
		runSteps:         make(map[string]openai.RunStepList),
		retrieveRunCount: map[string]int{},
	}
	handler.beforeReturnRunFunc = func(
		m *mockOpenAIClientServer,
		run *openai.Run,
	) {
		panic(fmt.Sprintf("panicked! %#v", run))
	}
	bot.openai.client = handler

	discordUser := newDiscordUser(t)
	ids := newCommandData(t)

	question := "where is the beef?"
	interaction := newDiscordInteraction(
		t,
		discordUser,
		ids.InteractionID,
		question,
	)
	bctx, bcancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(bcancel)
	go bot.handleInteraction(
		bctx,
		bot.getInteractionHandlerFunc(bctx, interaction),
	)

	chatCommand := waitForChatCommandFinish(t, bctx, bot.db, interaction.ID)
	t.Logf("chatCommand: %#v", chatCommand)

}

func setupTestDB(t testing.TB) *gorm.DB {
	t.Helper()
	tmpdir := t.TempDir()
	dbPath := filepath.Join(tmpdir, "test.sqlite3")
	db, err := CreateDB(
		context.Background(),
		"sqlite",
		dbPath,
	)
	if err != nil {
		t.Fatalf("error creating test database: %v", err)
	}
	return db
}

func newDisConcierge(t testing.TB) (*DisConcierge, *http.Client) {
	t.Helper()
	return newDisConciergeWithContext(t, context.Background())
}

func newDisConciergeWithContext(
	t testing.TB,
	ctx context.Context,
) (*DisConcierge, *http.Client) {
	t.Helper()
	cfg := DefaultTestConfig(t)
	dbctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	t.Cleanup(cancel)
	ids := newCommandData(t)

	cfg.OpenAI.AssistantID = ids.AssistantID

	mockClient := newMockOpenAIClient(t, &ids)

	db, err := CreateDB(dbctx, cfg.DatabaseType, cfg.Database)
	assert.NoError(t, err)
	t.Cleanup(
		func() {
			sqlDB, _ := db.DB()
			if sqlDB != nil {
				_ = sqlDB.Close()
			}
		},
	)

	runtimeCfg := DefaultTestRuntimeConfig(t)
	require.NoError(t, db.Create(runtimeCfg).Error)

	bot, err := New(cfg)
	require.NoError(t, err)

	bot.runtimeConfig = runtimeCfg
	bot.openai.client = mockClient
	bot.discord.session = newMockDiscordSession()
	setLoggers(t, bot)

	adminServer := httptest.NewTLSServer(bot.api.engine)

	t.Cleanup(adminServer.Close)
	bot.api.listener = adminServer.Listener
	bot.config.HTTPClient = adminServer.Client()
	bot.api.httpServer = adminServer.Config
	bot.api.listener = adminServer.Listener

	t.Logf(
		"test server URL: %s",
		adminServer.URL,
	)
	logger := slog.Default()
	bot.getInteractionHandlerFunc = func(
		ctx context.Context,
		i *discordgo.InteractionCreate,
	) InteractionHandler {
		stubHandler := stubInteractionHandler{
			callRespond: make(
				chan *discordgo.InteractionResponse,
				100,
			),
			config:                 bot.RuntimeConfig().CommandOptions,
			callGetResponse:        make(chan struct{}, 100),
			callEdit:               make(chan *stubEdits, 100),
			callMessageReply:       make(chan *stubMessageReply, 100),
			callDelete:             make(chan struct{}, 100),
			callGetInteraction:     make(chan struct{}, 100),
			callChannelMessageSend: make(chan *stubChannelMessageSend, 100),
			GatewayHandler: GatewayHandler{

				session:     bot.discord.session,
				interaction: i,
				logger:      logger.With("test_name", t.Name()),
			},
		}
		return stubHandler
	}

	botErr := make(chan error, 1)
	go func() {
		botErr <- bot.Run(ctx)
	}()

	select {
	case <-bot.signalReady:
		t.Cleanup(
			func() {
				cleanupCtx, cleanupCancel := context.WithTimeout(
					context.Background(),
					15*time.Second,
				)
				defer cleanupCancel()
				select {
				case <-cleanupCtx.Done():
					t.Logf("cleanup timed out")
				case bot.signalStop <- struct{}{}:
					t.Logf("sent stop signal")
				}
			},
		)
	case e := <-botErr:
		t.Fatalf("error starting bot: %v", e)
	}
	bot.cfgMu.Lock()
	defer bot.cfgMu.Unlock()
	return bot, adminServer.Client()
}

func newDisConciergePendingSetup(
	t testing.TB,
	ctx context.Context,
) (*DisConcierge, *http.Client) {
	t.Helper()
	cfg := DefaultTestConfig(t)

	ids := newCommandData(t)
	mockClient := newMockOpenAIClient(t, &ids)

	db, err := CreateDB(ctx, cfg.DatabaseType, cfg.Database)
	assert.NoError(t, err)
	t.Cleanup(
		func() {
			sqlDB, _ := db.DB()
			if sqlDB != nil {
				_ = sqlDB.Close()
			}
		},
	)

	bot, err := New(cfg)
	require.NoError(t, err)
	bot.openai.client = mockClient
	bot.discord.session = newMockDiscordSession()
	setLoggers(t, bot)

	adminServer := httptest.NewTLSServer(bot.api.engine)

	t.Cleanup(adminServer.Close)
	bot.api.listener = adminServer.Listener
	bot.config.HTTPClient = adminServer.Client()
	bot.api.httpServer = adminServer.Config
	bot.api.listener = adminServer.Listener

	t.Logf(
		"test server URL: %s",
		adminServer.URL,
	)
	logger := slog.Default()
	runtimeConfig := DefaultTestRuntimeConfig(t)
	runtimeConfig.AdminPassword = ""
	runtimeConfig.AdminUsername = ""
	require.NoError(t, db.Create(runtimeConfig).Error)

	bot.runtimeConfig = runtimeConfig
	bot.getInteractionHandlerFunc = func(
		ctx context.Context,
		i *discordgo.InteractionCreate,
	) InteractionHandler {
		stubHandler := stubInteractionHandler{
			callRespond: make(
				chan *discordgo.InteractionResponse,
				100,
			),
			callGetResponse:        make(chan struct{}, 100),
			callEdit:               make(chan *stubEdits, 100),
			callMessageReply:       make(chan *stubMessageReply, 100),
			callDelete:             make(chan struct{}, 100),
			callGetInteraction:     make(chan struct{}, 100),
			callChannelMessageSend: make(chan *stubChannelMessageSend, 100),
			GatewayHandler: GatewayHandler{
				session:     bot.discord.session,
				interaction: i,
				logger:      logger.With("test_name", t.Name()),
			},
			config: bot.RuntimeConfig().CommandOptions,
		}
		return stubHandler
	}

	botErr := make(chan error, 1)
	go func() {
		botErr <- bot.Run(ctx)
	}()

	pendingSetupCh := make(chan struct{}, 1)
	tctx, tcancel := context.WithTimeout(context.Background(), 300*time.Second)
	t.Cleanup(tcancel)
	go func() {
		for tctx.Err() == nil {
			if bot.pendingSetup.Load() {
				pendingSetupCh <- struct{}{}
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()

	select {
	case <-pendingSetupCh:
		t.Cleanup(
			func() {
				bot.signalStop <- struct{}{}
			},
		)
	case <-tctx.Done():
		t.Fatalf("timeout waiting for pending setup")
	case e := <-botErr:
		t.Fatalf("error starting bot: %v", e)
	}

	return bot, adminServer.Client()
}

func newDisConciergeWebhookWithContext(
	t testing.TB,
	ctx context.Context,
) (*DisConcierge, *MockDiscord) {
	t.Helper()
	cfg := DefaultTestConfig(t)
	cfg.Discord.WebhookServer.Enabled = true
	pubkey, privkey := generateDiscordKey(t)

	cfg.Discord.WebhookServer.PublicKey = pubkey

	ctx, cancel := context.WithTimeout(ctx, 1*time.Minute)
	t.Cleanup(cancel)
	mockClient := newMockOpenAIClient(t, nil)

	db, err := CreateDB(ctx, cfg.DatabaseType, cfg.Database)
	assert.NoError(t, err)
	t.Cleanup(
		func() {
			sqlDB, _ := db.DB()
			if sqlDB != nil {
				_ = sqlDB.Close()
			}
		},
	)

	runtimeCfg := DefaultTestRuntimeConfig(t)
	require.NoError(t, db.Create(runtimeCfg).Error)

	bot, err := New(cfg)
	require.NoError(t, err)
	bot.runtimeConfig = runtimeCfg

	bot.discord.session = newMockDiscordSession()

	setLoggers(t, bot)

	bot.openai.client = mockClient

	webhookServer := httptest.NewTLSServer(bot.discordWebhookServer.engine)
	t.Cleanup(webhookServer.Close)
	bot.discordWebhookServer.httpServer = webhookServer.Config
	bot.discordWebhookServer.listener = webhookServer.Listener
	bot.discordWebhookServer.httpServerURL = webhookServer.URL

	adminServer := httptest.NewTLSServer(bot.api.engine)

	t.Cleanup(adminServer.Close)
	bot.api.listener = adminServer.Listener
	bot.config.HTTPClient = adminServer.Client()
	bot.api.httpServer = adminServer.Config
	bot.api.listener = adminServer.Listener

	t.Logf(
		"test server URL: %s ",
		adminServer.URL,
	)
	logger := slog.Default()
	mockDiscord := &MockDiscord{
		PrivateKey: privkey,
		logger:     logger,
		httpClient: webhookServer.Client(),
		URL: fmt.Sprintf(
			"%s%s",
			webhookServer.URL,
			apiDiscordInteractions,
		),
	}

	bot.getInteractionHandlerFunc = func(
		ctx context.Context,
		i *discordgo.InteractionCreate,
	) InteractionHandler {
		stubHandler := stubInteractionHandler{
			callRespond: make(
				chan *discordgo.InteractionResponse,
				100,
			),
			config:                 bot.RuntimeConfig().CommandOptions,
			callMessageReply:       make(chan *stubMessageReply, 100),
			callGetResponse:        make(chan struct{}, 100),
			callEdit:               make(chan *stubEdits, 100),
			callDelete:             make(chan struct{}, 100),
			callGetInteraction:     make(chan struct{}, 100),
			callChannelMessageSend: make(chan *stubChannelMessageSend, 100),
			GatewayHandler: GatewayHandler{
				session: bot.discord.session,
				// session:     &discordgo.Session{},
				interaction: i,
				logger:      logger.With("test_name", t.Name()),
			},
		}
		return stubHandler
	}

	botErr := make(chan error, 1)
	go func() {
		botErr <- bot.Run(ctx)
	}()

	select {
	case <-bot.signalReady:
		t.Cleanup(
			func() {
				bot.signalStop <- struct{}{}
			},
		)
	case e := <-botErr:
		t.Fatalf("error starting bot: %v", e)
	}

	return bot, mockDiscord
}

func newTestDisConcierge(t testing.TB, ids *commandData) (
	*DisConcierge,
	*commandData,
	*http.Client,
) {
	t.Helper()

	if ids == nil {
		cmdData := newCommandData(t)
		ids = &cmdData
	}

	cfg := DefaultTestConfig(t)
	mockClient := newMockOpenAIClient(t, nil)

	db, err := CreateDB(context.Background(), cfg.DatabaseType, cfg.Database)
	assert.NoError(t, err)
	t.Cleanup(
		func() {
			sqlDB, _ := db.DB()
			if sqlDB != nil {
				_ = sqlDB.Close()
			}
		},
	)

	bot, err := New(cfg)
	require.NoError(t, err)
	bot.discord.session = newMockDiscordSession()

	runtimeCfg := DefaultTestRuntimeConfig(t)
	require.NoError(t, db.Create(runtimeCfg).Error)
	bot.runtimeConfig = runtimeCfg

	setLoggers(t, bot)

	bot.openai.client = mockClient

	bot.openai.assistant = &openai.Assistant{}

	adminServer := httptest.NewTLSServer(bot.api.engine)
	t.Cleanup(adminServer.Close)
	bot.api.listener = adminServer.Listener
	bot.config.HTTPClient = adminServer.Client()
	bot.api.httpServer = adminServer.Config
	bot.api.listener = adminServer.Listener

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	bot.getInteractionHandlerFunc = func(
		ctx context.Context,
		i *discordgo.InteractionCreate,
	) InteractionHandler {
		stubHandler := stubInteractionHandler{
			callRespond: make(
				chan *discordgo.InteractionResponse,
				100,
			),
			config:                 bot.RuntimeConfig().CommandOptions,
			callGetResponse:        make(chan struct{}, 100),
			callEdit:               make(chan *stubEdits, 100),
			callMessageReply:       make(chan *stubMessageReply, 100),
			callDelete:             make(chan struct{}, 100),
			callGetInteraction:     make(chan struct{}, 100),
			callChannelMessageSend: make(chan *stubChannelMessageSend, 100),
			GatewayHandler: GatewayHandler{
				session:     bot.discord.session,
				interaction: i,
				logger:      slog.Default().With("test_name", t.Name()),
			},
		}
		return stubHandler
	}

	botErr := make(chan error, 1)
	go func() {
		botErr <- bot.Run(ctx)
	}()

	select {
	case <-bot.signalReady:
		t.Cleanup(
			func() {
				bot.signalStop <- struct{}{}
			},
		)
	case e := <-botErr:
		t.Fatalf("error starting bot: %v", e)
	}

	return bot, ids, adminServer.Client()
}

func TestHandleDiscordMessage(t *testing.T) {
	t.Parallel()
	bot, _ := newDisConcierge(t)

	ctx := context.Background()

	t.Run(
		"Ignore message mentioning everyone", func(t *testing.T) {
			msg := &discordgo.MessageCreate{
				Message: &discordgo.Message{
					Content:         "Hello @everyone",
					MentionEveryone: true,
					Author: &discordgo.User{
						ID: "mentioneveryone",
					},
				},
			}
			bot.handleDiscordMessage(ctx, msg)
			// Assert that no DiscordMessage was created
			var count int64
			bot.db.Model(&DiscordMessage{}).Count(&count)
			assert.Equal(t, int64(0), count)
		},
	)

	t.Run(
		"Ignore message without mentions", func(t *testing.T) {
			msg := &discordgo.MessageCreate{
				Message: &discordgo.Message{
					Content: "Hello world",
					Author: &discordgo.User{
						ID: "nomentions",
					},
				},
			}
			bot.handleDiscordMessage(ctx, msg)
			// Assert that no DiscordMessage was created
			var count int64
			bot.db.Model(&DiscordMessage{}).Count(&count)
			assert.Equal(t, int64(0), count)
		},
	)

	t.Run(
		"Ignore message from bot", func(t *testing.T) {
			msg := &discordgo.MessageCreate{
				Message: &discordgo.Message{
					Content: "Hello from bot",
					Author: &discordgo.User{
						ID:  "bot123-ignoreme",
						Bot: true,
					},
					Mentions: []*discordgo.User{
						{ID: bot.config.Discord.ApplicationID},
					},
				},
			}
			bot.handleDiscordMessage(ctx, msg)
			// Assert that no DiscordMessage was created
			var count int64
			bot.db.Model(&DiscordMessage{}).Count(&count)
			assert.Equal(t, int64(0), count)
		},
	)

	t.Run(
		"Handle valid mention", func(t *testing.T) {
			user := &discordgo.User{
				ID:         "validuser123",
				Username:   "testuser",
				GlobalName: "Test User",
			}
			require.NotEmpty(t, bot.config.Discord.ApplicationID)
			msg := &discordgo.MessageCreate{
				Message: &discordgo.Message{
					ID:      "msg123",
					Content: "Hello <@" + bot.config.Discord.ApplicationID + ">",
					Author:  user,
					Mentions: []*discordgo.User{
						{ID: bot.config.Discord.ApplicationID},
					},
				},
			}
			mctx, mcancel := context.WithTimeout(ctx, 300*time.Second)
			t.Cleanup(mcancel)

			connectSession := discordChannelMessageSendHandler{
				DiscordSessionHandler: bot.discord.session,
				messagesSent:          make(chan stubChannelMessageSend, 100),
				repliesSent:           make(chan stubMessageReply, 100),
				errCh:                 make(chan error, 100),
				t:                     t,
			}
			bot.discord.session = connectSession

			doneCh := make(chan struct{}, 1)
			go func() {
				bot.handleDiscordMessage(mctx, msg)
				doneCh <- struct{}{}
			}()

			select {
			case <-mctx.Done():
				t.Fatal("timed out waiting on command")
			case <-doneCh:
				//
			}
			// Assert that a DiscordMessage was created
			var discordMsg DiscordMessage
			err := bot.db.Last(&discordMsg).Error
			require.NoError(t, err)
			assert.Equal(t, msg.ID, discordMsg.MessageID)
			assert.Equal(t, user.ID, discordMsg.UserID)
			assert.Equal(t, user.Username, discordMsg.Username)
			assert.Equal(t, user.GlobalName, discordMsg.GlobalName)

			var createdUser *User
			require.NoError(
				t,
				bot.db.Last(&createdUser, "id = ?", user.ID).Error,
			)
			time.Sleep(250 * time.Millisecond)
		},
	)

	t.Run(
		"Handle message with interaction", func(t *testing.T) {
			ids := newCommandData(t)
			ids.UserID = fmt.Sprintf("withinteraction-%s", t.Name())
			chatCommand := ids.populateChatCommand(nil)
			chatCommand.Response = strPtr(
				fmt.Sprintf(
					"you said: %s!",
					t.Name(),
				),
			)
			require.Equal(
				t,
				discordgo.InteractionApplicationCommand.String(),
				chatCommand.Type,
			)
			discordMessageID := fmt.Sprintf("%10d", randomGenerator.Uint32())
			discordChannelID := fmt.Sprintf("%10d", randomGenerator.Uint32())
			discordGuildID := fmt.Sprintf("%10d", randomGenerator.Uint32())

			appUser := &discordgo.User{
				ID:         ids.DiscordApplicationID,
				Username:   "disconcierge",
				GlobalName: "DisConcierge",
				Bot:        true,
			}

			originalMsg := discordgo.Message{
				ID:        discordMessageID,
				ChannelID: discordChannelID,
				GuildID:   discordGuildID,
				Content:   *chatCommand.Response,
				Author:    appUser,
			}
			_, err := bot.writeDB.Create(chatCommand.User)
			require.NoError(t, err)

			_, err = bot.writeDB.Create(chatCommand)
			require.NoError(t, err)
			require.Empty(t, chatCommand.DiscordMessageID)
			require.NotEmpty(t, chatCommand.InteractionID)
			user := &discordgo.User{
				ID:         chatCommand.User.ID,
				Username:   chatCommand.User.Username,
				GlobalName: chatCommand.User.GlobalName,
			}

			interactionTypes := map[string]discordgo.InteractionType{
				discordgo.InteractionPing.String():               discordgo.InteractionPing,
				discordgo.InteractionApplicationCommand.String(): discordgo.InteractionApplicationCommand,
				discordgo.InteractionMessageComponent.String():   discordgo.InteractionMessageComponent,
				discordgo.InteractionModalSubmit.String():        discordgo.InteractionModalSubmit,
			}
			_, ok := interactionTypes[chatCommand.Type]
			require.Truef(
				t,
				ok,
				"%v not found in: %#v",
				chatCommand.Type,
				interactionTypes,
			)

			msg := &discordgo.MessageCreate{
				Message: &discordgo.Message{
					ID:                fmt.Sprintf("incoming_msg-%s", t.Name()),
					Content:           "Interaction response",
					Author:            user,
					Mentions:          []*discordgo.User{appUser},
					MessageReference:  originalMsg.Reference(),
					ReferencedMessage: &originalMsg,
					Interaction: &discordgo.MessageInteraction{
						ID:   chatCommand.InteractionID,
						Type: interactionTypes[chatCommand.Type],
						Name: DiscordSlashCommandChat,
						User: user,
					},
				},
			}
			bot.handleDiscordMessage(ctx, msg)

			// Assert that a DiscordMessage was created with interaction ID
			var discordMsg DiscordMessage
			err = bot.db.First(&discordMsg, "message_id = ?", msg.ID).Error
			require.NoError(t, err)
			assert.Equal(t, msg.Interaction.ID, discordMsg.InteractionID)

			require.NoError(t, bot.db.Last(chatCommand).Error)
			require.NotEmpty(t, msg.MessageReference.MessageID)
			assert.Equal(
				t,
				msg.MessageReference.MessageID,
				chatCommand.DiscordMessageID,
			)
			time.Sleep(500 * time.Millisecond)
			require.NotNil(t, chatCommand.User)
		},
	)

	t.Run(
		"Handle message for ignored user", func(t *testing.T) {
			ignoredUser := &discordgo.User{
				ID:         "ignored789",
				Username:   "ignoreduser",
				GlobalName: "Ignored User",
			}
			// Create and set the user as ignored
			dbUser, _, err := bot.GetOrCreateUser(ctx, *ignoredUser)
			require.NoError(t, err)
			_, err = bot.writeDB.Update(dbUser, "ignored", true)
			require.NoError(t, err)

			msg := &discordgo.MessageCreate{
				Message: &discordgo.Message{
					ID:      "msg789",
					Content: "Hello <@" + bot.config.Discord.ApplicationID + ">",
					Author:  ignoredUser,
					Mentions: []*discordgo.User{
						{ID: bot.config.Discord.ApplicationID},
					},
				},
			}
			bot.handleDiscordMessage(ctx, msg)

			// Assert that a DiscordMessage was created but no response was sent
			var discordMsg DiscordMessage
			err = bot.db.First(&discordMsg, "message_id = ?", msg.ID).Error
			require.NoError(t, err)
			assert.Equal(t, ignoredUser.ID, discordMsg.UserID)
		},
	)

	t.Run(
		"Handle multiple mentions", func(t *testing.T) {
			multiUser := &discordgo.User{
				ID:         "multi123",
				Username:   "multiuser",
				GlobalName: "Mutli User",
			}
			// Create and set the user as ignored
			_, _, err := bot.GetOrCreateUser(ctx, *multiUser)
			require.NoError(t, err)

			msg := &discordgo.MessageCreate{
				Message: &discordgo.Message{
					ID:      "multimsg789",
					Content: "Hello <@" + bot.config.Discord.ApplicationID + ">",
					Author:  multiUser,
					Mentions: []*discordgo.User{
						{ID: bot.config.Discord.ApplicationID},
						{ID: fmt.Sprintf("otheruser-%s", t.Name())},
					},
				},
			}
			bot.handleDiscordMessage(ctx, msg)

			// Assert that a DiscordMessage was created but no response was sent
			var discordMsg DiscordMessage
			err = bot.db.First(&discordMsg, "message_id = ?", msg.ID).Error
			require.NoError(t, err)
			assert.Equal(t, multiUser.ID, discordMsg.UserID)
		},
	)
}

func TestDisConcierge_New_InvalidDatabaseType(t *testing.T) {
	dbType := "mysql"
	cfg := DefaultTestConfig(t)
	cfg.DatabaseType = dbType
	_, err := New(cfg)
	require.NotNil(t, err)
	require.ErrorContains(t, err, "invalid database type")
}

// isCI returns true if the "CI" environment variable is set (which means
// we're running in a github action)
func isCI(t testing.TB) bool {
	t.Helper()
	return strings.ToLower(os.Getenv("CI")) == "true"
}
