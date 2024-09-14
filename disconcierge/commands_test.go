package disconcierge

import (
	"context"
	"errors"
	"fmt"
	"github.com/bwmarrin/discordgo"
	"github.com/sashabaranov/go-openai"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestChatCommand_State_IsProcessing(t *testing.T) {
	tests := []struct {
		state    ChatCommandState
		expected bool
	}{
		{ChatCommandStateReceived, true},
		{ChatCommandStateQueued, true},
		{ChatCommandStateInProgress, true},
		{ChatCommandStateCompleted, false},
		{ChatCommandStateFailed, false},
		{ChatCommandStateExpired, false},
		{ChatCommandStateIgnored, false},
		{ChatCommandStateRateLimited, false},
		{ChatCommandStateAborted, false},
	}

	for _, tt := range tests {
		t.Run(
			string(tt.state), func(t *testing.T) {
				result := tt.state.IsProcessing()
				assert.Equal(t, tt.expected, result)
			},
		)
	}
}

func TestChatCommand_State_StopProcessing(t *testing.T) {
	tests := []struct {
		state    ChatCommandState
		expected bool
	}{
		{ChatCommandStateReceived, false},
		{ChatCommandStateQueued, false},
		{ChatCommandStateInProgress, false},
		{ChatCommandStateCompleted, false},
		{ChatCommandStateFailed, true},
		{ChatCommandStateExpired, true},
		{ChatCommandStateIgnored, true},
		{ChatCommandStateRateLimited, true},
		{ChatCommandStateAborted, true},
	}

	for _, tt := range tests {
		t.Run(
			string(tt.state), func(t *testing.T) {
				result := tt.state.StopProcessing()
				assert.Equal(t, tt.expected, result)
			},
		)
	}
}

func TestChatCommand_State_IsFinal(t *testing.T) {
	tests := []struct {
		name     string
		state    ChatCommandState
		expected bool
	}{
		{"Completed", ChatCommandStateCompleted, true},
		{"Failed", ChatCommandStateFailed, true},
		{"Expired", ChatCommandStateExpired, true},
		{"Ignored", ChatCommandStateIgnored, true},
		{"RateLimited", ChatCommandStateRateLimited, true},
		{"Aborted", ChatCommandStateAborted, true},
		{"Received", ChatCommandStateReceived, false},
		{"Queued", ChatCommandStateQueued, false},
		{"InProgress", ChatCommandStateInProgress, false},
	}

	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				result := tt.state.IsFinal()
				assert.Equal(t, tt.expected, result, "For state %s", tt.state)
			},
		)
	}
}

func TestChatCommand_Step_IsFinal(t *testing.T) {
	testCases := []struct {
		State    ChatCommandState
		Expected bool
	}{
		{
			State:    ChatCommandStateCompleted,
			Expected: true,
		},
		{
			State:    ChatCommandStateFailed,
			Expected: true,
		},
		{
			State:    ChatCommandStateExpired,
			Expected: true,
		},
		{
			State:    ChatCommandStateIgnored,
			Expected: true,
		},
		{
			State:    ChatCommandStateRateLimited,
			Expected: true,
		},
		{
			State:    ChatCommandStateAborted,
			Expected: true,
		},

		{
			State:    ChatCommandStateReceived,
			Expected: false,
		},
		{
			State:    ChatCommandStateQueued,
			Expected: false,
		},
		{
			State:    ChatCommandStateInProgress,
			Expected: false,
		},
	}
	for _, tc := range testCases {
		t.Run(
			tc.State.String(), func(t *testing.T) {
				assert.Equal(t, tc.Expected, tc.State.IsFinal())
			},
		)
	}
}

func TestChatCommand_NextAvailable(t *testing.T) {

	unixTimestamps := []int64{
		1722474695487,
		1722476103680,

		1722531424153,
		1722533537692,
		1722536846487,
		1722537184458,
		1722539466510,
		1722542678862,
		1722543169430,
		1722548648368,
		1722548664978,
		1722548691691,
	}
	timestrs := []string{}
	for _, u := range unixTimestamps {
		timestrs = append(
			timestrs,
			fmt.Sprintf("%#v", time.UnixMilli(u).Round(time.Second)),
		)
	}
	t.Logf("%s", strings.Join(timestrs, ",\n"))
	var nowTS int64 = 1722550666879
	now := time.UnixMilli(nowTS)
	t.Logf("now time: %#v", now)

	requestTimes := make([]time.Time, 0, len(unixTimestamps))
	for _, ts := range unixTimestamps {
		requestTimes = append(requestTimes, time.UnixMilli(ts))
	}
	availableAt, ok := nextRequestAvailable(
		context.Background(),
		requestTimes,
		10,
		6*time.Hour,
		now,
	)
	if assert.False(t, ok) {
		assert.Greater(t, availableAt, now)
	}

	t.Logf("available at %s from %s", availableAt.String(), now.String())
}

func TestChatCommand_CreateMessage_Failed(t *testing.T) {
	t.Parallel()
	bot, _ := newDisConcierge(t)
	errMsg := "oops"
	u := newDiscordUser(t)
	ids := newCommandData(t)
	interaction := newDiscordInteraction(t, u, ids.InteractionID, t.Name())
	client := newMockOpenAIClient(t, &ids)
	client.CreateMessageResponse = map[string]openai.Message{ids.ThreadID: openai.Message{}}
	client.CreateMessageError = map[string]error{ids.ThreadID: errors.New(errMsg)}
	bot.openai.client = client
	ctx := context.Background()

	go bot.handleInteraction(
		ctx,
		bot.getInteractionHandlerFunc(ctx, interaction),
	)

	chatCommand := waitForChatCommandCreation(t, ctx, bot.db, ids.InteractionID)

	state := waitOnChatCommandFinalState(
		t,
		ctx,
		bot.db,
		500*time.Millisecond,
		chatCommand.ID,
	)
	if state == nil {
		t.Fatalf("nil state")
	}
	assert.Equal(t, ChatCommandStateFailed, *state)

	require.NoError(t, bot.hydrateChatCommand(ctx, chatCommand))

	assert.Equal(t, ChatCommandStateFailed, chatCommand.State)
	assert.Equal(t, errMsg, chatCommand.Error.String())
	assert.Equal(t, ChatCommandStepCreatingMessage, chatCommand.Step)

	var createMsgRec OpenAICreateMessage
	require.NoError(t, bot.db.Last(&createMsgRec).Error)
	require.NotNil(t, createMsgRec.ChatCommandID)
	require.Equal(t, chatCommand.ID, *createMsgRec.ChatCommandID)
	assert.Equal(t, errMsg, createMsgRec.Error)
	assert.NotEmpty(t, createMsgRec.ResponseBody)
	assert.NotNil(t, chatCommand.FinishedAt)
}

func TestChatCommand_ListMessage_Failed(t *testing.T) {
	t.Parallel()
	bot, _ := newDisConcierge(t)
	errMsg := "oops"
	u := newDiscordUser(t)
	ids := newCommandData(t)
	interaction := newDiscordInteraction(t, u, ids.InteractionID, t.Name())
	client := newMockOpenAIClient(t, &ids)
	client.ListMessageResponse = map[string]openai.MessagesList{}
	client.ListMessageError = map[string]error{ids.ThreadID: errors.New(errMsg)}
	bot.openai.client = client
	ctx := context.Background()

	go bot.handleInteraction(
		ctx,
		bot.getInteractionHandlerFunc(ctx, interaction),
	)

	chatCommand := waitForChatCommandCreation(t, ctx, bot.db, ids.InteractionID)

	state := waitOnChatCommandFinalState(
		t,
		ctx,
		bot.db,
		500*time.Millisecond,
		chatCommand.ID,
	)
	if state == nil {
		t.Fatalf("nil state")
	}

	var response string
	if chatCommand.Response != nil {
		response = *chatCommand.Response
	}

	assert.Equalf(t, ChatCommandStateFailed, *state, "response: %s", response)

	require.NoError(t, bot.hydrateChatCommand(ctx, chatCommand))

	assert.Equalf(
		t,
		ChatCommandStateFailed,
		chatCommand.State,
		"response: %v",
		response,
	)
	assert.Equal(t, errMsg, chatCommand.Error.String())
	assert.Equal(t, ChatCommandStepListMessage, chatCommand.Step)

	var listMsgRec OpenAIListMessages
	require.NoError(t, bot.db.Last(&listMsgRec).Error)
	require.NotNil(t, listMsgRec.ChatCommandID)
	require.Equal(t, chatCommand.ID, *listMsgRec.ChatCommandID)
	assert.Equal(t, errMsg, listMsgRec.Error)
	assert.NotEmpty(t, listMsgRec.ResponseBody)
	assert.NotNil(t, chatCommand.FinishedAt)
}

func TestChatCommand_CreateThread_Failed(t *testing.T) {
	t.Parallel()
	bot, _ := newDisConcierge(t)
	err := &openai.RequestError{
		HTTPStatusCode: http.StatusUnauthorized,
		Err: &openai.APIError{
			HTTPStatusCode: http.StatusUnauthorized,
			Message:        "Unauthorized",
		},
	}
	u := newDiscordUser(t)
	ids := newCommandData(t)

	interaction := newDiscordInteraction(t, u, ids.InteractionID, t.Name())

	client := newMockOpenAIClient(t, &ids)
	client.CreateThreadError = err
	bot.openai.client = client
	ctx := context.Background()
	go bot.handleInteraction(
		ctx,
		bot.getInteractionHandlerFunc(ctx, interaction),
	)

	chatCommand := waitForChatCommandCreation(t, ctx, bot.db, ids.InteractionID)

	state := waitOnChatCommandFinalState(
		t,
		ctx,
		bot.db,
		500*time.Millisecond,
		chatCommand.ID,
	)
	if state == nil {
		t.Fatalf("nil state")
	}
	assert.Equal(t, ChatCommandStateFailed, *state)

	require.NoError(t, bot.hydrateChatCommand(ctx, chatCommand))

	assert.Equal(t, ChatCommandStateFailed, chatCommand.State)
	assert.Equal(t, err.Error(), chatCommand.Error.String())
	assert.Equal(t, ChatCommandStepCreatingThread, chatCommand.Step)
	assert.Equal(
		t,
		bot.RuntimeConfig().DiscordErrorMessage,
		*chatCommand.Response,
	)
}

func TestChatCommand_CreateRun_Failed(t *testing.T) {
	t.Parallel()
	bot, _ := newDisConcierge(t)
	err := &openai.RequestError{
		HTTPStatusCode: http.StatusUnauthorized,
		Err: &openai.APIError{
			HTTPStatusCode: http.StatusUnauthorized,
			Message:        "Unauthorized",
		},
	}
	u := newDiscordUser(t)
	ids := newCommandData(t)
	interactionID := fmt.Sprintf("interaction_%s", t.Name())
	interaction := newDiscordInteraction(t, u, interactionID, t.Name())

	client := newMockOpenAIClient(t, &ids)
	client.CreateRunError = map[string]error{ids.ThreadID: err}
	bot.openai.client = client
	ctx := context.Background()

	go bot.handleInteraction(
		ctx,
		bot.getInteractionHandlerFunc(ctx, interaction),
	)

	chatCommand := waitForChatCommandCreation(t, ctx, bot.db, interactionID)

	state := waitOnChatCommandFinalState(
		t,
		ctx,
		bot.db,
		500*time.Millisecond,
		chatCommand.ID,
	)
	if state == nil {
		t.Fatalf("nil state")
	}
	assert.Equal(t, ChatCommandStateFailed, *state)

	require.NoError(t, bot.hydrateChatCommand(ctx, chatCommand))

	assert.Equal(t, ChatCommandStateFailed, chatCommand.State)
	assert.Equal(t, err.Error(), chatCommand.Error.String())
	assert.Equal(t, ChatCommandStepCreatingRun, chatCommand.Step)

	assert.Equal(
		t,
		bot.RuntimeConfig().DiscordErrorMessage,
		*chatCommand.Response,
	)
}

func TestChatCommand_RetrieveRun_Failed(t *testing.T) {
	t.Parallel()
	bot, _ := newDisConcierge(t)
	errMsg := "oops"
	u := newDiscordUser(t)
	ids := newCommandData(t)
	interaction := newDiscordInteraction(t, u, ids.InteractionID, t.Name())
	client := newMockOpenAIClient(t, &ids)
	client.RetrieveRunResponse = map[string]openai.Run{}
	client.RetrieveRunError = map[string]error{
		fmt.Sprintf(
			"%s_%s",
			ids.ThreadID,
			ids.RunID,
		): errors.New(errMsg),
	}
	bot.openai.client = client
	ctx := context.Background()
	go bot.handleInteraction(
		ctx,
		bot.getInteractionHandlerFunc(ctx, interaction),
	)

	chatCommand := waitForChatCommandCreation(t, ctx, bot.db, ids.InteractionID)

	state := waitOnChatCommandFinalState(
		t,
		ctx,
		bot.db,
		500*time.Millisecond,
		chatCommand.ID,
	)
	if state == nil {
		t.Fatalf("nil state")
	}

	var response string
	if chatCommand.Response != nil {
		response = *chatCommand.Response
	}

	assert.Equalf(t, ChatCommandStateFailed, *state, "response: %s", response)

	require.NoError(t, bot.hydrateChatCommand(ctx, chatCommand))

	assert.Equalf(
		t,
		ChatCommandStateFailed,
		chatCommand.State,
		"response: %v",
		response,
	)
	assert.Contains(t, chatCommand.Error.String(), errMsg)
	assert.Equal(t, ChatCommandStepPollingRun, chatCommand.Step)

	var getRuns []OpenAIRetrieveRun
	require.NoError(t, bot.db.Find(&getRuns).Error)
	require.Greater(t, len(getRuns), 0)

	assert.NotNil(t, chatCommand.FinishedAt)

	for _, r := range getRuns {
		require.NotNil(t, r.ChatCommandID)
		require.Equal(t, chatCommand.ID, *r.ChatCommandID)
		assert.Equal(t, errMsg, r.Error)
		assert.NotEmpty(t, r.ResponseBody)
	}
}

func TestChatCommand_RunStatus_Incomplete(t *testing.T) {
	t.Parallel()
	bot, _ := newDisConcierge(t)

	u := newDiscordUser(t)
	ids := newCommandData(t)
	interaction := newDiscordInteraction(t, u, ids.InteractionID, t.Name())
	client := newMockOpenAIClient(t, &ids)
	client.RetrieveRunResponse = map[string]openai.Run{
		fmt.Sprintf("%s_%s", ids.ThreadID, ids.RunID): {
			ThreadID: ids.ThreadID,
			ID:       ids.RunID,
			Status:   openai.RunStatusIncomplete,
		},
	}

	bot.openai.client = client
	ctx := context.Background()

	go bot.handleInteraction(
		ctx,
		bot.getInteractionHandlerFunc(ctx, interaction),
	)

	chatCommand := waitForChatCommandCreation(t, ctx, bot.db, ids.InteractionID)

	state := waitOnChatCommandFinalState(
		t,
		ctx,
		bot.db,
		500*time.Millisecond,
		chatCommand.ID,
	)
	if state == nil {
		t.Fatalf("nil state")
	}
	assert.Equal(t, ChatCommandStateFailed, *state)

	require.NoError(t, bot.hydrateChatCommand(ctx, chatCommand))

	assert.Equal(t, ChatCommandStateFailed, chatCommand.State)
	assert.Equal(t, ChatCommandStepPollingRun, chatCommand.Step)
	assert.Equal(t, openai.RunStatusIncomplete, chatCommand.RunStatus)
	assert.Equal(
		t,
		bot.RuntimeConfig().DiscordErrorMessage,
		*chatCommand.Response,
	)
	assert.NotEqual(t, "", chatCommand.Error)
}

func TestChatCommand_RunStatus_Failed(t *testing.T) {
	t.Parallel()
	bot, _ := newDisConcierge(t)

	u := newDiscordUser(t)
	ids := newCommandData(t)
	interaction := newDiscordInteraction(t, u, ids.InteractionID, t.Name())
	client := newMockOpenAIClient(t, &ids)
	client.RetrieveRunResponse = map[string]openai.Run{
		fmt.Sprintf("%s_%s", ids.ThreadID, ids.RunID): {
			ThreadID: ids.ThreadID,
			ID:       ids.RunID,
			Status:   openai.RunStatusFailed,
		},
	}

	bot.openai.client = client
	ctx := context.Background()
	go bot.handleInteraction(
		ctx,
		bot.getInteractionHandlerFunc(ctx, interaction),
	)

	chatCommand := waitForChatCommandCreation(t, ctx, bot.db, ids.InteractionID)

	state := waitOnChatCommandFinalState(
		t,
		ctx,
		bot.db,
		500*time.Millisecond,
		chatCommand.ID,
	)
	require.NotNil(t, state)
	assert.Equal(t, ChatCommandStateFailed, *state)

	require.NoError(t, bot.hydrateChatCommand(ctx, chatCommand))

	assert.Equal(t, ChatCommandStateFailed, chatCommand.State)
	assert.Equal(t, ChatCommandStepPollingRun, chatCommand.Step)
	assert.Equal(t, openai.RunStatusFailed, chatCommand.RunStatus)
	assert.Equal(
		t,
		bot.RuntimeConfig().DiscordErrorMessage,
		*chatCommand.Response,
	)
	assert.NotEqual(t, "", chatCommand.Error)
	require.NotNil(t, chatCommand.FinishedAt)
}

func TestChatCommand_CreateOpenAIRun_Failed(t *testing.T) {
	t.Parallel()
	bot, _ := newDisConcierge(t)

	u := newDiscordUser(t)
	ids := newCommandData(t)
	interaction := newDiscordInteraction(t, u, ids.InteractionID, t.Name())
	client := newMockOpenAIClient(t, &ids)
	client.CreateRunError = map[string]error{
		ids.ThreadID: errors.New("the server had an error while processing your request. Sorry about that"),
	}
	client.CreateRunResponse = map[string]openai.Run{
		ids.ThreadID: openai.Run{},
	}

	bot.openai.client = client
	ctx := context.Background()
	go bot.handleInteraction(
		ctx,
		bot.getInteractionHandlerFunc(ctx, interaction),
	)

	chatCommand := waitForChatCommandCreation(t, ctx, bot.db, ids.InteractionID)

	state := waitOnChatCommandFinalState(
		t,
		ctx,
		bot.db,
		500*time.Millisecond,
		chatCommand.ID,
	)
	require.NotNil(t, state)
	assert.Equal(t, ChatCommandStateFailed, *state)

	require.NoError(t, bot.hydrateChatCommand(ctx, chatCommand))

	assert.Equal(t, ChatCommandStateFailed, chatCommand.State)
	assert.Equal(t, ChatCommandStepCreatingRun, chatCommand.Step)
	assert.Empty(t, chatCommand.RunStatus)
	assert.Equal(
		t,
		bot.RuntimeConfig().DiscordErrorMessage,
		*chatCommand.Response,
	)
	assert.NotEqual(t, "", chatCommand.Error)
	require.NotNil(t, chatCommand.FinishedAt)

	var createRunReq OpenAICreateRun
	require.NoError(t, bot.db.Last(&createRunReq).Error)
	require.NotNil(t, createRunReq.ChatCommandID)
	require.Equal(t, chatCommand.ID, *createRunReq.ChatCommandID)
	assert.Equal(
		t,
		client.CreateRunError[ids.ThreadID].Error(),
		createRunReq.Error,
	)
	assert.NotEmpty(t, createRunReq.ResponseBody)
}

func TestClearCommand(t *testing.T) {
	ctx := context.Background()
	bot, _ := newDisConcierge(t)
	u := newDiscordUser(t)

	user, _, err := bot.GetOrCreateUser(ctx, *u)
	require.NoError(t, err)

	require.NoError(t, err)
	threadID := fmt.Sprintf("thread_%s", t.Name())
	_, err = bot.writeDB.Update(user, columnChatCommandThreadID, threadID)
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

	go bot.handleInteraction(
		cctx,
		clearTooSoonHandler,
	)

	select {
	case <-cctx.Done():
		t.Fatalf("timeout waiting for response")
	case se := <-clearTooSoonStubHandler.callEdit:
		t.Logf("got interaction edit: %#v", se)
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

type dbiFailedUpdate struct {
	DBI
	t testing.TB
}

func (d *dbiFailedUpdate) Update(
	model any,
	column string,
	value any,
) (rowsAffected int64, err error) {
	d.t.Helper()

	_, ok := model.(*User)
	if ok {
		return 0, errors.New(d.t.Name())
	}
	return d.DBI.Update(model, column, value)
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
	_, err = bot.writeDB.Create(clearCommand)
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

func waitForChatCommandFinish(
	t testing.TB,
	ctx context.Context,
	db *gorm.DB,
	interactionID string,
) *ChatCommand {
	t.Helper()

	chatCommandCh := make(chan *ChatCommand, 1)

	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				chatCommandCh <- nil
				return
			case <-ticker.C:
				var chatCommand ChatCommand
				err := db.Joins("User").Where(
					"interaction_id = ?",
					interactionID,
				).First(&chatCommand).Error

				if err == nil && (chatCommand.State.IsFinal() || chatCommand.FinishedAt != nil) {
					t.Logf(
						"interaction %s: chat command final state seen (%s): %#v",
						interactionID,
						chatCommand.State,
						chatCommand,
					)
					chatCommandCh <- &chatCommand
					return
				} else if chatCommand.InteractionID == interactionID {
					t.Logf(
						"interaction %s: chat_command (state: %s): %#v",
						interactionID,
						chatCommand.State,
						chatCommand,
					)
				}
			}
		}
	}()
	chatCommand := <-chatCommandCh

	if chatCommand == nil {
		t.Logf("expected chat command to not be nil")
	}
	return chatCommand

}

func waitForChatCommandState(
	t testing.TB,
	ctx context.Context,
	db *gorm.DB,
	chatCommandID uint,
	state ...ChatCommandState,
) bool {
	t.Helper()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	var previousState ChatCommandState
	for {
		select {
		case <-ctx.Done():
			t.Fatalf(
				"timeout waiting for chat command states '%v' (last seen: %s): %v",
				state,
				previousState.String(),
				ctx.Err(),
			)
		case <-ticker.C:
			chatCommand := ChatCommand{}
			chatCommand.ID = chatCommandID
			err := db.Select("state").Take(&chatCommand).Error
			require.NoError(t, err)
			previousState = chatCommand.State
			for _, s := range state {
				if chatCommand.State == s {
					return true
				}
			}
		}
	}
	return false
}

func waitForChatCommandCreation(
	t testing.TB,
	ctx context.Context,
	db *gorm.DB,
	interactionID string,
) *ChatCommand {
	t.Helper()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			t.Fatalf("timeout waiting for chat command creation: %v", ctx.Err())
		case <-ticker.C:
			var chatCommand ChatCommand
			err := db.Joins("User").Where(
				"interaction_id = ?",
				interactionID,
			).First(&chatCommand).Error
			if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
				t.Fatalf("error getting chat command: %v", err)
			}
			return &chatCommand
		}
	}
	return nil
}

func createTestChatCommand(
	t testing.TB,
	ctx context.Context,
	d *DisConcierge,
	ids commandData,
) *ChatCommand {
	t.Helper()
	discordUser := &discordgo.User{
		ID:       ids.UserID,
		Username: ids.Username,
	}

	interaction := &discordgo.InteractionCreate{
		Interaction: &discordgo.Interaction{
			Type: discordgo.InteractionApplicationCommand,
			ID:   ids.InteractionID,
			User: discordUser,
			Data: discordgo.ApplicationCommandInteractionData{
				CommandType: discordgo.ChatApplicationCommand,
				Name:        DiscordSlashCommandChat,
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

	handlerCh := make(chan struct{}, 1)

	go func() {
		d.handleInteraction(
			context.Background(),
			d.getInteractionHandlerFunc(context.Background(), interaction),
		)
		<-handlerCh
	}()

	cmdCheckCtx, cmdCheckCancel := context.WithTimeout(ctx, 10*time.Second)
	t.Cleanup(cmdCheckCancel)

	cmdCh := make(chan *ChatCommand, 1)
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for cmdCheckCtx.Err() == nil {
			select {
			case <-cmdCheckCtx.Done():
				cmdCh <- nil
				return
			case <-ticker.C:
				var cmd ChatCommand
				err := d.db.WithContext(cmdCheckCtx).Where(
					"user_id = ?",
					ids.UserID,
				).Last(&cmd).Error
				if err != nil {
					t.Logf("error getting chat command: %v", err)
				} else {
					cmdCh <- &cmd
					return
				}
			}
		}
	}()

	cmdChat := <-cmdCh
	if cmdChat == nil {
		t.Fatalf("expected chat command to not be nil")
	}

	pollCtx, pollCancel := context.WithTimeout(
		context.Background(),
		10*time.Second,
	)
	t.Cleanup(pollCancel)
	rv := waitOnChatCommandFinalState(
		t,
		pollCtx,
		d.db,
		500*time.Millisecond,
		cmdChat.ID,
	)
	if rv == nil {
		t.Fatalf("expected final state to not be nil")
	}
	require.NoError(t, d.hydrateChatCommand(ctx, cmdChat))
	return cmdChat
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

func TestChatCommand_WrongRunStatusColumn(t *testing.T) {
	bot, _ := newDisConcierge(t)
	discordUser := newDiscordUser(t)
	ids := newCommandData(t)

	mockClient := bot.openai.client.(*mockOpenAIClient)
	mockClient.RetrieveRunResponse = map[string]openai.Run{
		fmt.Sprintf("%s_%s", ids.ThreadID, ids.RunID): openai.Run{
			ID:        ids.RunID,
			ThreadID:  ids.ThreadID,
			Status:    openai.RunStatusInProgress,
			CreatedAt: time.Now().UTC().UnixNano(),
			Object:    "thread.run",
		},
	}
	question := "where is the beef?"
	interaction := newDiscordInteraction(
		t,
		discordUser,
		ids.InteractionID,
		question,
	)
	ctx := context.Background()
	go bot.handleInteraction(
		ctx,
		bot.getInteractionHandlerFunc(ctx, interaction),
	)
	chatCommand := waitForChatCommandCreation(t, ctx, bot.db, ids.InteractionID)
	originalColumn := columnChatCommandRunStatus
	badColumn := "runstatus"

	chatCommand = waitForChatCommandRunStatus(
		t,
		ctx,
		bot.db,
		250*time.Millisecond,
		chatCommand,
		openai.RunStatusInProgress,
	)

	columnChatCommandRunStatus = badColumn
	t.Cleanup(
		func() {
			columnChatCommandRunStatus = originalColumn
		},
	)

	chatCommand = waitForChatCommandFinish(t, ctx, bot.db, interaction.ID)
	t.Logf("chatCommand: %#v", chatCommand)
	assert.Equal(t, ChatCommandStateFailed, chatCommand.State)
	assert.Equal(t, openai.RunStatusInProgress, chatCommand.RunStatus)
	assert.NotEmpty(t, chatCommand.Error.String())
	assert.Equal(t, ChatCommandStepPollingRun, chatCommand.Step)
	require.NotNil(t, t, chatCommand.Response)
	assert.Equal(
		t,
		bot.RuntimeConfig().DiscordErrorMessage,
		*chatCommand.Response,
	)
}

func waitForChatCommandRunStatus(
	t testing.TB,
	ctx context.Context,
	db *gorm.DB,
	checkInterval time.Duration,
	chatCommand *ChatCommand,
	runStatus openai.RunStatus,
) *ChatCommand {
	t.Helper()

	for ctx.Err() == nil {
		err := db.Joins("User").Last(chatCommand).Error
		if err != nil {
			t.Logf("err: %v", err)
		} else if chatCommand.RunStatus == runStatus {
			return chatCommand
		}
		time.Sleep(checkInterval)
	}
	t.Fatalf(
		"timeout waiting for chat command run status '%s' (current: %s)",
		runStatus,
		chatCommand.RunStatus,
	)
	return nil
}

// waitOnChatCommandFinalState polls the given chat command and returns the final state
// seen - either because the command enters a 'final' state, or because the
// context was cancelled
func waitOnChatCommandFinalState(
	t testing.TB,
	ctx context.Context,
	db *gorm.DB,
	checkEvery time.Duration,
	chatCommandID uint,
) *ChatCommandState {
	t.Helper()
	ch := pollChatCommand(t, ctx, db, checkEvery, chatCommandID)
	for state := range ch {
		t.Logf(

			"ChatCommand %d state: %s (final: %v)",
			chatCommandID,
			state,
			state.IsFinal(),
		)
		if state.IsFinal() {
			return &state
		}
	}
	return nil
}

func pollChatCommand(
	t testing.TB,
	ctx context.Context,
	db *gorm.DB,
	checkEvery time.Duration,
	chatCommandID uint,
) <-chan ChatCommandState {
	t.Helper()
	ch := make(chan ChatCommandState)
	ticker := time.NewTicker(checkEvery)

	go func() {
		defer close(ch)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				chatCommand := ChatCommand{}
				chatCommand.ID = chatCommandID
				err := db.Select("state").Take(&chatCommand).Error
				if err != nil {
					t.Logf(
						"error polling chat command: %v",
						err,
					)
					continue
				}
				ch <- chatCommand.State
			}
		}
	}()
	return ch
}

func TestChatCommand_Resume_AbandonMaxAttempts(t *testing.T) {
	bot, _ := newDisConcierge(t)
	maxRetries := 3
	_, err := bot.writeDB.Update(
		bot.runtimeConfig,
		columnRuntimeConfigChatCommandMaxAttempts,
		maxRetries,
	)
	require.NoError(t, err)
	require.Equal(t, maxRetries, bot.RuntimeConfig().ChatCommandMaxAttempts)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	ids := newCommandData(t)
	i := ids.newChatCommandInteraction(t.Name())
	u, _, err := bot.GetOrCreateUser(ctx, *i.User)
	require.NoError(t, err)

	chatCommand, err := NewChatCommand(u, i)
	require.NoError(t, err)

	chatCommand.Attempts = maxRetries
	_, err = bot.writeDB.Create(chatCommand)
	require.NoError(t, err)
	require.NoError(t, bot.hydrateChatCommand(ctx, chatCommand))

	handler := chatCommand.handler.(stubInteractionHandler)

	require.NoError(t, bot.resumeChatCommand(ctx, chatCommand))
	assert.Equal(t, ChatCommandStateAborted, chatCommand.State)

	select {
	case edit := <-handler.callEdit:
		require.NotNil(t, edit.WebhookEdit)
		require.NotNil(t, edit.WebhookEdit.Content)
		assert.Equal(
			t,
			bot.RuntimeConfig().DiscordErrorMessage,
			*edit.WebhookEdit.Content,
		)
	case <-ctx.Done():
		t.Fatal("timed out")
	}
}

func TestClearCommand_Run(t *testing.T) {
	ctx := context.Background()
	bot, _ := newDisConciergeWithContext(t, ctx)

	u := newDiscordUser(t)

	user, _, err := bot.GetOrCreateUser(ctx, *u)
	require.NoError(t, err)

	require.NoError(t, err)
	threadID := fmt.Sprintf("thread_%s", t.Name())
	_, err = bot.writeDB.Update(user, columnChatCommandThreadID, threadID)
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

func TestGetOrCreateThreadID(t *testing.T) {
	mockDB := new(mockDBI)
	mockOpenAI := &mockOpenAIThreadClient{}
	d := &DisConcierge{
		writeDB: mockDB,
		openai:  &OpenAI{client: mockOpenAI},
		logger:  slog.Default(),
	}
	ctx := context.Background()

	testCases := []struct {
		name           string
		chatCommand    *ChatCommand
		user           *User
		expectedThread string
		mockSetup      func()
		expectedError  bool
	}{
		{
			name:           "Existing ThreadID in ChatCommand",
			chatCommand:    &ChatCommand{ThreadID: "existing-thread"},
			expectedThread: "existing-thread",
			mockSetup:      func() {},
			expectedError:  false,
		},
		{
			name:           "Existing ThreadID in User",
			chatCommand:    &ChatCommand{Interaction: Interaction{User: &User{ThreadID: "user-thread"}}},
			expectedThread: "user-thread",
			mockSetup: func() {
				mockDB.updateFunc = func(
					model any,
					column string,
					value any,
				) (int64, error) {
					return 1, nil
				}
			},
			expectedError: false,
		},
		{
			name:        "Create New Thread",
			chatCommand: &ChatCommand{Interaction: Interaction{User: &User{}}},
			mockSetup: func() {
				mockOpenAI.createThreadFunc = func(
					ctx context.Context,
				) (string, error) {
					return "new-thread", nil
				}
				mockDB.updateFunc = func(
					model any,
					column string,
					value any,
				) (int64, error) {
					return 1, nil
				}
			},
			expectedThread: "new-thread",
			expectedError:  false,
		},
		{
			name:        "Error Creating Thread",
			chatCommand: &ChatCommand{Interaction: Interaction{User: &User{}}},
			mockSetup: func() {
				mockOpenAI.createThreadFunc = func(
					ctx context.Context,
				) (string, error) {
					return "", errors.New("creation error")
				}
			},
			expectedError: true,
		},
		{
			name:        "Error Inserting Thread",
			chatCommand: &ChatCommand{Interaction: Interaction{User: &User{}}},
			mockSetup: func() {
				mockDB.createFunc = func(
					value any,
					omit ...string,
				) (int64, error) {
					return 0, errors.New("insertion error")
				}
			},
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(
			tc.name, func(t *testing.T) {
				// Reset mocks
				mockDB.updateFunc = nil
				mockOpenAI.createThreadFunc = nil

				// Setup mocks for this test case
				tc.mockSetup()

				threadID, err := getOrCreateThreadID(ctx, d, tc.chatCommand)

				if tc.expectedError {
					if err == nil {
						t.Errorf("Expected an error, but got nil")
					}
				} else {
					if err != nil {
						t.Errorf("Unexpected error: %v", err)
					}
					if threadID != tc.expectedThread {
						t.Errorf(
							"Expected thread ID %s, but got %s",
							tc.expectedThread,
							threadID,
						)
					}
					if tc.chatCommand.ThreadID != tc.expectedThread {
						t.Errorf(
							"Expected ChatCommand ThreadID %s, but got %s",
							tc.expectedThread,
							tc.chatCommand.ThreadID,
						)
					}
					if tc.chatCommand.User != nil && tc.chatCommand.User.ThreadID != tc.expectedThread {
						t.Errorf(
							"Expected User ThreadID %s, but got %s",
							tc.expectedThread,
							tc.chatCommand.User.ThreadID,
						)
					}
				}
			},
		)
	}
}

type mockDBI struct {
	updateFunc func(model any, column string, value any) (
		int64,
		error,
	)
	createFunc func(value any, omit ...string) (int64, error)
	DBI
}

func (m *mockDBI) Create(
	value any,
	omit ...string,
) (rowsAffected int64, err error) {
	if m.createFunc != nil {
		return m.createFunc(value, omit...)
	}
	return 1, nil
}

func (m *mockDBI) Update(
	model any,
	column string,
	value any,
) (int64, error) {
	if m.updateFunc != nil {
		return m.updateFunc(model, column, value)
	}
	return 0, nil
}

type mockOpenAIThreadClient struct {
	createThreadFunc func(ctx context.Context) (
		string,
		error,
	)
	OpenAIClient
}

func (m *mockOpenAIThreadClient) CreateThread(
	ctx context.Context, _ openai.ThreadRequest,
) (openai.Thread, error) {
	if m.createThreadFunc != nil {
		threadID, err := m.createThreadFunc(ctx)
		return openai.Thread{ID: threadID, Object: "thread"}, err
	}
	return openai.Thread{}, nil
}

func TestChatCommand_finalizeExpiredButtons(t *testing.T) {
	cfg := DefaultTestConfig(t)
	db, err := CreateDB(context.Background(), cfg.DatabaseType, cfg.Database)
	require.NoError(t, err)
	t.Cleanup(
		func() {
			sqlDB, _ := db.DB()
			if sqlDB != nil {
				_ = sqlDB.Close()
			}
		},
	)

	ctx := context.Background()
	dc := &DisConcierge{writeDB: NewDatabase(db, nil, true)}

	t.Run(
		"Public interaction", func(t *testing.T) {
			user := &User{
				ID:         fmt.Sprintf("%s-1", t.Name()),
				Username:   fmt.Sprintf("%s-1", t.Name()),
				GlobalName: fmt.Sprintf("%s-1", t.Name()),
			}
			require.NoError(t, db.Create(user).Error)
			cmd := &ChatCommand{
				ModelUintID:                     ModelUintID{ID: 1},
				Private:                         false,
				Step:                            ChatCommandStepFeedbackOpen,
				FeedbackButtonStateGood:         FeedbackButtonStateEnabled,
				FeedbackButtonStateOutdated:     FeedbackButtonStateEnabled,
				FeedbackButtonStateHallucinated: FeedbackButtonStateEnabled,
				FeedbackButtonStateOther:        FeedbackButtonStateEnabled,
				Interaction: Interaction{
					InteractionID: fmt.Sprintf("%s-1", t.Name()),
					UserID:        user.ID,
					User:          user,
				},
			}

			feedback := UserFeedback{
				ChatCommandID: &cmd.ID,
				Type:          string(UserFeedbackGood),
				UserID:        &user.ID,
			}

			require.NoError(t, db.Create(cmd).Error)
			require.NoError(t, db.Create(&feedback).Error)
			cmd.finalizeExpiredButtons(ctx, dc.writeDB)

			var updatedCmd ChatCommand
			require.NoError(t, db.First(&updatedCmd, cmd.ID).Error)

			assert.Equal(t, ChatCommandStepFeedbackClosed, updatedCmd.Step)
			assert.Equal(t, FeedbackButtonStateDisabled, updatedCmd.FeedbackButtonStateGood)

			assert.Equal(t, FeedbackButtonStateHidden, updatedCmd.FeedbackButtonStateOutdated)
			assert.Equal(t, FeedbackButtonStateHidden, updatedCmd.FeedbackButtonStateHallucinated)
			assert.Equal(t, FeedbackButtonStateHidden, updatedCmd.FeedbackButtonStateOther)
			assert.Equal(t, FeedbackButtonStateHidden, updatedCmd.FeedbackButtonStateReset)
		},
	)

	t.Run(
		"Private interaction (Private)", func(t *testing.T) {
			user := &User{
				ID:         fmt.Sprintf("%s-2", t.Name()),
				Username:   fmt.Sprintf("%s-2", t.Name()),
				GlobalName: fmt.Sprintf("%s-2", t.Name()),
			}
			require.NoError(t, db.Create(user).Error)
			cmd := &ChatCommand{
				ModelUintID:                     ModelUintID{ID: 2},
				Private:                         true,
				Step:                            ChatCommandStepFeedbackOpen,
				FeedbackButtonStateGood:         FeedbackButtonStateEnabled,
				FeedbackButtonStateOutdated:     FeedbackButtonStateEnabled,
				FeedbackButtonStateHallucinated: FeedbackButtonStateEnabled,
				FeedbackButtonStateOther:        FeedbackButtonStateEnabled,
				Interaction: Interaction{
					InteractionID: fmt.Sprintf("%s-2", t.Name()),
					UserID:        user.ID,
					User:          user,
				},
			}

			require.NoError(t, db.Create(cmd).Error)

			cmd.finalizeExpiredButtons(ctx, dc.writeDB)

			var updatedCmd ChatCommand
			err = db.First(&updatedCmd, cmd.ID).Error
			require.NoError(t, err)

			assert.Equal(t, ChatCommandStepFeedbackClosed, updatedCmd.Step)

			assert.Equal(t, FeedbackButtonStateHidden, updatedCmd.FeedbackButtonStateGood)
			assert.Equal(t, FeedbackButtonStateHidden, updatedCmd.FeedbackButtonStateOutdated)
			assert.Equal(t, FeedbackButtonStateHidden, updatedCmd.FeedbackButtonStateHallucinated)
			assert.Equal(t, FeedbackButtonStateHidden, updatedCmd.FeedbackButtonStateOther)
			assert.Equal(t, FeedbackButtonStateHidden, updatedCmd.FeedbackButtonStateReset)
		},
	)

	t.Run(
		"Multiple feedback types", func(t *testing.T) {
			user := &User{
				ID:         t.Name(),
				Username:   t.Name(),
				GlobalName: t.Name(),
			}
			cmd := &ChatCommand{
				ModelUintID:                     ModelUintID{ID: 3},
				Private:                         false,
				Step:                            ChatCommandStepFeedbackOpen,
				FeedbackButtonStateGood:         FeedbackButtonStateEnabled,
				FeedbackButtonStateOutdated:     FeedbackButtonStateEnabled,
				FeedbackButtonStateHallucinated: FeedbackButtonStateEnabled,
				FeedbackButtonStateOther:        FeedbackButtonStateEnabled,
				Interaction: Interaction{
					UserID:        user.ID,
					User:          user,
					InteractionID: t.Name(),
				},
			}

			require.NoError(t, db.Create(user).Error)
			require.NoError(t, db.Create(cmd).Error)

			feedbacks := []UserFeedback{
				{
					ChatCommandID: &cmd.ID,
					Type:          string(UserFeedbackGood),
					UserID:        &user.ID,
				},
				{
					ChatCommandID: &cmd.ID,
					Type:          string(UserFeedbackOutdated),
					UserID:        &user.ID,
				},
				{
					ChatCommandID: &cmd.ID,
					Type:          string(UserFeedbackHallucinated),
					UserID:        &user.ID,
				},
			}

			require.NoError(t, db.Create(&feedbacks).Error)

			cmd.finalizeExpiredButtons(ctx, dc.writeDB)

			var updatedCmd ChatCommand
			err = db.First(&updatedCmd, cmd.ID).Error
			require.NoError(t, err)

			assert.Equal(t, ChatCommandStepFeedbackClosed, updatedCmd.Step)

			assert.Equal(t, FeedbackButtonStateDisabled, updatedCmd.FeedbackButtonStateGood)
			assert.Equal(t, FeedbackButtonStateDisabled, updatedCmd.FeedbackButtonStateOutdated)
			assert.Equal(
				t,
				FeedbackButtonStateDisabled,
				updatedCmd.FeedbackButtonStateHallucinated,
			)
			assert.Equal(t, FeedbackButtonStateHidden, updatedCmd.FeedbackButtonStateOther)
			assert.Equal(t, FeedbackButtonStateHidden, updatedCmd.FeedbackButtonStateReset)
		},
	)
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

func TestChatCommand_HandleError(t *testing.T) {
	t.Parallel()

	bot, _, _ := newTestDisConcierge(t, nil)
	ctx := context.Background()

	tests := []struct {
		name               string
		initialAttempts    int
		maxAttempts        int
		tokenExpires       int64
		expectedState      ChatCommandState
		expectedAttempts   int
		expectInteraction  bool
		expectAbortedState bool
	}{
		{
			name:              "Below max attempts",
			initialAttempts:   1,
			maxAttempts:       3,
			tokenExpires:      time.Now().Add(1 * time.Hour).UnixMilli(),
			expectedState:     ChatCommandStateQueued,
			expectedAttempts:  2,
			expectInteraction: false,
		},
		{
			name:               "Reached max attempts",
			initialAttempts:    2,
			maxAttempts:        3,
			tokenExpires:       time.Now().Add(1 * time.Hour).UnixMilli(),
			expectedState:      ChatCommandStateAborted,
			expectedAttempts:   3,
			expectInteraction:  true,
			expectAbortedState: true,
		},
		{
			name:              "Expired token",
			initialAttempts:   1,
			maxAttempts:       3,
			tokenExpires:      time.Now().Add(-1 * time.Hour).UnixMilli(),
			expectedState:     ChatCommandStateQueued,
			expectedAttempts:  2,
			expectInteraction: false,
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				chatCommand := &ChatCommand{
					Attempts:    tt.initialAttempts,
					Interaction: Interaction{TokenExpires: tt.tokenExpires},
					State:       ChatCommandStateQueued,
				}

				mockHandler := newStubInteractionHandler(t)
				cmdConfig := mockHandler.config
				cmdConfig.ChatCommandMaxAttempts = tt.maxAttempts
				mockHandler.config = cmdConfig
				chatCommand.handler = mockHandler

				chatCommand.handleError(ctx, bot)

				assert.Equal(
					t,
					tt.expectedAttempts,
					chatCommand.Attempts,
					"Attempts not updated correctly",
				)

				if tt.expectAbortedState {
					assert.Equal(
						t,
						ChatCommandStateAborted,
						chatCommand.State,
						"State not updated to Aborted",
					)
				} else {
					assert.Equal(
						t,
						tt.expectedState,
						chatCommand.State,
						"State updated unexpectedly",
					)
				}

				if tt.expectInteraction {
					select {
					case edit := <-mockHandler.callEdit:
						assert.NotNil(t, edit, "Expected an interaction edit")
						assert.Equal(
							t,
							mockHandler.Config().DiscordErrorMessage,
							*edit.WebhookEdit.Content,
							"Unexpected error message",
						)
					default:
						t.Error("Expected an interaction edit, but none occurred")
					}
				} else {
					select {
					case <-mockHandler.callEdit:
						t.Error("Unexpected interaction edit")
					default:
						// No interaction edit, as expected
					}
				}
			},
		)
	}
}
