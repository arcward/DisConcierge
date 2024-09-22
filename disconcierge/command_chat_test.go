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

// TestChatCommand_NextAvailable validates that nextRequestAvailable returns
// the expected times when calculating user rate limits
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
	var nowTS int64 = 1722550666879
	now := time.UnixMilli(nowTS)

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

// TestChatCommand_CreateMessage_Failed checks ChatCommand execution behavior
// when attempting to call the OpenAI 'create message' endpoint returns an
// error (e.g. 401 Unauthorized)
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
	require.NotNil(t, state)
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

// TestChatCommand_ListMessage_Failed checks ChatCommand execution behavior
// when attempting to call the OpenAI 'list messages' endpoint returns an
// error (e.g. 401 Unauthorized)
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
	require.NotNil(t, state)

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

// TestChatCommand_CreateThread_Failed checks ChatCommand execution behavior
// when attempting to call the OpenAI 'create thread' endpoint returns an
// error (e.g. 401 Unauthorized)
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
	require.NotNil(t, state)
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

// TestChatCommand_CreateRun_Failed checks ChatCommand execution behavior
// when attempting to call the OpenAI 'create run' endpoint returns an
// error (e.g. 401 Unauthorized)
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
	require.NotNil(t, state)
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

// TestChatCommand_RetrieveRun_Failed checks ChatCommand execution behavior
// when attempting to call the OpenAI 'retrieve run' endpoint returns an
// error (e.g. 401 Unauthorized)
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

// TestChatCommand_RunStatus_Failed tests ChatCommand execution when
// the OpenAI API returns a 'incomplete' run status when polling the run
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

// TestChatCommand_RunStatus_Failed tests ChatCommand execution when
// the OpenAI API returns a 'failed' run status when polling the run
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

// TestChatCommand_CreateOpenAIRun_Failed validates what happens when
// creating an OpenAI run via API fails
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
	go bot.handleInteraction(ctx, bot.getInteractionHandlerFunc(ctx, interaction))

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

// TestChatCommand_WrongRunStatusColumn temporarily sets the `run_status`
// column variable to `runstatus` to induce a DB error during processing,
// to validate the ChatCommand ends up in the correct (failed) state.
// This test is not safe to run in parallel with other tests.
func TestChatCommand_WrongRunStatusColumn(t *testing.T) {
	bot, _ := newDisConcierge(t)
	discordUser := newDiscordUser(t)
	ids := newCommandData(t)
	require.False(t, bot.runtimeConfig.RecoverPanic)
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

	_ = waitForChatCommandRunStatus(
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

// TestChatCommand_Resume_AbandonMaxAttempts tests the behavior of resuming a chat command
// when the maximum number of attempts has been reached.
func TestChatCommand_Resume_AbandonMaxAttempts(t *testing.T) {
	bot, _ := newDisConcierge(t)
	maxRetries := 3
	_, err := bot.writeDB.Update(
		context.TODO(),
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
	_, err = bot.writeDB.Create(context.TODO(), chatCommand)
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
				mockDB.updateFunc = func(_ any, _ string, _ any) (int64, error) {
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
					_ context.Context,
				) (string, error) {
					return "new-thread", nil
				}
				mockDB.updateFunc = func(_ any, _ string, _ any) (int64, error) {
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
				mockOpenAI.createThreadFunc = func(_ context.Context) (string, error) {
					return "", errors.New("creation error")
				}
			},
			expectedError: true,
		},
		{
			name:        "Error Inserting Thread",
			chatCommand: &ChatCommand{Interaction: Interaction{User: &User{}}},
			mockSetup: func() {
				mockDB.createFunc = func(_ any, _ ...string) (int64, error) {
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

func TestChatCommand_HandleError(t *testing.T) {
	t.Parallel()

	bot, _, _ := newTestDisConcierge(t, nil)
	ctx := context.Background()

	discordUser := newDiscordUser(t)
	user, _, err := bot.GetOrCreateUser(ctx, *discordUser)
	require.NoError(t, err)

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
					Attempts: tt.initialAttempts,
					Interaction: Interaction{
						InteractionID: tt.name,
						TokenExpires:  tt.tokenExpires,
						User:          user,
						UserID:        user.ID,
					},
					State: ChatCommandStateQueued,
				}

				mockHandler := newStubInteractionHandler(t)
				cmdConfig := mockHandler.config
				cmdConfig.ChatCommandMaxAttempts = tt.maxAttempts
				mockHandler.config = cmdConfig
				chatCommand.handler = mockHandler
				_, err = bot.writeDB.Create(context.Background(), chatCommand)
				require.NoError(t, err)

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

// waitForChatCommandState polls, and returns true if the ChatCommand reaches
// one of the given states
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
			err := db.Select(columnChatCommandState).Take(&chatCommand).Error
			require.NoError(t, err)
			previousState = chatCommand.State
			for _, s := range state {
				if chatCommand.State == s {
					return true
				}
			}
		}
	}
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
	require.NotNil(t, cmdChat)

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
				err := db.Select(columnChatCommandState).Take(&chatCommand).Error
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

type mockDBI struct {
	updateFunc func(model any, column string, value any) (
		int64,
		error,
	)
	createFunc func(value any, omit ...string) (int64, error)
	DBI
}

func (m *mockDBI) Create(_ context.Context, value any, omit ...string) (
	rowsAffected int64,
	err error,
) {
	if m.createFunc != nil {
		return m.createFunc(value, omit...)
	}
	return 1, nil
}

func (m *mockDBI) Update(_ context.Context, model any, column string, value any) (int64, error) {
	if m.updateFunc != nil {
		return m.updateFunc(model, column, value)
	}
	return 0, nil
}

type dbiFailedUpdate struct {
	DBI
	t testing.TB
}

func (d *dbiFailedUpdate) Update(
	_ context.Context,
	model any,
	column string,
	value any,
) (rowsAffected int64, err error) {
	d.t.Helper()

	_, ok := model.(*User)
	if ok {
		return 0, errors.New(d.t.Name())
	}
	return d.DBI.Update(context.TODO(), model, column, value)
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
