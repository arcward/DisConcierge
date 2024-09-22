package disconcierge

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bwmarrin/discordgo"
	"github.com/sashabaranov/go-openai"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
	"gorm.io/gorm"
	"log/slog"
	mathrand "math/rand"
	"math/rand/v2"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	openAIOrderDescending = "desc"
)

// TestMockOpenAIAssistantHandler_ListMessage validates that
// we're mocking OpenAI's pagination correctly when it comes
// to listing messages
func TestMockOpenAIAssistantHandler_ListMessage(t *testing.T) {
	handler := &mockOpenAIClientServer{
		t:        t,
		threads:  make(map[string]openai.Thread),
		messages: make(map[string]openai.Message),
		runs:     make(map[string]*openai.Run),
		runSteps: make(map[string]openai.RunStepList),
	}

	thread := handler.newThread(openai.ThreadRequest{})
	handler.threads[thread.ID] = thread

	messages := []openai.Message{
		handler.newMessage(
			thread,
			openai.MessageRequest{
				Content: "Message 1",
				Role:    openaiAssistantRoleUser,
			},
		),
		handler.newMessage(
			thread,
			openai.MessageRequest{
				Content: "Message 2",
				Role:    openaiAssistantRoleAssistant,
			},
		),
		handler.newMessage(
			thread,
			openai.MessageRequest{
				Content: "Message 3",
				Role:    openaiAssistantRoleUser,
			},
		),
		handler.newMessage(
			thread,
			openai.MessageRequest{
				Content: "Message 4",
				Role:    openaiAssistantRoleAssistant,
			},
		),
		handler.newMessage(
			thread,
			openai.MessageRequest{
				Content: "Message 5",
				Role:    openaiAssistantRoleUser,
			},
		),
	}

	for ind, msg := range messages {
		msg.CreatedAt = msg.CreatedAt + ind
		handler.messages[msg.ID] = msg
	}

	ctx := context.Background()

	t.Run(
		"List all messages descending", func(t *testing.T) {
			limit := 10
			order := openAIOrderDescending
			result, err := handler.ListMessage(
				ctx,
				thread.ID,
				&limit,
				&order,
				nil,
				nil,
			)

			require.NoError(t, err)
			assert.Len(t, result.Messages, 5)
			assert.Equal(
				t,
				"Message 5",
				result.Messages[0].Content[0].Text.Value,
			)
			assert.Equal(
				t,
				"Message 1",
				result.Messages[4].Content[0].Text.Value,
			)
		},
	)

	t.Run(
		"List all messages ascending", func(t *testing.T) {
			limit := 10
			order := openaiListMessageOrderAscending
			result, err := handler.ListMessage(
				ctx,
				thread.ID,
				&limit,
				&order,
				nil,
				nil,
			)

			require.NoError(t, err)
			assert.Len(t, result.Messages, 5)
			assert.Equal(
				t,
				"Message 1",
				result.Messages[0].Content[0].Text.Value,
			)
			assert.Equal(
				t,
				"Message 5",
				result.Messages[4].Content[0].Text.Value,
			)
		},
	)

	t.Run(
		"Limit results", func(t *testing.T) {
			limit := 3
			order := openAIOrderDescending
			result, err := handler.ListMessage(
				ctx,
				thread.ID,
				&limit,
				&order,
				nil,
				nil,
			)

			require.NoError(t, err)
			require.Len(t, result.Messages, 3)
			assert.True(t, result.HasMore)
			assert.Equal(
				t,
				"Message 5",
				result.Messages[0].Content[0].Text.Value,
			)
			assert.Equal(
				t,
				"Message 3",
				result.Messages[2].Content[0].Text.Value,
			)
		},
	)

	t.Run(
		"Paginate with 'after'", func(t *testing.T) {
			limit := 2
			order := openAIOrderDescending
			after := messages[2].ID // Start after "Message 3"
			result, err := handler.ListMessage(
				ctx,
				thread.ID,
				&limit,
				&order,
				&after,
				nil,
			)

			require.NoError(t, err)
			require.Len(t, result.Messages, 2)
			require.Len(t, result.Messages[0].Content, 1)
			require.Len(t, result.Messages[1].Content, 1)
			assert.Equal(
				t,
				"Message 2",
				result.Messages[0].Content[0].Text.Value,
			)
			assert.Equal(
				t,
				"Message 1",
				result.Messages[1].Content[0].Text.Value,
			)
		},
	)

	t.Run(
		"Paginate with 'before'", func(t *testing.T) {
			limit := 2
			order := "asc"
			before := messages[3].ID // End before "Message 4"
			result, err := handler.ListMessage(
				ctx,
				thread.ID,
				&limit,
				&order,
				nil,
				&before,
			)

			require.NoError(t, err)
			assert.Len(t, result.Messages, 2)
			assert.Equal(
				t,
				"Message 1",
				result.Messages[0].Content[0].Text.Value,
			)
			assert.Equal(
				t,
				"Message 2",
				result.Messages[1].Content[0].Text.Value,
			)
		},
	)

	t.Run(
		"Non-existent thread", func(t *testing.T) {
			limit := 10
			order := openAIOrderDescending
			_, err := handler.ListMessage(
				ctx,
				"non_existent_thread",
				&limit,
				&order,
				nil,
				nil,
			)

			require.Error(t, err)
			assert.Contains(t, err.Error(), "no thread_id found")
		},
	)

	t.Run(
		"Empty thread", func(t *testing.T) {
			emptyThread := handler.newThread(openai.ThreadRequest{})
			handler.threads[emptyThread.ID] = emptyThread

			limit := 10
			order := openAIOrderDescending
			result, err := handler.ListMessage(
				ctx,
				emptyThread.ID,
				&limit,
				&order,
				nil,
				nil,
			)

			require.NoError(t, err)
			assert.Empty(t, result.Messages)
			assert.False(t, result.HasMore)
		},
	)
}

func TestPollRun(t *testing.T) {
	t.Parallel()
	ids := newCommandData(t)

	pollClient := &mockOpenAIPollingClient{
		RunID:    ids.RunID,
		ThreadID: ids.ThreadID,
		t:        t,
		RunStatusProgression: []openai.RunStatus{
			openai.RunStatusQueued,
			openai.RunStatusInProgress,
			openai.RunStatusInProgress,
			openai.RunStatusInProgress,
			openai.RunStatusCompleted,
		},
		Responses: []openai.Run{},
	}

	cfg := &OpenAIConfig{AssistantID: ids.AssistantID}
	botAI := &OpenAI{
		client: pollClient,
		config: cfg,
		logger: slog.Default(),
	}
	db := setupTestDB(t)
	writeDB := NewDatabase(db, nil, false)
	ctx, cancel := context.WithTimeout(
		context.Background(),
		time.Duration(300)*time.Second,
	)
	t.Cleanup(cancel)

	user := &User{ID: ids.UserID, Username: ids.Username}
	req := &ChatCommand{
		Interaction: Interaction{
			UserID:        user.ID,
			User:          user,
			InteractionID: "baz",
		},
		ThreadID: ids.ThreadID,
		RunID:    ids.RunID,
	}
	require.NoError(t, db.Create(user).Error)
	require.NoError(t, db.Create(req).Error)

	err := botAI.pollUpdateRunStatus(
		ctx,
		writeDB,
		req,
		500*time.Millisecond,
		1*time.Second,
		5,
	)

	require.NoError(t, err)
	assert.Equal(t, openai.RunStatusCompleted, req.RunStatus)

	queryCtx, queryCancel := context.WithTimeout(
		context.Background(),
		20*time.Second,
	)
	t.Cleanup(queryCancel)

	time.Sleep(1 * time.Second)
	var requests []OpenAIRetrieveRun
	rv := db.WithContext(queryCtx).Find(&requests)
	require.NoError(t, rv.Error)
	assert.Equal(t, len(pollClient.Responses), len(requests))

	var lastRequest *OpenAIRetrieveRun
	rv = db.Last(&lastRequest)
	require.NoError(t, rv.Error)
	assert.Equal(t, req.ID, *lastRequest.ChatCommandID)

	var lastRun openai.Run
	err = json.Unmarshal([]byte(lastRequest.ResponseBody), &lastRun)
	require.NoError(t, err)

	assert.Equal(t, req.ThreadID, lastRun.ThreadID)
	assert.Equal(t, "", lastRequest.Error)
}

func TestGetMessageResponse(t *testing.T) {
	ids := newCommandData(t)
	mockClient := newMockOpenAIClient(t, &ids)

	cfg := &OpenAIConfig{
		AssistantID: ids.AssistantID,
	}
	botAI := &OpenAI{
		client: mockClient,
		config: cfg,
		logger: slog.Default(),
	}
	db := setupTestDB(t)
	writeDB := NewDatabase(db, nil, false)
	ctx, cancel := context.WithTimeout(
		context.Background(),
		time.Duration(300)*time.Second,
	)
	t.Cleanup(cancel)

	discordUser := &User{
		ID:       ids.UserID,
		Username: ids.Username,
	}

	_, err := writeDB.Create(context.TODO(), discordUser)
	require.NoError(t, err)

	req := &ChatCommand{
		ThreadID: ids.ThreadID,
		RunID:    ids.RunID,
		Interaction: Interaction{
			UserID:        discordUser.ID,
			User:          discordUser,
			InteractionID: ids.InteractionID,
		},
	}

	_, err = writeDB.Create(context.TODO(), req)
	require.NoError(t, err)

	if len(mockClient.PromptResponses) == 0 {
		t.Fatal("no prompt registered")
	}
	var rawMsg string
	for _, pr := range mockClient.PromptResponses {
		rawMsg = pr
		break
	}
	assert.NotEmpty(t, rawMsg)

	msgList := newOpenAIMessageList(t, rawMsg, ids)
	mockClient.ListMessageResponse[ids.ThreadID] = msgList

	answer, err := botAI.getMessageResponse(
		ctx,
		writeDB,
		req,
	)
	answer = minifyString(
		removeCitations(answer),
		discordMaxMessageLength,
	)
	require.NoError(t, err)
	assert.NotEqual(t, "", answer)

	expectedMsg := minifyString(
		removeCitations(rawMsg),
		discordMaxMessageLength,
	)

	assert.Equal(t, expectedMsg, answer)

	var requests []*OpenAIListMessages
	rv := db.Find(&requests)
	require.NoError(t, rv.Error)
	assert.Equal(t, 1, len(requests))

	var lastRequest *OpenAIListMessages
	rv = db.Last(&lastRequest)
	require.NoError(t, rv.Error)

	assert.Equal(t, req.ID, *lastRequest.ChatCommandID)
	assert.Equal(t, "", lastRequest.Error)
}

func TestCreateMessage(t *testing.T) {
	bot, _ := newDisConcierge(t)

	commandIDs := newCommandData(t)

	mockClient := &mockOpenAIClient{
		t: t,
		CreateMessageResponse: map[string]openai.Message{
			commandIDs.ThreadID: openai.Message{ID: commandIDs.MessageID},
		},
	}
	bot.openai.client = mockClient

	db := setupTestDB(t)
	writeDB := NewDatabase(db, nil, false)

	// Create a user first
	user := &User{
		ID:       commandIDs.UserID,
		Username: commandIDs.Username,
	}
	if _, err := writeDB.Create(context.TODO(), user); err != nil {
		t.Fatalf("error creating test user: %v", err)
	}

	// Now create the ChatCommand with the associated user
	req := &ChatCommand{
		Prompt:   "Test prompt",
		ThreadID: commandIDs.ThreadID,
		CustomID: commandIDs.CustomID,
		Interaction: Interaction{
			UserID:        commandIDs.UserID,
			User:          user,
			InteractionID: commandIDs.InteractionID,
		},
	}
	if _, err := writeDB.Create(context.TODO(), req); err != nil {
		t.Fatalf("error creating test data: %v", err)
	}
	openAI := bot.openai
	messageID, err := openAI.CreateMessage(context.Background(), writeDB, req)

	require.NoError(t, err)
	assert.Equal(t, commandIDs.MessageID, messageID)

	var messageRecord OpenAICreateMessage
	result := db.First(&messageRecord)
	require.NoError(t, result.Error)
	assert.Equal(t, req.ID, *messageRecord.ChatCommandID)
	assert.NotEmpty(t, messageRecord.RequestBody)
	assert.NotEmpty(t, messageRecord.ResponseBody)
}

func TestRetrieveRun(t *testing.T) {
	ids := newCommandData(t)
	mockClient := newMockOpenAIClient(t, &ids)
	mockClient.RetrieveRunResponse = map[string]openai.Run{
		fmt.Sprintf("%s_%s", ids.ThreadID, ids.RunID): {
			ID:       ids.RunID,
			ThreadID: ids.ThreadID,
			Status:   openai.RunStatusCompleted,
			Usage: openai.Usage{
				PromptTokens:     10,
				CompletionTokens: 20,
				TotalTokens:      30,
			},
		},
	}

	bot, _ := newDisConcierge(t)
	bot.openai.client = mockClient

	db := setupTestDB(t)
	writeDB := NewDatabase(db, nil, false)

	// Create a user first
	user := &User{
		ID:       ids.UserID,
		Username: ids.Username,
	}
	if _, err := writeDB.Create(context.TODO(), user); err != nil {
		t.Fatalf("error creating test user: %v", err)
	}

	req := &ChatCommand{
		ThreadID: ids.ThreadID,
		RunID:    ids.RunID,
		CustomID: ids.CustomID,
		Interaction: Interaction{
			UserID:        user.ID,
			User:          user,
			InteractionID: ids.InteractionID,
		},
	}
	if _, err := writeDB.Create(context.TODO(), req); err != nil {
		t.Fatalf("error creating test data: %v", err)
	}
	oo := bot.openai
	run, err := oo.RetrieveRun(context.Background(), writeDB, req)

	require.NoError(t, err)
	assert.Equal(t, ids.RunID, run.ID)
	assert.Equal(t, ids.ThreadID, run.ThreadID)
	assert.Equal(t, openai.RunStatusCompleted, run.Status)
	assert.Equal(t, 10, run.Usage.PromptTokens)
	assert.Equal(t, 20, run.Usage.CompletionTokens)
	assert.Equal(t, 30, run.Usage.TotalTokens)

	var runRecord OpenAIRetrieveRun
	result := db.First(&runRecord)
	require.NoError(t, result.Error)
	assert.Equal(t, req.ID, *runRecord.ChatCommandID)
	assert.NotEmpty(t, runRecord.ResponseBody)
}

type mockOpenAIPollingClient struct {
	OpenAIClient
	RunID                string
	ThreadID             string
	CheckCount           int
	RunStatusProgression []openai.RunStatus
	mu                   sync.Mutex
	t                    testing.TB
	Responses            []openai.Run
}

func (m *mockOpenAIPollingClient) RetrieveRun(
	_ context.Context,
	threadID string,
	runID string,
) (response openai.Run, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.t.Logf("got retrieve run request")
	m.CheckCount++

	r := openai.Run{
		ID:        runID,
		ThreadID:  threadID,
		CreatedAt: time.Now().Unix(),
		Status:    m.RunStatusProgression[0],
	}
	m.t.Logf("RetrieveRun: %s %s status: %s", threadID, runID, r.Status)
	if len(m.RunStatusProgression) > 1 {
		m.RunStatusProgression = m.RunStatusProgression[1:]
	}
	m.Responses = append(m.Responses, r)
	return r, nil
}

// mockOpenAIClient allows responses (or errors) to be registered
// in advance for various OpenAI API methods.
//
// The struct contains fields for mocking responses and errors for different
// OpenAI API methods.
// Most fields are maps keyed by string identifiers - generally, the key
// is the most specific identifier used in an API call. Ex: Creating a run
// uses the thread ID, so 'create run' responses are keyed by that thread
// ID. A created run has a run ID, so 'retrieve run' responses are keyed by
// the run ID.
//
// Fields:
//
//   - RetrieveAssistantResponse: Map of assistant IDs to mock Assistant responses.
//
//   - RetrieveAssistantError: Map of assistant IDs to errors for RetrieveAssistant calls.
//
//   - CreateThreadResponse: If this isset, it will be returned as the response
//     to the first quest to create a thread, and then this field will be
//     set nil, so the same thread isn't returned more than once.
//     If nil or not set, a random thread ID will be generated based on the
//     test name, and incremented based on the number of threads already created.
//
//   - CreateThreadError: Error to return for CreateThread calls.
//
//   - ThreadsCreated: Map to store created threads.
//
//   - CreateRunResponse: Map of thread IDs to mock Run responses for CreateRun calls.
//
//   - CreateRunError: Map of thread IDs to errors for CreateRun calls.
//
//   - RetrieveRunResponse: Map of run IDs to mock Run responses for RetrieveRun calls.
//
//   - RetrieveRunError: Map of run IDs to errors for RetrieveRun calls.
//
//   - CreateMessageResponse: Map of thread IDs to mock Message responses for CreateMessage calls.
//
//   - CreateMessageError: Map of thread IDs to errors for CreateMessage calls.
//
//   - ListMessageResponse: Map of thread IDs to mock MessagesList responses for ListMessage calls.
//
//   - ListMessageError: Map of thread IDs to errors for ListMessage calls.
//
//   - ListRunStepsResponse: Map of run IDs to mock RunStepList responses for ListRunSteps calls.
//
//   - ListRunStepsError: Map of run IDs to errors for ListRunSteps calls.
//
//   - PromptResponses: Map of prompts to predefined responses.
//
//   - ids: Pointer to commandData for generating unique IDs.
//
// This mock client is useful for unit testing components that depend on OpenAI API
// without making actual API calls, allowing for controlled and predictable test scenarios.
type mockOpenAIClient struct {
	OpenAIClient

	RetrieveAssistantResponse map[string]openai.Assistant
	RetrieveAssistantError    map[string]error

	CreateThreadResponse *openai.Thread
	CreateThreadError    error
	ThreadsCreated       map[string]openai.Thread

	CreateRunResponse map[string]openai.Run
	CreateRunError    map[string]error

	RetrieveRunResponse map[string]openai.Run
	RetrieveRunError    map[string]error

	CreateMessageResponse map[string]openai.Message
	CreateMessageError    map[string]error

	ListMessageResponse map[string]openai.MessagesList
	ListMessageError    map[string]error

	ListRunStepsResponse map[string]openai.RunStepList
	ListRunStepsError    map[string]error

	PromptResponses map[string]string

	ids *commandData
	t   testing.TB
	mu  sync.RWMutex
}

func newMockOpenAIClient(
	t testing.TB,
	ids *commandData,
) *mockOpenAIClient {
	t.Helper()
	if ids == nil {
		cmdData := newCommandData(t)
		ids = &cmdData
	}
	mockClient := &mockOpenAIClient{
		ids: ids,
		t:   t,
		RetrieveAssistantResponse: map[string]openai.Assistant{
			ids.AssistantID: {
				ID: ids.AssistantID,
			},
		},
		CreateThreadResponse: &openai.Thread{
			ID: ids.ThreadID,
		},
		CreateMessageResponse: map[string]openai.Message{},
		CreateRunResponse: map[string]openai.Run{
			ids.ThreadID: {
				ThreadID: ids.ThreadID,
				ID:       ids.RunID,
				Status:   openai.RunStatusQueued,
			},
		},
		RetrieveRunResponse: map[string]openai.Run{
			fmt.Sprintf("%s_%s", ids.ThreadID, ids.RunID): {
				ThreadID: ids.ThreadID,
				ID:       ids.RunID,
				Status:   openai.RunStatusCompleted,
			},
		},
		ListMessageResponse: map[string]openai.MessagesList{},
		ListRunStepsResponse: map[string]openai.RunStepList{
			fmt.Sprintf("%s_%s", ids.ThreadID, ids.RunID): {

				HasMore: false,
				FirstID: ids.StepID,
				LastID:  ids.StepID,
				RunSteps: []openai.RunStep{
					{
						ThreadID: ids.ThreadID,
						ID:       ids.StepID,
						RunID:    ids.RunID,
						Metadata: map[string]any{"interaction_id": ids.InteractionID},
					},
				},
			},
		},
		PromptResponses: map[string]string{
			t.Name(): fmt.Sprintf("I don't know anything about %s", t.Name()),
		},
	}

	prompt := "where is the beef?"
	response := "The 'beef' is a lie."
	mockClient.PromptResponses[prompt] = response

	msgCreated := time.Date(2023, 10, 31, 12, 0, 0, 0, time.UTC)

	msg := openai.Message{
		ID:        ids.MessageID,
		ThreadID:  ids.ThreadID,
		Object:    "message",
		Role:      "user",
		CreatedAt: int(msgCreated.Unix()),
		Content: []openai.MessageContent{
			{
				Type: "text",
				Text: &openai.MessageText{Value: prompt},
			},
		},
		// AssistantID: ids.AssistantID,
	}

	msgResponse := openai.Message{
		ID:        fmt.Sprintf("response_%s", ids.MessageID),
		ThreadID:  ids.ThreadID,
		Object:    "message",
		Role:      openaiAssistantRoleAssistant,
		CreatedAt: int(msgCreated.Add(time.Minute).Unix()),
		Content: []openai.MessageContent{
			{
				Type: "text",
				Text: &openai.MessageText{Value: response},
			},
		},
	}
	mockClient.CreateMessageResponse[ids.ThreadID] = msg
	mockClient.ListMessageResponse[ids.ThreadID] = openai.MessagesList{
		Object:   "list",
		FirstID:  &msgResponse.ID,
		LastID:   &msg.ID,
		HasMore:  false,
		Messages: []openai.Message{msgResponse, msg},
	}

	return mockClient
}

func (m *mockOpenAIClient) RetrieveAssistant(
	_ context.Context,
	assistantID string,
) (response openai.Assistant, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	response, ok := m.RetrieveAssistantResponse[assistantID]
	responseErr, okErr := m.RetrieveAssistantError[assistantID]

	if !ok && !okErr {
		return response, fmt.Errorf("no entry for assistant %s", assistantID)
	}
	return response, responseErr
}

func (m *mockOpenAIClient) CreateThread(
	_ context.Context,
	_ openai.ThreadRequest,
) (response openai.Thread, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.CreateThreadError != nil {
		return openai.Thread{}, m.CreateThreadError
	}
	if m.ThreadsCreated == nil {
		m.ThreadsCreated = map[string]openai.Thread{}
	}

	if m.CreateThreadResponse != nil {
		m.ThreadsCreated[m.CreateThreadResponse.ID] = *m.CreateThreadResponse
		resp := *m.CreateThreadResponse
		m.CreateThreadResponse = nil
		return resp, nil
	}

	thread := openai.Thread{
		ID: fmt.Sprintf(
			"thread_%s-%d",
			m.t.Name(),
			len(m.ThreadsCreated)+1,
		),
		Object:    "thread",
		CreatedAt: time.Now().Unix(),
	}
	if len(m.ThreadsCreated) == 0 {
		thread.ID = fmt.Sprintf("thread_%s", m.t.Name())
	} else {
		thread.ID = fmt.Sprintf(
			"thread_%s-%d",
			m.t.Name(),
			len(m.ThreadsCreated)+1,
		)
	}
	_, ok := m.ThreadsCreated[thread.ID]
	if ok {
		m.t.Fatalf("conflict")
	}
	m.ThreadsCreated[thread.ID] = thread
	return thread, m.CreateThreadError
}

func (m *mockOpenAIClient) CreateRun(
	_ context.Context,
	threadID string,
	_ openai.RunRequest,
) (response openai.Run, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.t.Logf("error: %v response: %v", m.CreateRunError, m.CreateRunResponse)

	response, ok := m.CreateRunResponse[threadID]
	responseErr, okErr := m.CreateRunError[threadID]

	if !ok && !okErr {
		return response, fmt.Errorf(
			"tried to create run, but no entry for thread %s",
			threadID,
		)
	}
	return response, responseErr
}

func (m *mockOpenAIClient) RetrieveRun(
	_ context.Context,
	threadID string,
	runID string,
) (response openai.Run, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.t.Logf(
		"error: %v response: %v",
		m.RetrieveRunError,
		m.RetrieveRunResponse,
	)
	id := fmt.Sprintf("%s_%s", threadID, runID)
	response, ok := m.RetrieveRunResponse[id]
	responseErr, okErr := m.RetrieveRunError[id]

	if !ok && !okErr {
		return response, fmt.Errorf(
			"no entry for thread %s, run %s (id: %#v registered: %#v)",
			threadID,
			runID,
			id,
			m.RetrieveRunResponse,
		)
	}
	if response.Status == openai.RunStatusCompleted {
		createMsg := m.CreateMessageResponse[threadID]
		var prompt string
		if len(createMsg.Content) > 0 {
			prompt = createMsg.Content[len(createMsg.Content)-1].Text.Value
		}
		promptResponse, ok := m.PromptResponses[prompt]
		m.t.Logf("response to '%s': %#v", prompt, promptResponse)
		if ok && m.ListMessageError[threadID] == nil {
			msgList, ok := m.ListMessageResponse[threadID]
			if ok {
				m.t.Logf("message list found: %#v", msgList)
			} else {
				m.t.Logf("no msg list found, creating new")
				msgList = newOpenAIMessageList(m.t, prompt, *m.ids)
				firstMsg := msgList.Messages[0]
				firstMsg.Role = openaiAssistantRoleUser

				responseMessageID := fmt.Sprintf("msg_response_%s", m.t.Name())
				responseMsg := openai.Message{
					ID:        responseMessageID,
					Object:    "thread.message",
					CreatedAt: int(time.Now().Unix()),
					ThreadID:  threadID,
					Role:      openaiAssistantRoleAssistant,
					Content: []openai.MessageContent{
						{
							Type: "text",
							Text: &openai.MessageText{
								Value: promptResponse,
							},
						},
					},
					AssistantID: &m.ids.AssistantID,
					RunID:       &runID,
				}
				msgList.FirstID = &responseMsg.ID
				msgList.LastID = &firstMsg.ID
				msgList.Messages[0] = responseMsg
				msgList.Messages = append(msgList.Messages, firstMsg)
				m.ListMessageResponse[threadID] = msgList
			}
		} else {
			m.t.Logf(
				"no response found for prompt '%s' (registered: %#v)",
				prompt,
				m.PromptResponses,
			)
		}
	}
	return response, responseErr
}

func (m *mockOpenAIClient) CreateMessage(
	_ context.Context,
	threadID string,
	request openai.MessageRequest,
) (msg openai.Message, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.t.Logf(
		"error: %v response: %v",
		m.CreateMessageError,
		m.CreateMessageResponse,
	)
	response, ok := m.CreateMessageResponse[threadID]
	responseErr, okErr := m.CreateMessageError[threadID]

	if ok {
		return response, responseErr
	} else if okErr {
		return response, responseErr
	}

	msg.ID = m.ids.MessageID
	msg.ThreadID = threadID
	msg.Content = []openai.MessageContent{
		{
			Type: "text",
			Text: &openai.MessageText{Value: request.Content},
		},
	}
	msg.Object = "message"
	msg.Role = openaiAssistantRoleUser
	msgList, ok := m.ListMessageResponse[threadID]
	if !ok {
		msgList = openai.MessagesList{
			Messages: []openai.Message{},
			Object:   "list",
		}
	}

	msgList.Messages = append(msgList.Messages, msg)
	firstID := msgList.Messages[0].ID
	lastID := msgList.Messages[len(msgList.Messages)-1].ID
	msgList.FirstID = &firstID
	msgList.LastID = &lastID
	m.ListMessageResponse[threadID] = msgList

	return response, fmt.Errorf("no entry for thread %s", threadID)
}

func (m *mockOpenAIClient) ListMessage(
	_ context.Context,
	threadID string,
	limit *int,
	order *string,
	after *string,
	before *string,
) (messages openai.MessagesList, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.t.Logf(
		"error: %#v response: %#v limit: %v order: %v after: %v before: %v",
		m.ListMessageError,
		m.ListMessageResponse,
		*limit,
		*order,
		*after,
		before,
	)
	response, ok := m.ListMessageResponse[threadID]
	responseErr, okErr := m.ListMessageError[threadID]

	if !ok && !okErr {
		m.t.Logf("no list messages registered")
		return response, fmt.Errorf("no entry for thread %s", threadID)
	}

	if okErr {
		m.t.Logf("found error: %#v", responseErr)
		return response, responseErr
	}
	return openaiPaginateListMessage(response, limit, order, after, before), nil
}

func (m *mockOpenAIClient) ListRunSteps(
	_ context.Context,
	threadID string,
	runID string,
	_ openai.Pagination,
) (response openai.RunStepList, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.t.Logf(
		"error: %v response: %v",
		m.ListRunStepsError,
		m.ListRunStepsResponse,
	)
	id := fmt.Sprintf("%s_%s", threadID, runID)
	response, ok := m.ListRunStepsResponse[id]
	responseErr, okErr := m.ListRunStepsError[id]

	if !ok && !okErr {
		return response, fmt.Errorf(
			"no entry for thread %s, run %s",
			threadID,
			runID,
		)
	}

	return response, responseErr
}

// mockOpenAIClientServer implements OpenAIClient in a way that
// simulates the OpenAI API behavior. Objects that are created are
// given random/unique IDs, and those objects are tracked, so calls
// to retrieve them return the appropriate objects - as well as
// an error if an unknown ID is referenced.
//
// This means workflows should enqueue from CreateThread, then CreateMessage,
// then CreateRun, then RetrieveRun, then ListMessage.
//
// **Note**: The ListMessage function also attempts to simulate pagination based on
// query parameters.
type mockOpenAIClientServer struct {
	// Threads created, mapped by thread ID
	threads map[string]openai.Thread

	// Messages created, mapped by message ID
	messages map[string]openai.Message

	// Runs created, mapped by run ID
	runs map[string]*openai.Run

	// Run steps, mapped by run ID
	runSteps map[string]openai.RunStepList

	// maps user prompts to assistant responses
	prompts map[string]string

	mu               sync.RWMutex
	retrieveRunCount map[string]int
	t                testing.TB

	// Called by RetrieveRun on the openai.Run object before returning it.
	// Use this to do things like update the openai.RunStatus or other fields.
	// By default, this is a function that transitions the run
	// status from queued -> in_progress -> completed, with one transition
	// per RetrieveRun call, to simulate polling and an eventual successful
	// result. When `in_progress` is seen and transitioned to `completed`,
	// a new openai.Message is created simulating the assistant response
	// to the prompt.
	beforeReturnRunFunc func(m *mockOpenAIClientServer, run *openai.Run)
}

func newMockOpenAIAssistantHandler(
	t testing.TB,
) *mockOpenAIClientServer {
	h := &mockOpenAIClientServer{
		t:                t,
		threads:          map[string]openai.Thread{},
		messages:         map[string]openai.Message{},
		runs:             map[string]*openai.Run{},
		prompts:          map[string]string{},
		runSteps:         map[string]openai.RunStepList{},
		mu:               sync.RWMutex{},
		retrieveRunCount: map[string]int{},
		beforeReturnRunFunc: func(m *mockOpenAIClientServer, run *openai.Run) {
			m.retrieveRunCount[run.ID]++
			switch run.Status {
			case openai.RunStatusQueued:
				run.Status = openai.RunStatusInProgress
			case openai.RunStatusInProgress:
				run.Status = openai.RunStatusCompleted
				runMessages := m.threadMessages(run.ThreadID)

				userMessages := make([]openai.Message, 0, len(runMessages))
				for _, ms := range runMessages {
					if ms.Role == openaiAssistantRoleUser {
						userMessages = append(userMessages, ms)
					}
				}
				slices.SortFunc(
					userMessages, func(x, y openai.Message) int {
						return cmp.Compare(y.CreatedAt, x.CreatedAt)
					},
				)
				prompt := userMessages[0].Content[0].Text.Value
				promptReply, ok := m.prompts[prompt]
				if !ok {
					m.t.Logf(
						"no reply found for prompt '%s' (known: %#v)",
						prompt,
						m.prompts,
					)
				}
				msg := m.newAssistantMessage(
					run.ThreadID, promptReply,
				)
				m.messages[msg.ID] = msg

				runSteps := m.newRunStepList(*run, msg)
				m.runSteps[run.ID] = runSteps
			}
		},
	}
	h.prompts[t.Name()] = fmt.Sprintf(
		"I don't know anything about %s",
		t.Name(),
	)
	return h
}

func (m *mockOpenAIClientServer) newRunStepList(
	run openai.Run,
	msg openai.Message,
) openai.RunStepList {
	id, err := GenerateRandomIntString(randomGenerator, 6)
	require.NoError(m.t, err)

	id = fmt.Sprintf("step_%s_%s", m.t.Name(), id)
	step := openai.RunStep{
		ID:        id,
		Object:    "thread.run.step",
		CreatedAt: time.Now().UnixNano(),
		ThreadID:  run.ThreadID,
		RunID:     run.ID,
		Type:      "message_creation",
		Status:    "completed",
		StepDetails: openai.StepDetails{
			Type: "message_creation",
			MessageCreation: &openai.StepDetailsMessageCreation{
				MessageID: msg.ID,
			},
		},
		CompletedAt: run.CompletedAt,
	}
	steps := openai.RunStepList{
		RunSteps: []openai.RunStep{step},
		FirstID:  step.ID,
		LastID:   step.ID,
	}
	return steps
}

func (m *mockOpenAIClientServer) threadMessages(threadID string) []openai.Message {
	messages := []openai.Message{}
	for _, msg := range m.messages {
		if msg.ThreadID == threadID {
			messages = append(messages, msg)
		}
	}
	slices.SortFunc(
		messages, func(x, y openai.Message) int {
			return cmp.Compare(x.CreatedAt, y.CreatedAt)
		},
	)
	return messages
}

func (m *mockOpenAIClientServer) CreateMessage(
	_ context.Context,
	threadID string,
	request openai.MessageRequest,
) (msg openai.Message, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	thread, ok := m.threads[threadID]
	if !ok {
		return msg, errors.New("thread not found")
	}
	msg = m.newMessage(thread, request)
	m.messages[msg.ID] = msg
	return msg, nil
}

func (m *mockOpenAIClientServer) CreateRun(
	_ context.Context,
	threadID string,
	request openai.RunRequest,
) (response openai.Run, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	thread, ok := m.threads[threadID]
	if !ok {
		return response, errors.New("thread not found")
	}
	run := m.newRun(thread, request)
	m.runs[run.ID] = &run
	m.retrieveRunCount[run.ID] = 0
	return run, nil
}

func (m *mockOpenAIClientServer) CreateThread(
	_ context.Context,
	request openai.ThreadRequest,
) (response openai.Thread, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	thread := m.newThread(request)
	m.threads[thread.ID] = thread
	return thread, nil
}

func (*mockOpenAIClientServer) GetFile(
	_ context.Context,
	_ string,
) (file openai.File, err error) {
	return file, err
}

func (m *mockOpenAIClientServer) ListMessage(
	_ context.Context,
	threadID string,
	limit *int,
	order *string,
	after *string,
	before *string,
) (messages openai.MessagesList, err error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	_, ok := m.threads[threadID]
	if !ok {
		return messages, fmt.Errorf("no thread_id found %s", threadID)
	}
	existingMessages := []openai.Message{}
	msgList := openai.MessagesList{Object: "list", Messages: []openai.Message{}}

	for _, msg := range m.messages {
		if msg.ThreadID == threadID {
			existingMessages = append(existingMessages, msg)
		}
	}
	msgList.Messages = existingMessages
	return openaiPaginateListMessage(msgList, limit, order, after, before), nil
}

func (m *mockOpenAIClientServer) ListRunSteps(
	_ context.Context,
	threadID string,
	runID string,
	_ openai.Pagination,
) (response openai.RunStepList, err error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, threadOk := m.threads[threadID]
	if !threadOk {
		return response, fmt.Errorf("no thread found for thread %s", threadID)
	}
	response, ok := m.runSteps[runID]
	if !ok {
		return response, fmt.Errorf("no run steps found for run %s", runID)
	}

	return response, nil
}

func (m *mockOpenAIClientServer) RetrieveRun(
	_ context.Context,
	threadID string,
	runID string,
) (response openai.Run, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.threads[threadID]
	if !ok {
		return response, fmt.Errorf("unknown thread '%s'", threadID)
	}

	run, ok := m.runs[runID]
	if !ok {
		return response, fmt.Errorf("unknown run '%s'", runID)
	}
	m.beforeReturnRunFunc(m, run)
	return *run, nil
}

func (*mockOpenAIClientServer) RetrieveAssistant(
	_ context.Context,
	_ string,
) (response openai.Assistant, err error) {
	return response, nil
}

func (m *mockOpenAIClientServer) newThread(req openai.ThreadRequest) openai.Thread {
	id, err := GenerateRandomIntString(randomGenerator, 6)
	require.NoError(m.t, err)

	id = fmt.Sprintf("thread_%s_%s", m.t.Name(), id)

	thread := openai.Thread{
		ID:        id,
		Object:    "thread",
		CreatedAt: time.Now().Unix(),
	}
	if req.Metadata != nil {
		meta := map[string]any{}
		for k, v := range req.Metadata {
			meta[k] = v
		}
		thread.Metadata = meta
	}
	return thread
}

func (m *mockOpenAIClientServer) newMessage(
	thread openai.Thread,
	request openai.MessageRequest,
) openai.Message {
	id, err := GenerateRandomIntString(randomGenerator, 6)
	require.NoError(m.t, err)

	id = fmt.Sprintf("msg_%s_%s", m.t.Name(), id)
	content := openai.MessageContent{
		Type: "text",
		Text: &openai.MessageText{
			Value: request.Content,
		},
	}
	msg := openai.Message{
		ID:        id,
		ThreadID:  thread.ID,
		CreatedAt: int(time.Now().UnixNano()),
		Object:    "thread.message",
		Role:      request.Role,
		Metadata:  request.Metadata,
		Content:   []openai.MessageContent{content},
	}
	return msg
}

func (m *mockOpenAIClientServer) newAssistantMessage(
	threadID string,
	content string,
) openai.Message {
	id, err := GenerateRandomIntString(randomGenerator, 6)
	require.NoError(m.t, err)

	id = fmt.Sprintf("msg_%s_%s", m.t.Name(), id)
	msg := openai.Message{
		ID:        id,
		ThreadID:  threadID,
		CreatedAt: int(time.Now().UnixNano()),
		Object:    "thread.message",
		Role:      openaiAssistantRoleAssistant,
		Content: []openai.MessageContent{
			{
				Type: "text",
				Text: &openai.MessageText{
					Value: content,
				},
			},
		},
	}
	return msg
}

func (m *mockOpenAIClientServer) newRun(
	thread openai.Thread,
	request openai.RunRequest,
) openai.Run {
	id, err := GenerateRandomIntString(randomGenerator, 6)
	require.NoError(m.t, err)

	id = fmt.Sprintf("run_%s_%s", m.t.Name(), id)

	run := openai.Run{
		ID:                  id,
		Object:              "run",
		Metadata:            request.Metadata,
		Instructions:        request.Instructions,
		ThreadID:            thread.ID,
		Temperature:         request.Temperature,
		MaxPromptTokens:     request.MaxPromptTokens,
		MaxCompletionTokens: request.MaxCompletionTokens,
		TruncationStrategy:  request.TruncationStrategy,
		Status:              openai.RunStatusQueued,
		CreatedAt:           time.Now().Unix(),
	}
	return run
}

func newOpenAIMessageList(
	t testing.TB,
	text string,
	ids commandData,
) openai.MessagesList {
	t.Helper()
	msgList := openai.MessagesList{
		Object:  "list",
		FirstID: &ids.MessageID,
		LastID:  &ids.MessageID,
		HasMore: false,
		Messages: []openai.Message{
			{
				ID:        ids.MessageID,
				Object:    "thread.message",
				CreatedAt: int(time.Now().Unix()),
				ThreadID:  ids.ThreadID,
				Role:      openaiAssistantRoleAssistant,
				Content: []openai.MessageContent{
					{
						Type: "text",
						Text: &openai.MessageText{
							Value: text,
						},
					},
				},
				AssistantID: &ids.AssistantID,
				RunID:       &ids.RunID,
			},
		},
	}

	return msgList
}

func TestGetAssistantMessageContent(t *testing.T) {
	tests := []struct {
		name    string
		input   openai.MessagesList
		want    string
		wantErr bool
	}{
		{
			name: "Valid assistant message",
			input: openai.MessagesList{
				Messages: []openai.Message{
					{
						Role:      openaiAssistantRoleAssistant,
						CreatedAt: 1000,
						Content: []openai.MessageContent{
							{
								Type: "text",
								Text: &openai.MessageText{Value: "Hello, I'm an assistant."},
							},
						},
					},
				},
			},
			want:    "Hello, I'm an assistant.",
			wantErr: false,
		},
		{
			name: "Multiple messages, newest assistant message",
			input: openai.MessagesList{
				Messages: []openai.Message{
					{
						Role:      openaiAssistantRoleUser,
						CreatedAt: 1000,
						Content: []openai.MessageContent{
							{
								Type: "text",
								Text: &openai.MessageText{Value: "Hello"},
							},
						},
					},
					{
						Role:      openaiAssistantRoleAssistant,
						CreatedAt: 2000,
						Content: []openai.MessageContent{
							{
								Type: "text",
								Text: &openai.MessageText{Value: "Hi there!"},
							},
						},
					},
					{
						Role:      openaiAssistantRoleAssistant,
						CreatedAt: 3000,
						Content: []openai.MessageContent{
							{
								Type: "text",
								Text: &openai.MessageText{Value: "How can I help you?"},
							},
						},
					},
				},
			},
			want:    "How can I help you?",
			wantErr: false,
		},
		{
			name: "No messages",
			input: openai.MessagesList{
				Messages: []openai.Message{},
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "No assistant messages",
			input: openai.MessagesList{
				Messages: []openai.Message{
					{
						Role:      openaiAssistantRoleUser,
						CreatedAt: 1000,
						Content: []openai.MessageContent{
							{
								Type: "text",
								Text: &openai.MessageText{Value: "Hello"},
							},
						},
					},
				},
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "Assistant message with empty content",
			input: openai.MessagesList{
				Messages: []openai.Message{
					{
						Role:      openaiAssistantRoleAssistant,
						CreatedAt: 1000,
						Content:   []openai.MessageContent{},
					},
				},
			},
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				got, err := getAssistantMessageContent(tt.input.Messages)
				if (err != nil) != tt.wantErr {
					t.Errorf(
						"getAssistantMessageContent() error = %v, wantErr %v, got msg: %#v",
						err,
						tt.wantErr,
						got,
					)
					return
				}
				if got != tt.want {
					t.Errorf(
						"getAssistantMessageContent() = %v, want %v",
						got,
						tt.want,
					)
				}
			},
		)
	}
}

func openaiPaginateListMessage(
	msgList openai.MessagesList,
	limit *int,
	order *string,
	after *string,
	before *string,
) openai.MessagesList {
	existingMessages := make([]openai.Message, len(msgList.Messages))
	copy(existingMessages, msgList.Messages)

	resultLimit := 20
	if limit != nil {
		resultLimit = *limit
	}

	sortOrder := openAIOrderDescending
	if order != nil {
		sortOrder = *order
	}

	slices.SortFunc(
		existingMessages, func(x, y openai.Message) int {
			if sortOrder == "asc" {
				return cmp.Compare(x.CreatedAt, y.CreatedAt)
			}
			return cmp.Compare(y.CreatedAt, x.CreatedAt)
		},
	)

	if after != nil {
		afterID := *after
		for ind, msg := range existingMessages {
			if msg.ID == afterID {
				existingMessages = existingMessages[ind+1:]
				break
			}
		}
	} else if before != nil {
		beforeID := *before
		for ind, msg := range existingMessages {
			if msg.ID == beforeID {
				existingMessages = existingMessages[:ind]
				break
			}
		}
	}

	if len(existingMessages) == 0 {
		return openai.MessagesList{Messages: existingMessages, Object: "list"}
	}

	if resultLimit < len(existingMessages) {
		existingMessages = existingMessages[:resultLimit]
		msgList.HasMore = true
	}
	msgList.Messages = existingMessages
	firstID := existingMessages[0].ID
	lastID := existingMessages[len(existingMessages)-1].ID
	msgList.FirstID = &firstID
	msgList.LastID = &lastID
	return msgList
}

func TestOpenaiPaginateListMessage(t *testing.T) {
	// Create a sample list of messages
	messages := []openai.Message{
		{ID: "1", CreatedAt: 1000},
		{ID: "2", CreatedAt: 2000},
		{ID: "3", CreatedAt: 3000},
		{ID: "4", CreatedAt: 4000},
		{ID: "5", CreatedAt: 5000},
	}

	msgList := openai.MessagesList{
		Messages: messages,
	}

	t.Run(
		"Default order and limit (desc,20)", func(t *testing.T) {
			result := openaiPaginateListMessage(msgList, nil, nil, nil, nil)
			assert.Len(t, result.Messages, 5)
			assert.Equal(t, "5", result.Messages[0].ID)
			assert.Equal(t, "1", result.Messages[4].ID)
			assert.Equal(t, "5", *result.FirstID)
			assert.Equal(t, "1", *result.LastID)
			assert.False(t, result.HasMore)
		},
	)

	t.Run(
		"Ascending order", func(t *testing.T) {
			order := "asc"
			result := openaiPaginateListMessage(msgList, nil, &order, nil, nil)
			assert.Len(t, result.Messages, 5)
			assert.Equal(t, "1", result.Messages[0].ID)
			assert.Equal(t, "5", result.Messages[4].ID)
			assert.Equal(t, "1", *result.FirstID)
			assert.Equal(t, "5", *result.LastID)
		},
	)

	t.Run(
		"Limit", func(t *testing.T) {
			limit := 3
			result := openaiPaginateListMessage(msgList, &limit, nil, nil, nil)
			assert.Equal(t, 3, len(result.Messages))
			assert.Equal(t, "5", result.Messages[0].ID)
			assert.Equal(t, "3", result.Messages[2].ID)
			assert.True(t, result.HasMore)
		},
	)

	t.Run(
		"After", func(t *testing.T) {
			after := "3"
			result := openaiPaginateListMessage(msgList, nil, nil, &after, nil)
			assert.Equal(t, 2, len(result.Messages))
			assert.Equal(t, "2", result.Messages[0].ID)
			assert.Equal(t, "1", result.Messages[1].ID)
		},
	)

	t.Run(
		"Before", func(t *testing.T) {
			before := "3"
			result := openaiPaginateListMessage(msgList, nil, nil, nil, &before)
			assert.Equal(t, 2, len(result.Messages))
			assert.Equal(t, "5", result.Messages[0].ID)
			assert.Equal(t, "4", result.Messages[1].ID)
		},
	)

	t.Run(
		"Combination of parameters", func(t *testing.T) {
			limit := 2
			order := "asc"
			after := "2"
			result := openaiPaginateListMessage(
				msgList,
				&limit,
				&order,
				&after,
				nil,
			)
			assert.Equal(t, 2, len(result.Messages))
			assert.Equal(t, "3", result.Messages[0].ID)
			assert.Equal(t, "4", result.Messages[1].ID)
			assert.True(t, result.HasMore)
		},
	)

	t.Run(
		"Empty result descending", func(t *testing.T) {
			after := "1"
			result := openaiPaginateListMessage(msgList, nil, nil, &after, nil)
			assert.Emptyf(
				t,
				result.Messages,
				"should be empty, found %d messages: %#v",
				len(result.Messages),
				result.Messages,
			)
			assert.Nil(t, result.FirstID)
			assert.Nil(t, result.LastID)
		},
	)
	t.Run(
		"Empty result ascending", func(t *testing.T) {
			after := "5"
			order := "asc"
			result := openaiPaginateListMessage(
				msgList,
				nil,
				&order,
				&after,
				nil,
			)
			assert.Emptyf(
				t,
				result.Messages,
				"should be empty, found %d messages: %#v",
				len(result.Messages),
				result.Messages,
			)
			assert.Nil(t, result.FirstID)
			assert.Nil(t, result.LastID)
		},
	)
}

type mockRandomOpenAIServer struct {
	*mockOpenAIClientServer
	r                *rand.Rand
	minResponseDelay time.Duration
	maxResponseDelay time.Duration
}

func (m *mockRandomOpenAIServer) sleepRandom() {
	d := randomDuration(m.r, m.minResponseDelay, m.maxResponseDelay)
	m.t.Logf("%s sleeping for: %s", m.t.Name(), d.String())
	time.Sleep(d)
}

func (m *mockRandomOpenAIServer) CreateMessage(
	ctx context.Context,
	threadID string,
	request openai.MessageRequest,
) (msg openai.Message, err error) {
	m.sleepRandom()
	err = randomError(m.t, m.r)
	if err != nil {
		return msg, err
	}
	return m.mockOpenAIClientServer.CreateMessage(ctx, threadID, request)
}

func (m *mockRandomOpenAIServer) CreateRun(
	ctx context.Context,
	threadID string,
	request openai.RunRequest,
) (response openai.Run, err error) {
	m.sleepRandom()
	err = randomError(m.t, m.r)
	if err != nil {
		return response, err
	}
	return m.mockOpenAIClientServer.CreateRun(ctx, threadID, request)
}

func (m *mockRandomOpenAIServer) CreateThread(
	ctx context.Context,
	request openai.ThreadRequest,
) (response openai.Thread, err error) {
	m.sleepRandom()
	err = randomError(m.t, m.r)
	if err != nil {
		return response, err
	}
	return m.mockOpenAIClientServer.CreateThread(ctx, request)
}

func (m *mockRandomOpenAIServer) ListMessage(
	ctx context.Context,
	threadID string,
	limit *int,
	order *string,
	after *string,
	before *string,
) (messages openai.MessagesList, err error) {
	m.sleepRandom()
	err = randomError(m.t, m.r)
	if err != nil {
		return messages, err
	}
	return m.mockOpenAIClientServer.ListMessage(
		ctx,
		threadID,
		limit,
		order,
		after,
		before,
	)
}

func (m *mockRandomOpenAIServer) ListRunSteps(
	ctx context.Context,
	threadID string,
	runID string,
	pagination openai.Pagination,
) (response openai.RunStepList, err error) {
	m.sleepRandom()
	err = randomError(m.t, m.r)
	if err != nil {
		return response, err
	}
	return m.mockOpenAIClientServer.ListRunSteps(
		ctx,
		threadID,
		runID,
		pagination,
	)
}

func (m *mockRandomOpenAIServer) RetrieveRun(
	ctx context.Context,
	threadID string,
	runID string,
) (response openai.Run, err error) {
	m.sleepRandom()
	err = randomError(m.t, m.r)
	if err != nil {
		return response, err
	}
	return m.mockOpenAIClientServer.RetrieveRun(ctx, threadID, runID)
}

func BenchmarkLoad(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	b.Cleanup(cancel)
	bot, _ := newDisConciergeWithContext(b, ctx)
	bot.requestQueue.config.SleepEmpty = 3 * time.Second
	bot.config.ShutdownTimeout = 20 * time.Second
	mockClient := newMockOpenAIAssistantHandler(b)

	bot.openai.requestLimiter.SetLimit(rate.Limit(10))

	h := &mockRandomOpenAIServer{mockOpenAIClientServer: mockClient}
	h.r = rand.New(rand.NewPCG(1, 2))
	h.minResponseDelay = 100 * time.Millisecond
	h.maxResponseDelay = 3 * time.Second

	mockClient.beforeReturnRunFunc = func(
		m *mockOpenAIClientServer,
		run *openai.Run,
	) {
		m.retrieveRunCount[run.ID]++
		switch run.Status {
		case openai.RunStatusQueued, openai.RunStatusInProgress:
			randomStatus := randomNextRunStatus(b, run.Status, h.r)
			run.Status = randomStatus

			if run.Status != openai.RunStatusCompleted {
				return
			}
			runMessages := m.threadMessages(run.ThreadID)

			userMessages := make([]openai.Message, 0, len(runMessages))
			for _, ms := range runMessages {
				if ms.Role == openaiAssistantRoleUser {
					userMessages = append(userMessages, ms)
				}
			}
			slices.SortFunc(
				userMessages, func(x, y openai.Message) int {
					return cmp.Compare(y.CreatedAt, x.CreatedAt)
				},
			)
			prompt := userMessages[0].Content[0].Text.Value
			promptReply, ok := m.prompts[prompt]
			if !ok {
				m.t.Logf(
					"no reply found for prompt '%s' (known: %#v)",
					prompt,
					m.prompts,
				)
			}
			msg := m.newAssistantMessage(
				run.ThreadID, promptReply,
			)
			m.messages[msg.ID] = msg
			runSteps := m.newRunStepList(*run, msg)
			m.runSteps[run.ID] = runSteps
		}
	}
	bot.openai.client = h

	users := generateTestUsers(10, h.r)
	if len(users) != 40 {
		b.Fatalf("wrong user count: %d", len(users))
	}

	finishCt := atomic.Int64{}
	chatCommandsSeen := atomic.Int64{}
	b.ResetTimer()

	wg := sync.WaitGroup{}
	limitMsg := bot.RuntimeConfig().DiscordRateLimitMessage

	type interactionResult struct {
		User        discordgo.User
		Interaction *discordgo.InteractionCreate
		Error       error
	}

	interactionErrors := make(chan *interactionResult, len(users))

	for i := 0; i < len(users); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			userInd := rand.IntN(len(users))
			user := users[userInd]
			b.Logf("user at ind %d: %#v", userInd, user)
			iresult := &interactionResult{User: user}
			defer func() {
				interactionErrors <- iresult
			}()
			interactionType, interaction := randomDiscordInteraction(
				b,
				h.r,
				user,
			)
			iresult.Interaction = interaction
			handler := bot.getInteractionHandlerFunc(ctx, interaction)
			go bot.handleInteraction(
				ctx,
				handler,
			)

			cmdCtx, cmdCancel := context.WithTimeout(ctx, 5*time.Minute)
			defer cmdCancel()

			if user.Bot {
				interactionLog := waitForInteractionLog(
					b,
					cmdCtx,
					bot.db,
					interaction.ID,
				)
				if interactionLog == nil {
					iresult.Error = fmt.Errorf(
						"no interaction log found for bot: %#v: %#v",
						user,
						interaction,
					)
				} else {
					b.Logf(
						"interaction log for %#v / %#v: %#v",
						user,
						interaction,
						interactionLog,
					)
				}
				return
			}

			checkCtx, checkCancel := context.WithCancel(cmdCtx)

			doneCh := make(chan struct{}, 1)
			swg := sync.WaitGroup{}

			swg.Add(1)
			go func() {
				defer swg.Done()
				defer checkCancel()
				stubHandler := handler.(stubInteractionHandler)

				for {
					select {
					case <-checkCtx.Done():
						return
					case stubEdit := <-stubHandler.callEdit:
						editContent := *stubEdit.WebhookEdit.Content
						if editContent == limitMsg {
							b.Logf(
								"got rate limit msg: %#v / %#v",
								user,
								interaction,
							)
							return
						}
					}
				}
			}()

			swg.Add(1)
			go func() {
				defer swg.Done()
				defer checkCancel()
				switch interactionType {
				case DiscordSlashCommandChat, DiscordSlashCommandPrivate:
					chatCommandsSeen.Add(1)
					chatCommand := waitForChatCommandFinish(
						b,
						checkCtx,
						bot.db,
						interaction.ID,
					)
					if chatCommand == nil {
						b.Logf("nil chat command for: %#v", interaction)
						var singleChatCommand ChatCommand
						if chatErr := bot.db.Last(
							&singleChatCommand,
							"interaction_id = ?",
							iresult.Interaction.ID,
						).Error; chatErr != nil {
							b.Logf("erm %#v", interaction)
							iresult.Error = fmt.Errorf("nil chatcommand: %w", chatErr)
						} else {
							if singleChatCommand.State.IsFinal() {
								b.Logf(
									"final state for: %#v",
									singleChatCommand,
								)
							} else {
								iresult.Error = fmt.Errorf("nil chatcommand")
							}
						}

					} else {
						b.Logf("got chat command: %#v", chatCommand)
					}
				case DiscordSlashCommandClear:
					clearCmd := waitForClearCommandFinish(
						b,
						checkCtx,
						bot.db,
						interaction.ID,
					)
					if clearCmd == nil {
						b.Logf("nil clear command for: %#v", interaction)
					} else {
						b.Logf("got clear command: %#v", clearCmd)
					}
				default:
					panic("uhhh")
				}
			}()

			finishCt.Add(1)

			go func() {
				swg.Wait()
				doneCh <- struct{}{}
			}()
			select {
			case <-doneCh:
			//
			case <-cmdCtx.Done():
				iresult.Error = fmt.Errorf(
					"command timed out: %#v %#v",
					user,
					interaction,
				)
			}
		}()
	}
	wg.Wait()
	cancel()
	close(interactionErrors)

	var chatCommands []ChatCommand
	rv := bot.db.Find(&chatCommands)
	b.Logf(
		"chat count: %v seen : %d err: %v",
		rv.RowsAffected,
		chatCommandsSeen.Load(),
		rv.Error,
	)
	for _, ac := range chatCommands {
		b.Logf(
			"user=%s interaction=%s state=%s step=%s run_status=%s finished=%v",
			ac.UserID,
			ac.InteractionID,
			ac.State,
			ac.Step,
			ac.RunStatus,
			ac.FinishedAt,
		)
	}

	var clearCommands []ClearCommand
	rv = bot.db.Find(&clearCommands)
	b.Logf("clear count: %v err: %v", rv.RowsAffected, rv.Error)
	for _, ac := range clearCommands {
		b.Logf(
			"user=%s interaction=%s finished=%v",
			ac.UserID,
			ac.InteractionID,
			ac.FinishedAt,
		)
	}

	var usersCreated []User
	rv = bot.db.Find(&usersCreated)
	b.Logf(
		"user count: %v err: %v len: %d",
		rv.RowsAffected,
		rv.Error,
		len(usersCreated),
	)

	for _, bu := range bot.writeDB.UserCache() {
		b.Logf("user %s: %#v", bu.ID, bu)
	}

	b.Logf("chat commands in progreess: %d", bot.chatCommandsInProgress.Load())
	b.Logf("timers in progreess: %d", bot.buttonTimersRunning.Load())
	b.Logf("msg delete in progreess: %d", bot.messageDeleteTimersRunning.Load())
	b.Logf("usage in progreess: %d", bot.usageCommandsInProgress.Load())
	b.Logf("clear in progreess: %d", bot.clearCommandsInProgress.Load())
	b.Logf("now in progreess: %d", bot.happeningNowCommandsInProgress.Load())
	b.Logf(
		"workers in progreess: %d (map count %d)",
		bot.userWorkersRunning.Load(),
		len(bot.userWorkers),
	)

	b.Cleanup(
		func() {
			b.Logf(
				"-chat commands in progreess: %d",
				bot.chatCommandsInProgress.Load(),
			)
			b.Logf("-timers in progreess: %d", bot.buttonTimersRunning.Load())
			b.Logf(
				"-msg delete in progreess: %d",
				bot.messageDeleteTimersRunning.Load(),
			)
			b.Logf(
				"-usage in progreess: %d",
				bot.usageCommandsInProgress.Load(),
			)
			b.Logf(
				"-clear in progreess: %d",
				bot.clearCommandsInProgress.Load(),
			)
			b.Logf(
				"-now in progreess: %d",
				bot.happeningNowCommandsInProgress.Load(),
			)
			b.Logf(
				"-workers in progreess: %d (map size: %d) (%#v)",
				bot.userWorkersRunning.Load(),
				len(bot.userWorkers),
				bot.userWorkers,
			)
		},
	)

	for ir := range interactionErrors {
		if ir.Error != nil {
			interactionData, _ := json.Marshal(ir.Interaction)

			if strings.Contains(ir.Error.Error(), "nil chat") {
				var checkAgain ChatCommand
				if checkErr := bot.db.Last(
					&checkAgain,
					"interaction_id = ?",
					ir.Interaction.ID,
				).Error; checkErr != nil {
					b.Errorf("no chat command found for %#v", ir.Interaction)
				} else {
					b.Logf("chat command found for %#v", checkAgain)
					continue
				}
			} else {
				b.Errorf(
					"error in interaction: \n- %v\n- %#v\n- %#v",
					ir.Error,
					string(interactionData),
					ir,
				)
			}
		} else {
			b.Logf("interaction result: %#v", ir)
		}
	}
}

func randomDiscordInteraction(
	t testing.TB,
	r *rand.Rand,
	u discordgo.User,
) (interactionType string, i *discordgo.InteractionCreate) {
	roll := r.Float64()
	interactionID := fmt.Sprintf("%10d", r.Int32())

	interactionType = DiscordSlashCommandChat
	switch {
	case roll >= 0.88:
		interactionType = DiscordSlashCommandClear
	case roll >= 0.50:
		interactionType = DiscordSlashCommandPrivate
	default:
		interactionType = DiscordSlashCommandChat
	}

	ctxRoll := r.Float64()
	var msgContext discordgo.InteractionContextType
	switch {
	case ctxRoll > 0.75:
		msgContext = discordgo.InteractionContextGuild
	case ctxRoll > 0.50:
		msgContext = discordgo.InteractionContextPrivateChannel
	default:
		msgContext = discordgo.InteractionContextBotDM
	}

	switch interactionType {
	case DiscordSlashCommandChat, DiscordSlashCommandPrivate:

		i = &discordgo.InteractionCreate{
			Interaction: &discordgo.Interaction{
				Type:    discordgo.InteractionApplicationCommand,
				ID:      interactionID,
				User:    &u,
				Context: msgContext,
				Data: discordgo.ApplicationCommandInteractionData{
					CommandType: discordgo.ChatApplicationCommand,
					Name:        interactionType,
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
	default:
		i = &discordgo.InteractionCreate{
			Interaction: &discordgo.Interaction{
				Type:    discordgo.InteractionApplicationCommand,
				ID:      interactionID,
				User:    &u,
				Context: msgContext,
				Data: discordgo.ApplicationCommandInteractionData{
					CommandType: discordgo.ChatApplicationCommand,
					Name:        interactionType,
				},
			},
		}
	}
	return interactionType, i
}

func generateTestUsers(count int, r *rand.Rand) []discordgo.User {
	users := []discordgo.User{}

	seen := map[string]bool{}

	for i := 0; i < count*4; i++ {
		randomInt := r.Int32N(int32(count))

		bot := false

		u := discordgo.User{
			ID:         fmt.Sprintf("u_%d", randomInt),
			Username:   fmt.Sprintf("testuser_%d", randomInt),
			GlobalName: fmt.Sprintf("testuser_%d", randomInt),
		}
		bot, ok := seen[u.ID]
		if !ok {
			botRoll := r.Float64()
			if botRoll < 0.02 {
				bot = true
			}
			seen[u.ID] = bot
		}
		u.Bot = bot

		users = append(
			users, u,
		)
	}
	return users
}

func randomDuration(
	r *rand.Rand,
	minDelay time.Duration,
	maxDelay time.Duration,
) time.Duration {
	delay := minDelay + time.Duration(r.Int64N(int64(maxDelay-minDelay)))
	return delay
}

func randomNextRunStatus(
	t testing.TB,
	status openai.RunStatus,
	r *rand.Rand,
) openai.RunStatus {
	t.Helper()
	roll := r.Float64()

	if status == openai.RunStatusQueued {
		if roll > 0.80 {
			return openai.RunStatusQueued
		}
		return openai.RunStatusInProgress
	}

	switch {
	case roll >= 0.98:
		return openai.RunStatusIncomplete
	case roll >= 0.93:
		return openai.RunStatusFailed
	default:
		return openai.RunStatusCompleted
	}
}

func randomError(t testing.TB, r *rand.Rand) error {
	t.Helper()
	if r.Float64() > 0.95 {
		return fmt.Errorf("random error! %s", t.Name())
	}
	return nil
}

func waitForClearCommandFinish(
	t testing.TB,
	ctx context.Context,
	db *gorm.DB,
	interactionID string,
) *ClearCommand {
	cmdCh := make(chan *ClearCommand, 1)

	go func() {
		for {
			if ctx.Err() != nil {
				cmdCh <- nil
				return
			}
			var clearCmd ClearCommand
			if err := db.Last(
				&clearCmd,
				"interaction_id = ?",
				interactionID,
			).Error; err != nil {
				t.Logf("error: %v", err)
				continue
			}
			if clearCmd.InteractionID == interactionID {
				if clearCmd.FinishedAt != nil || ctx.Err() != nil {
					cmdCh <- &clearCmd
					return
				}
			}
			time.Sleep(500 * time.Millisecond)
		}
	}()
	select {
	case usageCmd := <-cmdCh:
		return usageCmd
	case <-ctx.Done():
		return nil
	}
}

func waitForInteractionLog(
	t testing.TB,
	ctx context.Context,
	db *gorm.DB,
	interactionID string,
) *InteractionLog {
	cmdCh := make(chan *InteractionLog, 1)

	go func() {
		for {
			if ctx.Err() != nil {
				cmdCh <- nil
				return
			}
			var clearCmd InteractionLog
			if err := db.Last(
				&clearCmd,
				"interaction_id = ?",
				interactionID,
			).Error; err != nil {
				t.Logf("error: %v", err)
				continue
			}
			t.Logf("command: %#v", clearCmd)
			if clearCmd.InteractionID == interactionID {
				cmdCh <- &clearCmd
				return
			}
			time.Sleep(500 * time.Millisecond)
		}
	}()
	select {
	case usageCmd := <-cmdCh:
		return usageCmd
	case <-ctx.Done():
		return nil
	}
}

func GenerateRandomIntString(r *mathrand.Rand, length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("invalid length: %d", length)
	}

	// Calculate the maximum possible value with the given length

	intVals := make([]string, 0, length)
	for i := 0; i < length; i++ {
		intVals = append(intVals, "9")
	}
	maxInt, err := strconv.Atoi(strings.Join(intVals, ""))
	if err != nil {
		panic(err)
	}
	// Generate a random number in the range [0, max]

	randomNumber := r.Intn(maxInt)
	// Convert the number to a string with leading zeros
	randomString := fmt.Sprintf("%017d", randomNumber)

	return randomString, nil
}

type mockOpenAIListRunStepsTimeoutServer struct {
	returnAfter        time.Duration
	signalStop         chan struct{}
	t                  testing.TB
	listRunStepsCalled chan struct{}
	*mockOpenAIClientServer
}

func (m *mockOpenAIListRunStepsTimeoutServer) ListRunSteps(
	ctx context.Context,
	threadID string,
	runID string,
	pagination openai.Pagination,
) (response openai.RunStepList, err error) {

	m.t.Logf("waiting: %s", m.returnAfter.String())
	go func() {
		m.listRunStepsCalled <- struct{}{}
	}()
	select {
	case <-m.signalStop:
		m.t.Logf("timed out, got stop signal")
	case <-time.After(m.returnAfter):
		m.t.Logf("elapsed: %s", m.returnAfter.String())
	}
	return m.mockOpenAIClientServer.ListRunSteps(ctx, threadID, runID, pagination)
}

// TestOpenAI_ListRunStepsInBackground validates that, after a ChatCommand
// completes, the "List Run Steps" post-processing is called in the background
// and doesn't block the user from their next request. This test was created
// because the comments indicated that process would be run in a separate
// goroutine, but in practice it actually blocked the worker.
func TestOpenAI_ListRunStepsInBackground(t *testing.T) {
	t.Parallel()
	bot, _ := newDisConcierge(t)
	mockServer := newMockOpenAIAssistantHandler(t)
	timeoutServer := &mockOpenAIListRunStepsTimeoutServer{
		mockOpenAIClientServer: mockServer,
	}
	stopCh := make(chan struct{}, 1)
	runStepsCalled := make(chan struct{}, 1)
	t.Cleanup(
		func() {
			stopCh <- struct{}{}
		},
	)
	timeoutServer.listRunStepsCalled = runStepsCalled
	timeoutServer.signalStop = stopCh
	timeoutServer.returnAfter = 300 * time.Second
	timeoutServer.t = t
	bot.openai.client = timeoutServer

	discordUser := newDiscordUser(t)
	ids := newCommandData(t)

	question := "where is the beef?"
	interaction := newDiscordInteraction(
		t,
		discordUser,
		ids.InteractionID,
		question,
	)

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

	select {
	case <-runStepsCalled:
		t.Logf("run steps called")
	case <-ctx.Done():
		t.Fatalf("timed out waiting for run steps")
	}
	time.Sleep(2 * time.Second)
	var runSteps []OpenAIListRunSteps
	require.NoError(t, bot.db.Find(&runSteps, "chat_command_id = ?", chatCommand.ID).Error)
	require.Len(t, runSteps, 0)
	clearInteractionID := fmt.Sprintf("clear-%s", t.Name())
	clearInteraction := newClearInteraction(t, clearInteractionID, discordUser)

	clearRec := NewUserClearCommand(bot, chatCommand.User, clearInteraction)
	require.NotNil(t, clearRec)

	clearHandler := bot.getInteractionHandlerFunc(ctx, clearInteraction)
	clearRec.handler = clearHandler
	go func() {
		bot.runClearCommand(ctx, clearHandler, clearRec)
	}()

	sendCtx, sendCancel := context.WithTimeout(ctx, UserWorkerSendTimeout*2)
	var clearCmd ClearCommand
	var clearCmdResponse string
	for sendCtx.Err() == nil {
		cr := bot.db.Last(&clearCmd, "interaction_id = ?", clearInteractionID)
		if cr.Error != nil && !errors.Is(cr.Error, gorm.ErrRecordNotFound) {
			t.Fatalf("error: %v", cr.Error)
		}
		if clearCmd.Response != nil {
			clearCmdResponse = *clearCmd.Response
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if sendCtx.Err() != nil {
		t.Fatalf("timed out waiting for clear command")
	} else {
		sendCancel()
	}
	assert.Equal(t, clearCommandResponseForgotten, clearCmdResponse)

}

// TestPollRun_CancelContext tests ChatCommand execution behavior, when the
// overall bot runtime context is cancelled while the OpenAI run is in
// the middle of being polled.
func TestPollRun_CancelContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)

	bot, _ := newDisConciergeWithContext(t, ctx)
	mockClient := newMockOpenAIAssistantHandler(t)
	mockClient.beforeReturnRunFunc = func(m *mockOpenAIClientServer, run *openai.Run) {
		run.Status = openai.RunStatusInProgress
	}
	bot.openai.client = mockClient

	discordUser := newDiscordUser(t)
	ids := newCommandData(t)

	mockClient.threads = map[string]openai.Thread{
		ids.ThreadID: openai.Thread{ID: ids.ThreadID},
	}
	mockClient.runs = map[string]*openai.Run{
		ids.RunID: &openai.Run{ID: ids.RunID},
	}
	user, _, err := bot.GetOrCreateUser(ctx, *discordUser)
	require.NoError(t, err)

	interaction := newDiscordInteraction(t, discordUser, ids.InteractionID, "where is the beef?")

	req, _ := NewChatCommand(user, interaction)
	require.NotNil(t, req)
	req.State = ChatCommandStateInProgress
	req.ThreadID = ids.ThreadID
	req.RunID = ids.RunID
	req.MessageID = ids.MessageID

	require.NoError(t, bot.db.Create(req).Error)

	req.handler = bot.getInteractionHandlerFunc(ctx, interaction)

	select {
	case bot.requestQueue.requestCh <- req:
	//
	case <-time.After(time.Minute):
		t.Fatal("timed out sending to queue")
	}

	cctx, ccancel := context.WithTimeout(ctx, time.Minute)
	t.Cleanup(ccancel)
	req = waitForChatCommandRunStatus(
		t,
		cctx,
		bot.db,
		500*time.Millisecond,
		req,
		openai.RunStatusInProgress,
	)
	require.NotNil(t, req)
	cancel()
	select {
	case <-bot.eventShutdown:
	//
	case <-time.After(5 * time.Minute):
		t.Fatal("timed out waiting for shutdown")
	}
	require.NoError(t, bot.db.Last(req).Error)
	assert.Empty(t, req.Error)
	assert.Equal(t, ChatCommandStateInProgress, req.State)
	assert.Equal(t, openai.RunStatusInProgress, req.RunStatus)

}
