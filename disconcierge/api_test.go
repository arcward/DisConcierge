package disconcierge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bwmarrin/discordgo"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	gsessions "github.com/gorilla/sessions"
	"github.com/sashabaranov/go-openai"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAPILoginRateLimit(t *testing.T) {
	t.Parallel()
	bot, _ := newDisConcierge(t)

	requestLogin := func() int {
		w := httptest.NewRecorder()
		login := userLogin{
			Username: fmt.Sprintf("user_%s", t.Name()),
			Password: fmt.Sprintf("password_%s", t.Name()),
		}
		loginData, err := json.Marshal(login)
		require.NoError(t, err)
		req, err := http.NewRequest(
			http.MethodPost,
			"/login",
			bytes.NewReader(loginData),
		)
		req.Header.Add("Content-Type", "application/json")

		require.NoError(t, err)
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		bot.api.engine.ServeHTTP(w, req)
		resp := w.Result()
		return resp.StatusCode
	}

	assert.Equal(t, http.StatusOK, requestLogin())

	resultCodes := make(chan int, 5)
	wg := sync.WaitGroup{}
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resultCodes <- requestLogin()
		}()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)

	doneCh := make(chan struct{}, 1)
	go func() {
		wg.Wait()
		close(resultCodes)
		doneCh <- struct{}{}
	}()

	select {
	case <-doneCh:
		//
	case <-ctx.Done():
		t.Fatalf("context cancelled: %v", ctx.Err())
	}

	tooManyRequestsSeen := false
	codesSeen := []int{}
	for rc := range resultCodes {
		codesSeen = append(codesSeen, rc)
		if rc == http.StatusTooManyRequests {
			tooManyRequestsSeen = true
			break
		}
	}
	assert.Truef(
		t,
		tooManyRequestsSeen,
		"expected to see %d, saw: %#v",
		http.StatusTooManyRequests,
		codesSeen,
	)
}

func TestAPI_UserUpdate(t *testing.T) {
	t.Parallel()
	bot, _ := newDisConcierge(t)
	handlers := NewAPIHandlers(bot)
	u, _, err := bot.GetOrCreateUser(
		context.Background(),
		discordgo.User{ID: "foo"},
	)
	require.NoError(t, err)

	assert.NotNil(t, u.UserChatCommandLimit6h)

	assert.Equal(t, DefaultRequestLimit6h, u.UserChatCommandLimit6h)
	assert.False(t, u.Ignored)

	newIgnored := true
	new6hLimit := 5
	require.NotEqual(t, DefaultRequestLimit6h, new6hLimit)
	updateData := apiPatchUser{
		Ignored:                &newIgnored,
		UserChatCommandLimit6h: &new6hLimit,
	}

	payload, err := json.Marshal(updateData)
	require.NoError(t, err)

	rv := handleTestRequest(
		t,
		handlers.updateUser,
		http.MethodPatch,
		bytes.NewReader(payload),
		gin.Param{Key: "id", Value: u.ID},
	)

	if !assert.Equal(t, http.StatusAccepted, rv.StatusCode) {
		body := rv.Body
		defer func() {
			_ = body.Close()
		}()
		data, err := io.ReadAll(body)
		require.NoError(t, err)
		t.Fatalf(
			"unexpected status code: %d (data: %s)",
			rv.StatusCode,
			string(data),
		)
	}

	body := rv.Body
	defer func() {
		_ = body.Close()
	}()
	var userData User
	bodyData, err := io.ReadAll(body)
	require.NoError(t, err)
	err = json.Unmarshal(bodyData, &userData)
	require.NoError(t, err)
	assert.True(t, userData.Ignored)
	assert.Equal(t, userData.UserChatCommandLimit6h, new6hLimit)

	userCache := bot.writeDB.UserCache()
	require.NotNil(t, userCache)
	user, ok := userCache[u.ID]
	require.True(t, ok)
	require.Equal(t, user.UserChatCommandLimit6h, new6hLimit)

}

func TestAPI_BadUserUpdate(t *testing.T) {
	t.Parallel()
	bot, _ := newDisConcierge(t)
	handlers := NewAPIHandlers(bot)
	u, _, err := bot.GetOrCreateUser(
		context.Background(),
		discordgo.User{ID: "foo"},
	)
	require.NoError(t, err)

	assert.NotNil(t, u.UserChatCommandLimit6h)
	assert.Equal(t, DefaultRequestLimit6h, u.UserChatCommandLimit6h)
	assert.False(t, u.Ignored)

	newIgnored := true
	new6hLimit := -2

	updateData := apiPatchUser{
		Ignored:                &newIgnored,
		UserChatCommandLimit6h: &new6hLimit,
	}

	payload, err := json.Marshal(updateData)
	require.NoError(t, err)

	rv := handleTestRequest(
		t,
		handlers.updateUser,
		http.MethodPatch,
		bytes.NewReader(payload),
		gin.Param{Key: "id", Value: u.ID},
	)

	assert.Equal(t, http.StatusBadRequest, rv.StatusCode)
}

// TestUsersWithStats tests the /api/users endpoint with the include_stats query
//
//goland:noinspection GoVetCopyLock
func TestAPI_GetUsersWithStats(t *testing.T) {
	bot, _ := newDisConcierge(t)
	handlers := NewAPIHandlers(bot)

	userFoo, _, err := bot.GetOrCreateUser(
		context.Background(),
		discordgo.User{ID: "foo"},
	)
	require.NoError(t, err)
	userFoo.CreatedAt = time.Now().Add(-time.Hour).UnixMilli()
	_, err = bot.writeDB.Save(userFoo)
	require.NoError(t, err)

	chatCmdFoo := &ChatCommand{
		Interaction: Interaction{
			User:          userFoo,
			UserID:        userFoo.ID,
			InteractionID: "ifoo",
		},
		State:                 ChatCommandStateCompleted,
		ThreadID:              "threadFoo",
		RunID:                 "runFoo",
		UsagePromptTokens:     25,
		UsageCompletionTokens: 25,
		UsageTotalTokens:      50,
	}
	_, err = bot.writeDB.Create(chatCmdFoo, "User")
	require.NoError(t, err)

	reportFoo := chatCmdFoo.createReport(UserFeedbackGood, "foo")
	_, err = bot.writeDB.Create(&reportFoo)
	require.NoError(t, err)

	clearCmdFoo := &ClearCommand{
		Interaction: Interaction{
			User:          userFoo,
			UserID:        userFoo.ID,
			InteractionID: "fooClear",
		},
	}
	_, err = bot.writeDB.Create(clearCmdFoo)
	require.NoError(t, err)

	userBar, _, err := bot.GetOrCreateUser(
		context.Background(),
		discordgo.User{ID: "bar"},
	)
	require.NoError(t, err)

	chatCmdBar := &ChatCommand{
		Interaction: Interaction{
			User:          userBar,
			UserID:        userBar.ID,
			InteractionID: "ibar",
		},
		ThreadID:              "threadBar",
		RunID:                 "runBar",
		State:                 ChatCommandStateFailed,
		UsagePromptTokens:     100,
		UsageCompletionTokens: 100,
		UsageTotalTokens:      200,
	}
	chatCmdBar.CreatedAt = time.Now().Add(-(8 * time.Hour)).UnixMilli()
	_, err = bot.writeDB.Create(chatCmdBar, "User")
	require.NoError(t, err)

	reportBarOutdated := chatCmdBar.createReport(UserFeedbackOutdated, "bar")
	_, err = bot.writeDB.Create(&reportBarOutdated)
	require.NoError(t, err)

	reportBarHallucinated := chatCmdBar.createReport(UserFeedbackHallucinated, "bar")
	_, err = bot.writeDB.Create(&reportBarHallucinated)
	require.NoError(t, err)

	chatCmdBar2 := &ChatCommand{
		Interaction: Interaction{
			User:          userBar,
			UserID:        userBar.ID,
			InteractionID: "ibar2",
		},
		ThreadID:              chatCmdBar.ThreadID,
		Private:               true,
		RunID:                 "runBar2",
		State:                 ChatCommandStateCompleted,
		UsagePromptTokens:     100,
		UsageCompletionTokens: 100,
		UsageTotalTokens:      200,
	}
	chatCmdBar2.CreatedAt = time.Now().Add(-(3 * time.Hour)).UnixMilli()
	_, err = bot.writeDB.Create(chatCmdBar2, "User")
	require.NoError(t, err)

	var withStats []userWithStats

	req, err := http.NewRequest(
		http.MethodGet,
		fmt.Sprintf("%s%s", apiPrefix, apiPathUsers),
		http.NoBody,
	)
	require.NoError(t, err)
	q := req.URL.Query()
	q.Add("include_stats", "true")
	req.URL.RawQuery = q.Encode()

	rv := handleTestHTTPRequest(
		t,
		handlers.getUsers,
		req,
	)

	assert.Equal(t, http.StatusOK, rv.StatusCode)

	body := rv.Body
	defer func() {
		_ = body.Close()
	}()

	bodyData, err := io.ReadAll(body)
	require.NoError(t, err)
	t.Logf("data: %s", string(bodyData))
	err = json.Unmarshal(bodyData, &withStats)
	require.NoError(t, err)

	assert.Equal(t, 2, len(withStats))

	var foo userWithStats
	var bar userWithStats
	if withStats[0].ID == userFoo.ID {
		foo = withStats[0]
		bar = withStats[1]
	} else {
		foo = withStats[1]
		bar = withStats[0]

	}

	require.NotNil(t, foo.UserStats)
	require.NotNil(t, bar.UserStats)

	assert.Equal(t, foo.ID, userFoo.ID)
	assert.Equal(t, bar.ID, userBar.ID)

	assert.Equal(t, 1, foo.UserStats.ClearCommands)
	assert.Equalf(
		t,
		1,
		foo.UserStats.Reports[feedbackTypeDescription[UserFeedbackGood]],
		fmt.Sprintf("reports: %#v", foo.UserStats.Reports),
	)

	fooCmdStats := foo.UserStats.ChatCommandUsage

	assert.Equal(t, 1, fooCmdStats.Attempted6h)
	assert.Equal(t, 1, fooCmdStats.Billable6h)
	assert.Equal(t, 1, fooCmdStats.Threads6h)
	assert.Equal(t, 25, fooCmdStats.PromptTokens6h)
	assert.Equal(t, 25, fooCmdStats.CompletionTokens6h)
	assert.Equal(t, 50, fooCmdStats.TotalTokens6h)
	assert.Equal(
		t,
		1,
		fooCmdStats.State6h[ChatCommandStateCompleted],
	)
	assert.Equal(t, 0, fooCmdStats.Private6h)

	assert.Equal(t, bar.UserStats.ClearCommands, 0)
	assert.Equal(
		t,
		bar.UserStats.Reports[feedbackTypeDescription[UserFeedbackHallucinated]],
		1,
	)
	assert.Equal(
		t,
		bar.UserStats.Reports[feedbackTypeDescription[UserFeedbackOutdated]],
		1,
	)

	barCmdStats := bar.UserStats.ChatCommandUsage
	assert.Equal(t, 1, barCmdStats.Billable6h)
	assert.Equal(t, 1, barCmdStats.Threads6h)
	assert.Equal(t, 100, barCmdStats.PromptTokens6h)
	assert.Equal(t, 100, barCmdStats.CompletionTokens6h)
	assert.Equal(t, 200, barCmdStats.TotalTokens6h)
	assert.Equal(
		t,
		1,
		barCmdStats.State6h[ChatCommandStateCompleted],
	)
	assert.Equal(
		t,
		0,
		barCmdStats.State6h[ChatCommandStateFailed],
	)
	assert.Equal(t, 1, barCmdStats.Private6h)
}

func TestAPI_LoggedIn(t *testing.T) {
	t.Parallel()
	bot, _ := newDisConcierge(t)
	bot.config.API.Development = false
	requestLogin := func() *http.Response {
		w := httptest.NewRecorder()
		login := userLogin{
			Username: bot.RuntimeConfig().AdminUsername,
			Password: fmt.Sprintf("password_%s", t.Name()),
		}
		loginData, err := json.Marshal(login)
		require.NoError(t, err)
		req, err := http.NewRequest(
			http.MethodPost,
			"/login",
			bytes.NewReader(loginData),
		)
		req.Header.Add("Content-Type", "application/json")

		require.NoError(t, err)
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		bot.api.engine.ServeHTTP(w, req)
		return w.Result()
	}
	rv := requestLogin()
	assert.Equal(t, http.StatusOK, rv.StatusCode)
	cookies := rv.Cookies()
	assert.Equal(t, 1, len(cookies))
	cookie := cookies[0]

	t.Logf("cookie: %#v", cookie.String())
	assert.True(t, cookie.HttpOnly)
	assert.Equal(t, http.SameSiteStrictMode, cookie.SameSite)
	assert.Equal(t, int(bot.config.API.SessionMaxAge.Seconds()), cookie.MaxAge)

	loggedIn := func() *http.Response {
		w := httptest.NewRecorder()
		req, err := http.NewRequest(
			http.MethodGet,
			fmt.Sprintf("%s%s", apiPrefix, apiPathLoggedIn),
			http.NoBody,
		)
		require.NoError(t, err)
		req.AddCookie(cookie)
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		bot.api.engine.ServeHTTP(w, req)
		resp := w.Result()
		return resp
	}
	loggedInResp := loggedIn()
	assert.Equal(t, http.StatusOK, loggedInResp.StatusCode)

	data, err := io.ReadAll(loggedInResp.Body)
	require.NoError(t, err)
	t.Cleanup(
		func() {
			e := loggedInResp.Body.Close()
			if e != nil {
				t.Logf("error closing body: %s", e.Error())
			}
		},
	)

	var crv loggedInResponse
	err = json.Unmarshal(data, &crv)
	require.NoError(t, err)
	assert.Equal(t, fmt.Sprintf("user_%s", t.Name()), crv.Username)
}

func TestAPI_NotLoggedIn(t *testing.T) {
	bot, _ := newDisConcierge(t)

	requestLogin := func() int {
		w := httptest.NewRecorder()
		login := userLogin{
			Username: fmt.Sprintf("user_%s", t.Name()),
			Password: fmt.Sprintf("wrong_password_%s", t.Name()),
		}
		loginData, err := json.Marshal(login)
		require.NoError(t, err)
		req, err := http.NewRequest(
			http.MethodPost,
			"/login",
			bytes.NewReader(loginData),
		)
		req.Header.Add("Content-Type", "application/json")

		require.NoError(t, err)
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		bot.api.engine.ServeHTTP(w, req)
		resp := w.Result()
		return resp.StatusCode
	}

	assert.Equal(t, http.StatusUnauthorized, requestLogin())
}

func TestAPI_RegisterCommands(t *testing.T) {
	bot, _ := newDisConcierge(t)
	handlers := NewAPIHandlers(bot)
	cmdMock := registerCommandSessionMock{
		mockDiscordSession: bot.discord.session.(mockDiscordSession),
		CommandResponse:    make(chan []*discordgo.ApplicationCommand, 1),
		CommandError:       make(chan error, 1),
	}
	bot.discord.session = cmdMock

	rv := handleTestRequest(
		t,
		handlers.discordRegisterCommands,
		http.MethodPost,
		http.NoBody,
	)

	assert.Equal(t, http.StatusCreated, rv.StatusCode)

	body := rv.Body
	defer func() {
		_ = body.Close()
	}()
	var createdCommands []*discordgo.ApplicationCommand
	bodyData, err := io.ReadAll(body)
	require.NoError(t, err)
	err = json.Unmarshal(bodyData, &createdCommands)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	select {
	case <-ctx.Done():
		t.Fatal("timed out")
	case e := <-cmdMock.CommandError:
		if e != nil {
			t.Fatalf("expected no erroor, got; %s", e.Error())
		}
	}

	select {
	case <-ctx.Done():
		t.Fatal("timed out")
	case cmds := <-cmdMock.CommandResponse:
		assert.NotNil(t, cmds)
		assert.Equal(t, len(cmds), len(createdCommands))
	}
}

func TestAPI_GetUserHistory(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	bot, _ := newDisConcierge(t)
	handlers := NewAPIHandlers(bot)

	u := newDiscordUser(t)
	i := newDiscordInteraction(t, u, "", t.Name())

	go bot.handleInteraction(
		ctx,
		bot.getInteractionHandlerFunc(ctx, i),
	)

	chatCommand := waitForChatCommandCreation(t, ctx, bot.db, i.ID)
	state := waitOnChatCommandFinalState(
		t,
		ctx,
		bot.db,
		500*time.Millisecond,
		chatCommand.ID,
	)

	assert.NotNil(t, state)
	if !assert.Equal(t, ChatCommandStateCompleted, *state) {
		require.NoError(
			t,
			bot.hydrateChatCommand(ctx, chatCommand),
		)
		t.Fatalf(
			"chat command did not complete (state=%s): %#v",
			state,
			chatCommand,
		)
	}

	require.NoError(t, bot.hydrateChatCommand(ctx, chatCommand))

	rv := handleTestRequest(
		t,
		handlers.getUserHistory,
		http.MethodGet,
		http.NoBody,
		gin.Param{Key: "id", Value: u.ID},
	)

	assert.Equal(t, http.StatusOK, rv.StatusCode)

	body := rv.Body
	defer func() {
		_ = body.Close()
	}()
	var history []userHistoryItem
	bodyData, err := io.ReadAll(body)
	require.NoError(t, err)
	err = json.Unmarshal(bodyData, &history)
	if err != nil {
		t.Fatalf("error: %s for data: %s", err.Error(), string(bodyData))
	}

	assert.Equal(t, 1, len(history))
	h := history[0]
	assert.Equal(t, chatCommand.State, h.State)
	assert.Equal(t, chatCommand.Step, h.Step)
	assert.Equal(t, chatCommand.UserID, h.UserID)
	assert.Equal(t, chatCommand.RunStatus, h.RunStatus)
	assert.Equal(t, u.Username, h.Username)
	assert.Equal(t, u.GlobalName, h.GlobalName)
	assert.Equal(t, chatCommand.Prompt, h.Prompt)
	assert.Equal(t, chatCommand.ID, h.ChatCommandID)
	assert.Equal(t, chatCommand.ThreadID, h.ThreadID)
	assert.Equal(t, chatCommand.RunID, h.RunID)
	assert.Equal(t, chatCommand.InteractionID, h.InteractionID)

	assert.Equal(t, time.UnixMilli(chatCommand.CreatedAt).UTC(), h.CreatedAt)
	assert.Equal(t, string(chatCommand.Error), h.Error)
	assert.Equal(t, chatCommand.Private, h.Private)

	assert.NotNil(t, chatCommand.User)
	assert.NotEmpty(t, chatCommand.ThreadID)
	assert.NotEmpty(t, chatCommand.User.ThreadID)

	clearResp := handleTestRequest(
		t,
		handlers.clearThreads,
		http.MethodPost,
		http.NoBody,
	)

	assert.NotNil(t, clearResp)
	assert.Equal(t, http.StatusOK, clearResp.StatusCode)
	time.Sleep(2 * time.Second)
	reloadedUser := bot.writeDB.GetUser(chatCommand.UserID)
	assert.NotNil(t, reloadedUser)
	assert.Equal(t, reloadedUser.ID, chatCommand.User.ID)
	assert.Empty(t, reloadedUser.ThreadID)
	assert.NotEmpty(t, chatCommand.ThreadID)
}

func TestAPI_GetConfig(t *testing.T) {
	bot, _ := newDisConcierge(t)

	requestConfig := func() *http.Response {
		w := httptest.NewRecorder()

		req, err := http.NewRequest(
			http.MethodGet,
			fmt.Sprintf("%s%s", apiPrefix, apiPathConfig),
			http.NoBody,
		)
		require.NoError(t, err)
		req.Header.Add("Content-Type", "application/json")

		c, _ := gin.CreateTestContext(w)
		c.Request = req

		sess, err := bot.api.store.New(req, sessionVarName)
		require.NoError(t, err)
		sess.Options = &gsessions.Options{
			MaxAge:   60 * 60,
			SameSite: http.SameSiteStrictMode,
			HttpOnly: true,
		}
		require.NoError(t, err)
		sess.Values[sessionVarField] = bot.RuntimeConfig().AdminUsername
		mockStore := &MockStore{}
		bot.api.store = mockStore
		mockStore.returnSession = sess
		bot.api.engine.ServeHTTP(w, req)
		return w.Result()
	}

	resp := requestConfig()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var botState RuntimeConfig

	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	t.Cleanup(
		func() {
			e := resp.Body.Close()
			if e != nil {
				t.Logf("error closing body: %s", e.Error())
			}
		},
	)

	err = json.Unmarshal(data, &botState)
	require.NoError(t, err)

	existingState := bot.RuntimeConfig()

	existingStateData, err := json.Marshal(existingState)
	require.NoError(t, err)
	assert.Equal(t, string(data), string(existingStateData))
}

func TestAPI_UpdateConfig(t *testing.T) {
	bot, _ := newDisConcierge(t)
	handlers := NewAPIHandlers(bot)

	currentState := bot.RuntimeConfig()

	t.Logf("bot config: %#v", currentState)

	// Original values
	assert.False(t, currentState.Paused)
	assert.Equal(t, bot.config.LogLevel.Level(), currentState.LogLevel.Level())
	assert.Equal(
		t,
		bot.config.OpenAI.LogLevel.Level(),
		currentState.OpenAILogLevel.Level(),
	)
	assert.Equal(
		t,
		bot.config.Discord.LogLevel.Level(),
		currentState.DiscordLogLevel.Level(),
	)
	assert.Equal(
		t,
		bot.config.Discord.DiscordGoLogLevel.Level(),
		currentState.DiscordGoLogLevel.Level(),
	)
	assert.Equal(
		t,
		bot.config.DatabaseLogLevel.Level(),
		currentState.DatabaseLogLevel.Level(),
	)
	assert.Equal(
		t,
		bot.config.Discord.WebhookServer.LogLevel.Level(),
		currentState.DiscordWebhookLogLevel.Level(),
	)
	assert.Equal(
		t,
		bot.config.API.LogLevel.Level(),
		currentState.APILogLevel.Level(),
	)

	assert.Equal(t, DefaultRequestLimit6h, currentState.UserChatCommandLimit6h)

	u := newDiscordUser(t)
	uctx, ucancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(ucancel)
	user, _, err := bot.GetOrCreateUser(uctx, *u)
	require.NoError(t, err)

	assert.Equal(t, DefaultRequestLimit6h, user.UserChatCommandLimit6h)

	// Create RuntimeConfigUpdate with all fields changed
	paused := false
	discordCustomStatus := "New Status"
	feedbackEnabled := false
	feedbackModalInputLabel := "New Feedback Label"
	feedbackModalPlaceholder := "New Placeholder"
	feedbackModalMinLength := 10
	feedbackModalMaxLength := 1000
	feedbackModalTitle := "New Title"
	chatCommandDescription := "New Chat Description"
	chatCommandOptionDescription := "New Chat Option Description"
	chatCommandMaxLength := 1000
	privateCommandDescription := "New Private Description"

	openAITruncationStrategyType := openai.TruncationStrategyLastMessages
	openAITruncationStrategyLastMessages := 5
	openAIMaxRequestsPerSecond := 2
	openAIMaxPromptTokens := 4096
	openAIMaxCompletionTokens := 2048
	assistantPollInterval := Duration{10 * time.Second}
	assistantMaxPollInterval := Duration{50 * time.Second}
	assistantInstructions := "New Instructions"
	assistantTemperature := float32(0.8)
	logLevel := DBLogLevel(slog.LevelDebug.String())
	openAILogLevel := DBLogLevel(slog.LevelDebug.String())
	discordLogLevel := DBLogLevel(slog.LevelDebug.String())
	discordGoLogLevel := DBLogLevel(slog.LevelDebug.String())
	databaseLogLevel := DBLogLevel(slog.LevelDebug.String())
	discordWebhookLogLevel := DBLogLevel(slog.LevelDebug.String())
	apiLogLevel := DBLogLevel(slog.LevelDebug.String())

	requestLimit6h := bot.RuntimeConfig().UserChatCommandLimit6h * 2

	updateData := RuntimeConfigUpdate{

		Paused:                               &paused,
		DiscordCustomStatus:                  &discordCustomStatus,
		FeedbackEnabled:                      &feedbackEnabled,
		FeedbackModalInputLabel:              &feedbackModalInputLabel,
		FeedbackModalPlaceholder:             &feedbackModalPlaceholder,
		FeedbackModalMinLength:               &feedbackModalMinLength,
		FeedbackModalMaxLength:               &feedbackModalMaxLength,
		FeedbackModalTitle:                   &feedbackModalTitle,
		ChatCommandDescription:               &chatCommandDescription,
		ChatCommandOptionDescription:         &chatCommandOptionDescription,
		ChatCommandMaxLength:                 &chatCommandMaxLength,
		PrivateCommandDescription:            &privateCommandDescription,
		OpenAITruncationStrategyType:         &openAITruncationStrategyType,
		OpenAITruncationStrategyLastMessages: &openAITruncationStrategyLastMessages,
		OpenAIMaxRequestsPerSecond:           &openAIMaxRequestsPerSecond,
		OpenAIMaxPromptTokens:                &openAIMaxPromptTokens,
		OpenAIMaxCompletionTokens:            &openAIMaxCompletionTokens,
		AssistantPollInterval:                &assistantPollInterval,
		AssistantMaxPollInterval:             &assistantMaxPollInterval,
		AssistantInstructions:                &assistantInstructions,
		AssistantTemperature:                 &assistantTemperature,
		LogLevel:                             &logLevel,
		OpenAILogLevel:                       &openAILogLevel,
		DiscordLogLevel:                      &discordLogLevel,
		DiscordGoLogLevel:                    &discordGoLogLevel,
		DatabaseLogLevel:                     &databaseLogLevel,
		DiscordWebhookLogLevel:               &discordWebhookLogLevel,
		APILogLevel:                          &apiLogLevel,
		UserChatCommandLimit6h:               &requestLimit6h,
	}

	data, err := json.Marshal(updateData)
	require.NoError(t, err)

	t.Logf("sending test request")
	resp := handleTestRequest(
		t,
		handlers.updateRuntimeConfig,
		http.MethodPatch,
		bytes.NewReader(data),
	)
	t.Logf("got response")

	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusAccepted,
			resp.StatusCode,
		)
	}

	var resultState RuntimeConfig

	data, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	t.Cleanup(
		func() {
			e := resp.Body.Close()
			if e != nil {
				t.Logf("error closing body: %s", e.Error())
			}
		},
	)

	err = json.Unmarshal(data, &resultState)
	require.NoError(t, err)

	// Assert that the new values were updated on the struct returned by bot.RuntimeConfig()
	updatedState := bot.RuntimeConfig()
	assert.Equal(t, paused, updatedState.Paused)
	assert.Equal(t, discordCustomStatus, updatedState.DiscordCustomStatus)
	assert.Equal(t, feedbackEnabled, updatedState.FeedbackEnabled)
	assert.Equal(
		t,
		feedbackModalInputLabel,
		updatedState.FeedbackModalInputLabel,
	)
	assert.Equal(
		t,
		feedbackModalPlaceholder,
		updatedState.FeedbackModalPlaceholder,
	)
	assert.Equal(t, feedbackModalMinLength, updatedState.FeedbackModalMinLength)
	assert.Equal(t, feedbackModalMaxLength, updatedState.FeedbackModalMaxLength)
	assert.Equal(t, feedbackModalTitle, updatedState.FeedbackModalTitle)
	assert.Equal(t, chatCommandDescription, updatedState.ChatCommandDescription)
	assert.Equal(
		t,
		chatCommandOptionDescription,
		updatedState.ChatCommandOptionDescription,
	)

	assert.Equal(t, chatCommandMaxLength, updatedState.ChatCommandMaxLength)
	assert.Equal(
		t,
		privateCommandDescription,
		updatedState.PrivateCommandDescription,
	)

	assert.Equal(
		t,
		openAITruncationStrategyType,
		updatedState.OpenAITruncationStrategyType,
	)
	assert.Equal(
		t,
		openAITruncationStrategyLastMessages,
		updatedState.OpenAITruncationStrategyLastMessages,
	)
	assert.Equal(
		t,
		openAIMaxRequestsPerSecond,
		updatedState.OpenAIMaxRequestsPerSecond,
	)
	assert.Equal(t, openAIMaxPromptTokens, updatedState.OpenAIMaxPromptTokens)
	assert.Equal(
		t,
		openAIMaxCompletionTokens,
		updatedState.OpenAIMaxCompletionTokens,
	)
	assert.Equal(
		t,
		assistantPollInterval,
		updatedState.AssistantPollInterval,
	)
	assert.Equal(t, assistantInstructions, updatedState.AssistantInstructions)
	assert.Equal(t, assistantTemperature, updatedState.AssistantTemperature)
	assert.Equal(t, logLevel, updatedState.LogLevel)
	assert.Equal(t, openAILogLevel, updatedState.OpenAILogLevel)
	assert.Equal(t, discordLogLevel, updatedState.DiscordLogLevel)
	assert.Equal(t, discordGoLogLevel, updatedState.DiscordGoLogLevel)
	assert.Equal(t, databaseLogLevel, updatedState.DatabaseLogLevel)
	assert.Equal(t, discordWebhookLogLevel, updatedState.DiscordWebhookLogLevel)
	assert.Equal(t, apiLogLevel, updatedState.APILogLevel)

	// Assert that the associated config values were updated
	assert.Equal(t, paused, bot.paused.Load())
	assert.Equal(t, logLevel.Level(), bot.config.LogLevel.Level())
	assert.Equal(t, openAILogLevel.Level(), bot.config.OpenAI.LogLevel.Level())
	assert.Equal(
		t,
		discordLogLevel.Level(),
		bot.config.Discord.LogLevel.Level(),
	)
	assert.Equal(t, apiLogLevel.Level(), bot.config.API.LogLevel.Level())
	assert.Equal(
		t,
		discordWebhookLogLevel.Level(),
		bot.config.Discord.WebhookServer.LogLevel.Level(),
	)
	assert.Equal(
		t,
		discordGoLogLevel.Level(),
		bot.config.Discord.DiscordGoLogLevel.Level(),
	)
	assert.Equal(
		t,
		databaseLogLevel.Level(),
		bot.config.DatabaseLogLevel.Level(),
	)
	assert.Equal(
		t,
		rate.Limit(openAIMaxRequestsPerSecond),
		bot.openai.requestLimiter.Limit(),
	)

	assert.Equal(
		t,
		requestLimit6h,
		updatedState.UserChatCommandLimit6h,
	)

	err = bot.db.Last(user).Error
	require.NoError(t, err)

	assert.Equal(
		t,
		requestLimit6h,
		user.UserChatCommandLimit6h,
	)
}

func TestAPI_UpdateConfigBadPayload(t *testing.T) {
	bot, _ := newDisConcierge(t)
	handlers := NewAPIHandlers(bot)

	maxQuestionLength := -1
	updateData := RuntimeConfigUpdate{
		ChatCommandMaxLength: &maxQuestionLength,
	}

	data, err := json.Marshal(updateData)
	require.NoError(t, err)

	resp := handleTestRequest(
		t,
		handlers.updateRuntimeConfig,
		http.MethodPatch,
		bytes.NewReader(data),
	)

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	data, _ = io.ReadAll(resp.Body)
	defer func() {
		_ = resp.Body.Close()
	}()
	t.Logf("response data: %s", string(data))
}

// TestAPI_UpdateConfig_FailValidationInTransaction validates the config
// rollback behavior, when `RuntimeConfig` fails struct validation inside
// a DB transaction, when `RuntimeConfigUpdate` did not.
// `RuntimeConfig` checks that the feedback modal min length is smaller
// than the max length, but the update struct does not.
func TestAPI_UpdateConfig_FailValidationInTransaction(t *testing.T) {
	bot, _ := newDisConcierge(t)
	handlers := NewAPIHandlers(bot)

	originalMinLength := bot.runtimeConfig.FeedbackModalMinLength
	originalMaxLength := bot.runtimeConfig.FeedbackModalMaxLength
	minFeedbackLength := 1000
	maxFeedbackLength := 750
	require.NotEqual(t, minFeedbackLength, originalMinLength)
	require.NotEqual(t, maxFeedbackLength, originalMaxLength)
	updateData := RuntimeConfigUpdate{
		FeedbackModalMinLength: &minFeedbackLength,
		FeedbackModalMaxLength: &maxFeedbackLength,
	}

	data, err := json.Marshal(updateData)
	require.NoError(t, err)

	resp := handleTestRequest(
		t,
		handlers.updateRuntimeConfig,
		http.MethodPatch,
		bytes.NewReader(data),
	)

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	data, _ = io.ReadAll(resp.Body)
	defer func() {
		_ = resp.Body.Close()
	}()
	t.Logf("response data: %s", string(data))
	assert.Equal(t, originalMinLength, bot.runtimeConfig.FeedbackModalMinLength)
	assert.Equal(t, originalMaxLength, bot.runtimeConfig.FeedbackModalMaxLength)

	var latestConfig RuntimeConfig
	require.NoError(t, bot.db.Last(&latestConfig).Error)
	assert.Equal(t, originalMinLength, latestConfig.FeedbackModalMinLength)
	assert.Equal(t, originalMaxLength, latestConfig.FeedbackModalMaxLength)
}

func TestBotStateUpdateValidation(t *testing.T) {
	tests := []struct {
		name    string
		update  RuntimeConfigUpdate
		wantErr bool
	}{
		{
			name:    "Valid empty update",
			update:  RuntimeConfigUpdate{},
			wantErr: false,
		},
		{
			name: "Valid update with all fields",
			update: RuntimeConfigUpdate{
				Paused:                               boolPtr(true),
				DiscordCustomStatus:                  strPtr("Test Status"),
				FeedbackEnabled:                      boolPtr(true),
				FeedbackModalInputLabel:              strPtr("Test Label"),
				FeedbackModalPlaceholder:             strPtr("Test Placeholder"),
				FeedbackModalMinLength:               intPtr(10),
				FeedbackModalMaxLength:               intPtr(1000),
				FeedbackModalTitle:                   strPtr("Test Title"),
				ChatCommandDescription:               strPtr("Test Description"),
				ChatCommandOptionDescription:         strPtr("Test Option Description"),
				ChatCommandMaxLength:                 intPtr(2000),
				PrivateCommandDescription:            strPtr("Test Private Description"),
				OpenAITruncationStrategyType:         truncationStrategyPtr(openai.TruncationStrategyAuto),
				OpenAITruncationStrategyLastMessages: intPtr(10),
				OpenAIMaxRequestsPerSecond:           intPtr(5),
				OpenAIMaxPromptTokens:                intPtr(1000),
				OpenAIMaxCompletionTokens:            intPtr(1000),
				AssistantPollInterval:                durationPtr(pollInterval(1.5)),
				AssistantMaxPollInterval:             durationPtr(10 * time.Second),
				AssistantInstructions:                strPtr("Test Instructions"),
				AssistantTemperature:                 float32Ptr(0.7),
				LogLevel:                             dbLogLevelPtr(DBLogLevelInfo),
				OpenAILogLevel:                       dbLogLevelPtr(DBLogLevelWarn),
				DiscordLogLevel:                      dbLogLevelPtr(DBLogLevelError),
				DiscordGoLogLevel:                    dbLogLevelPtr(DBLogLevelDebug),
				DatabaseLogLevel:                     dbLogLevelPtr(DBLogLevelInfo),
				DiscordWebhookLogLevel:               dbLogLevelPtr(DBLogLevelWarn),
				APILogLevel:                          dbLogLevelPtr(DBLogLevelError),
			},
			wantErr: false,
		},
		{
			name: "Invalid FeedbackModalInputLabel length",
			update: RuntimeConfigUpdate{
				FeedbackModalInputLabel: strPtr(strings.Repeat("a", 46)),
			},
			wantErr: true,
		},
		{
			name: "Invalid FeedbackModalPlaceholder length",
			update: RuntimeConfigUpdate{
				FeedbackModalPlaceholder: strPtr(strings.Repeat("a", 101)),
			},
			wantErr: true,
		},
		{
			name: "Invalid FeedbackModalMinLength",
			update: RuntimeConfigUpdate{
				FeedbackModalMinLength: intPtr(-1),
			},
			wantErr: true,
		},
		{
			name: "Invalid FeedbackModalMaxLength",
			update: RuntimeConfigUpdate{
				FeedbackModalMaxLength: intPtr(5000),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				err := tt.update.validate()
				if tt.wantErr {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err)
				}
			},
		)
	}
}

func getButtonComponent(
	t testing.TB,
	components []discordgo.MessageComponent,
	feedbackType FeedbackButtonType,
) *discordgo.Button {
	t.Helper()
	for _, c := range components {
		row, ok := c.(discordgo.ActionsRow)
		require.Truef(t, ok, "expected actions row, got: %#v", c)
		for _, b := range row.Components {
			button, ok := b.(discordgo.Button)
			if !ok {
				t.Fatal("expected button")
			}
			if strings.HasPrefix(
				button.CustomID,
				fmt.Sprintf("%s:", string(feedbackType)),
			) {
				return &button
			}
		}
	}
	return nil

}

func handleTestRequest(
	t testing.TB,
	handler gin.HandlerFunc,
	method string,
	body io.Reader,
	params ...gin.Param,
) *http.Response {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	doneCh := make(chan struct{}, 1)

	req, err := http.NewRequest(method, "/", body)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	if len(params) > 0 {
		c.Params = params
	}
	go func() {
		t.Logf("calling handler! %s", t.Name())
		handler(c)
		doneCh <- struct{}{}
	}()
	select {
	case <-doneCh:
		t.Logf("handler finished!")
	case <-ctx.Done():
		t.Fatalf("%s timed out", t.Name())
	}
	return w.Result()
}

func handleTestHTTPRequest(
	t testing.TB,
	handler gin.HandlerFunc,
	req *http.Request,
	params ...gin.Param,
) *http.Response {
	t.Helper()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	if len(params) > 0 {
		c.Params = params
	}
	handler(c)
	return w.Result()

}

type MockStore struct {
	sessions.Store
	mock.Mock
	returnSession *gsessions.Session
}

func (m *MockStore) Get(_ *http.Request, _ string) (
	*gsessions.Session,
	error,
) {
	return m.returnSession, nil
}

type MockGStore struct {
	gsessions.Store
	mock.Mock
}

func (m *MockGStore) Options(_ sessions.Options) {
	//
}

func (m *MockGStore) Get(r *http.Request, name string) (
	*gsessions.Session,
	error,
) {
	args := m.Called(r, name)
	sa := args.Get(0)
	if sa != nil {
		return sa.(*gsessions.Session), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockGStore) New(r *http.Request, name string) (
	*gsessions.Session,
	error,
) {
	args := m.Called(r, name)
	return args.Get(0).(*gsessions.Session), args.Error(1)
}

func (m *MockGStore) Save(
	r *http.Request,
	w http.ResponseWriter,
	s *gsessions.Session,
) error {
	args := m.Called(r, w, s)
	return args.Error(0)
}

type registerCommandSessionMock struct {
	mockDiscordSession
	CommandResponse chan []*discordgo.ApplicationCommand
	CommandError    chan error
}

func (r registerCommandSessionMock) ApplicationCommandBulkOverwrite(
	appID string,
	guildID string,
	commands []*discordgo.ApplicationCommand,
	options ...discordgo.RequestOption,
) ([]*discordgo.ApplicationCommand, error) {
	rv, err := r.mockDiscordSession.ApplicationCommandBulkOverwrite(
		appID,
		guildID,
		commands,
		options...,
	)
	go func() {
		r.CommandError <- err
	}()
	go func() {
		r.CommandResponse <- rv
	}()

	return rv, err
}

func TestGinContextLogger_ExistingLogger(t *testing.T) {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	c.Set("logger", logger)

	result := ginContextLogger(c)

	assert.Equal(t, logger, result)
}

func TestGetSessionUsername(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		setupMock      func(*MockGStore)
		expectedResult string
		expectedError  error
	}{
		{
			name: "Valid session with username",
			setupMock: func(m *MockGStore) {
				session := gsessions.NewSession(m, sessionVarName)
				session.Values[sessionVarField] = "testuser"
				m.On("Get", mock.Anything, sessionVarName).Return(session, nil)
			},
			expectedResult: "testuser",
			expectedError:  nil,
		},
		{
			name: "Session without username",
			setupMock: func(m *MockGStore) {
				session := gsessions.NewSession(m, sessionVarName)
				m.On("Get", mock.Anything, sessionVarName).Return(session, nil)
			},
			expectedResult: "",
			expectedError:  errors.New("username not found in session"),
		},
		{
			name: "Session with non-string username",
			setupMock: func(m *MockGStore) {
				session := gsessions.NewSession(m, sessionVarName)
				session.Values[sessionVarField] = 123 // Non-string value
				m.On("Get", mock.Anything, sessionVarName).Return(session, nil)
			},
			expectedResult: "",
			expectedError:  errors.New("username not a string"),
		},
		{
			name: "Error getting session",
			setupMock: func(m *MockGStore) {
				m.On(
					"Get",
					mock.Anything,
					sessionVarName,
				).Return(sessions.Session(nil), errors.New("session error"))
			},
			expectedResult: "",
			expectedError:  errors.New("session error"),
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				mockStore := &MockGStore{}
				tt.setupMock(mockStore)

				api := &API{
					store: mockStore,
				}

				w := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(w)
				c.Request, _ = http.NewRequest("GET", "/", nil)

				result, err := api.getSessionUsername(c)

				assert.Equal(t, tt.expectedResult, result)
				if tt.expectedError != nil {
					assert.EqualError(t, err, tt.expectedError.Error())
				} else {
					assert.NoError(t, err)
				}

				mockStore.AssertExpectations(t)
			},
		)
	}
}

func TestAPI_AdminSetup_Forbidden(t *testing.T) {
	bot, _ := newDisConcierge(t)
	handlers := NewAPIHandlers(bot)
	require.False(t, bot.pendingSetup.Load())
	rv := handleTestRequest(
		t,
		handlers.adminSetup,
		http.MethodPost,
		http.NoBody,
		gin.Param{},
	)
	require.Equal(t, http.StatusForbidden, rv.StatusCode)

	var rvErr httpError
	data, err := io.ReadAll(rv.Body)
	t.Cleanup(
		func() {
			_ = rv.Body.Close()
		},
	)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &rvErr))

	require.Equal(t, "Forbidden", rvErr.Error)
}

func TestAPI_AdminSetup_DBUpdateError(t *testing.T) {
	bot, _ := newDisConciergePendingSetup(t, context.Background())
	handlers := NewAPIHandlers(bot)
	require.True(t, bot.pendingSetup.Load())
	payload := adminSetupPayload{
		Username:        t.Name(),
		Password:        fmt.Sprintf("changeme"),
		ConfirmPassword: fmt.Sprintf("changeme"),
	}
	payloadData, err := json.Marshal(payload)
	require.NoError(t, err)
	originalColumn := columnRuntimeConfigAdminPassword
	columnRuntimeConfigAdminPassword = "admin_asdf"
	t.Cleanup(
		func() {
			columnRuntimeConfigAdminPassword = originalColumn
		},
	)
	rv := handleTestRequest(
		t,
		handlers.adminSetup,
		http.MethodPost,
		bytes.NewReader(payloadData),
		gin.Param{},
	)
	require.Equal(t, http.StatusInternalServerError, rv.StatusCode)

	var rvErr httpError
	data, err := io.ReadAll(rv.Body)
	t.Cleanup(
		func() {
			_ = rv.Body.Close()
		},
	)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &rvErr))

	require.Equal(t, "error updating admin credentials", rvErr.Error)
}

func TestAPI_UpdateConfig_DiscordNotificationChannelID(t *testing.T) {
	bot, _ := newDisConcierge(t)
	require.Empty(t, bot.RuntimeConfig().DiscordNotificationChannelID)

	mockSession := newMockDiscordSession()
	connectSession := discordChannelMessageSendHandler{
		DiscordSessionHandler: mockSession,
		messagesSent:          make(chan stubChannelMessageSend, 100),
		repliesSent:           make(chan stubMessageReply, 100),
		errCh:                 make(chan error, 100),
		t:                     t,
	}
	channelID := fmt.Sprintf("c_%s", t.Name())
	bot.discord.session = connectSession

	handlers := NewAPIHandlers(bot)
	payload := RuntimeConfigUpdate{
		DiscordNotificationChannelID: strPtr(channelID),
	}
	payloadData, err := json.Marshal(payload)
	require.NoError(t, err)

	rv := handleTestRequest(
		t,
		handlers.updateRuntimeConfig,
		http.MethodPatch,
		bytes.NewReader(payloadData),
		gin.Param{},
	)
	assert.Equal(t, http.StatusAccepted, rv.StatusCode)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	select {
	case msgSent := <-connectSession.messagesSent:
		require.Equal(t, channelID, msgSent.ChannelID)
		require.Equal(t, bot.config.Discord.StartupMessage, msgSent.Content)
	case <-ctx.Done():
		t.Fatal("timed out")
	}
}

func TestAPIHandlers_botQuit(t *testing.T) {
	t.Parallel()
	bot, _ := newDisConcierge(t)
	handlers := NewAPIHandlers(bot)

	rv := handleTestRequest(
		t,
		handlers.botQuit,
		http.MethodPost,
		http.NoBody,
	)

	assert.Equal(t, http.StatusOK, rv.StatusCode)
	var response httpReply
	responseData, err := io.ReadAll(rv.Body)
	require.NoError(t, err)
	defer func() {
		_ = rv.Body.Close()
	}()

	err = json.Unmarshal(responseData, &response)
	require.NoError(t, err)
	assert.Equal(t, "quitting", response.Message)

	select {
	case <-bot.eventShutdown:
		//
	case <-time.After(60 * time.Second):
		t.Fatal("Timeout waiting for stop signal")
	}
}

func TestRequestIDMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(requestIDMiddleware())

	r.GET(
		"/test", func(c *gin.Context) {
			requestID, exists := c.Get(xRequestIDHeader)

			assert.True(t, exists, "Request ID should exist in context")
			assert.IsType(t, "", requestID, "Request ID should be a string")
			assert.NotEmpty(t, requestID, "Request ID should not be empty")
			assert.Len(
				t,
				requestID.(string),
				32,
				"Request ID should be 32 characters long",
			)

			c.String(http.StatusOK, "test")
		},
	)

	// Test multiple requests to ensure uniqueness
	previousID := ""
	for i := 0; i < 10; i++ {
		req, _ := http.NewRequest("GET", "/test", http.NoBody)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		requestID := w.Header().Get(xRequestIDHeader)
		assert.NotEmpty(
			t,
			requestID,
			"Request ID should be set in response header",
		)
		assert.Len(t, requestID, 32, "Request ID should be 32 characters long")
		assert.NotEqual(
			t,
			previousID,
			requestID,
			"Request IDs should be unique",
		)
		previousID = requestID
	}
}

func TestAPIHandlers_logoutHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)

	stores := map[string]CookieStore{}

	tests := []struct {
		name               string
		setupSession       func(*gin.Engine)
		expectedStatusCode int
		expectedMessage    string
	}{
		{
			name: "No active session",
			setupSession: func(r *gin.Engine) {
				store := NewCookieStore([]byte("secret"))
				r.Use(sessions.Sessions(sessionVarName, store))
			},
			expectedStatusCode: http.StatusOK,
			expectedMessage:    "logged out",
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				r := gin.New()
				tt.setupSession(r)

				bot, _ := newDisConcierge(t)
				handlers := NewAPIHandlers(bot)

				w := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(w)
				c.Request, _ = http.NewRequest("POST", "/logout", nil)

				// If it's a "Successful logout" test, set a session value
				if tt.name == "Successful logout" {
					store := stores[tt.name]
					session := gsessions.NewSession(store, sessionVarName)
					session.Values[sessionVarField] = "testuser"
					err := session.Save(c.Request, w)
					require.NoError(t, err)
				}

				handlers.logoutHandler(c)
				assert.Equal(t, tt.expectedStatusCode, w.Code)

				var response httpReply
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(t, err)
				assert.Equal(t, tt.expectedMessage, response.Message)
			},
		)
	}
}

func TestAPI_GetChatCommands(t *testing.T) {
	bot, _ := newDisConcierge(t)
	handlers := NewAPIHandlers(bot)

	// Create test users
	userFoo, _, err := bot.GetOrCreateUser(
		context.Background(),
		discordgo.User{ID: "foo", Username: "Foo User"},
	)
	require.NoError(t, err)

	userBar, _, err := bot.GetOrCreateUser(
		context.Background(),
		discordgo.User{ID: "bar", Username: "Bar User"},
	)
	require.NoError(t, err)

	// Create test ChatCommands
	now := time.Date(2024, 8, 28, 16, 0, 0, 0, time.UTC)

	chatCmdFoo1 := &ChatCommand{
		Interaction: Interaction{
			User:          userFoo,
			UserID:        userFoo.ID,
			InteractionID: "ifoo1",
		},
		State:                 ChatCommandStateCompleted,
		ThreadID:              "threadFoo1",
		RunID:                 "runFoo1",
		UsagePromptTokens:     25,
		UsageCompletionTokens: 25,
		UsageTotalTokens:      50,
		Prompt:                "Foo's first question",
	}
	chatCmdFoo1.CreatedAt = now.Add(-2 * (24 * time.Hour)).UnixMilli()
	_, err = bot.writeDB.Create(chatCmdFoo1, "User")
	require.NoError(t, err)

	chatCmdFoo2 := &ChatCommand{
		Interaction: Interaction{
			User:          userFoo,
			UserID:        userFoo.ID,
			InteractionID: "ifoo2",
		},
		State:                 ChatCommandStateCompleted,
		ThreadID:              "threadFoo2",
		RunID:                 "runFoo2",
		UsagePromptTokens:     30,
		UsageCompletionTokens: 30,
		UsageTotalTokens:      60,
		Prompt:                "Foo's second question",
	}
	chatCmdFoo2.CreatedAt = now.Add(-1 * (24 * time.Hour)).UnixMilli()
	_, err = bot.writeDB.Create(chatCmdFoo2, "User")
	require.NoError(t, err)

	chatCmdBar := &ChatCommand{
		Interaction: Interaction{
			User:          userBar,
			UserID:        userBar.ID,
			InteractionID: "ibar",
		},
		State:                 ChatCommandStateCompleted,
		ThreadID:              "threadBar",
		RunID:                 "runBar",
		UsagePromptTokens:     40,
		UsageCompletionTokens: 40,
		UsageTotalTokens:      80,
		Prompt:                "Bar's question",
	}
	chatCmdBar.CreatedAt = now.UnixMilli()
	_, err = bot.writeDB.Create(chatCmdBar, "User")
	require.NoError(t, err)

	// Question order:
	// 1. Foo's first question
	// 2. Foo's second question
	// 3. Bar's question

	// Test cases
	testCases := []struct {
		name           string
		query          map[string]string
		expectedStatus int
		expectedCount  int
		validate       func(t *testing.T, commands []ChatCommand)
	}{
		{
			name:           "Get all commands",
			query:          map[string]string{},
			expectedStatus: http.StatusOK,
			expectedCount:  3,
			validate: func(t *testing.T, commands []ChatCommand) {
				assert.Equal(t, 3, len(commands))
				assert.Equal(t, "Bar's question", commands[0].Prompt)
				assert.Equal(t, "Foo's second question", commands[1].Prompt)
				assert.Equal(t, "Foo's first question", commands[2].Prompt)
			},
		},
		{
			name: "Get commands with pagination",
			query: map[string]string{
				"limit":  "2",
				"offset": "1",
			},
			expectedStatus: http.StatusOK,
			expectedCount:  2,
			validate: func(t *testing.T, commands []ChatCommand) {
				assert.Equal(t, 2, len(commands))
				assert.Equal(t, "Foo's second question", commands[0].Prompt)
				assert.Equal(t, "Foo's first question", commands[1].Prompt)
			},
		},
		{
			name: "Get commands for specific user",
			query: map[string]string{
				"user_id": "foo",
			},
			expectedStatus: http.StatusOK,
			expectedCount:  2,
			validate: func(t *testing.T, commands []ChatCommand) {
				assert.Equal(t, 2, len(commands))
				assert.Equal(t, "foo", commands[0].UserID)
				assert.Equal(t, "foo", commands[1].UserID)
			},
		},
		{
			name: "Get commands with date range",
			query: map[string]string{
				"start_date": now.Add(-2 * (24 * time.Hour)).Format("2006-01-02"),
				"end_date":   now.Add(-1 * (24 * time.Hour)).Format("2006-01-02"),
			},
			expectedStatus: http.StatusOK,
			expectedCount:  2,
			validate: func(t *testing.T, commands []ChatCommand) {
				assert.Equal(t, 2, len(commands))
				assert.Equal(t, "Foo's first question", commands[1].Prompt)
				assert.Equal(t, "Foo's second question", commands[0].Prompt)
			},
		},
		{
			name: "Get commands in ascending order",
			query: map[string]string{
				"order": "asc",
			},
			expectedStatus: http.StatusOK,
			expectedCount:  3,
			validate: func(t *testing.T, commands []ChatCommand) {
				assert.Equal(t, 3, len(commands))
				assert.Equal(t, "Bar's question", commands[2].Prompt)
				assert.Equal(t, "Foo's second question", commands[1].Prompt)
				assert.Equal(t, "Foo's first question", commands[0].Prompt)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(
			tc.name, func(t *testing.T) {
				req, err := http.NewRequest(
					http.MethodGet,
					fmt.Sprintf("%s%s", apiPrefix, "/chat_commands"),
					http.NoBody,
				)
				require.NoError(t, err)

				q := req.URL.Query()
				for key, value := range tc.query {
					q.Add(key, value)
				}
				req.URL.RawQuery = q.Encode()

				rv := handleTestHTTPRequest(
					t,
					handlers.getChatCommands,
					req,
				)

				assert.Equal(t, tc.expectedStatus, rv.StatusCode)

				var commands []ChatCommand
				err = json.NewDecoder(rv.Body).Decode(&commands)
				require.NoError(t, err)

				assert.Equal(t, tc.expectedCount, len(commands))

				if tc.validate != nil {
					tc.validate(t, commands)
				}
			},
		)
	}
}

func TestAPI_GetChatCommandDetail(t *testing.T) {
	bot, _ := newDisConcierge(t)
	handlers := NewAPIHandlers(bot)

	// Create a test user
	user, _, err := bot.GetOrCreateUser(
		context.Background(),
		discordgo.User{ID: "testuser", Username: "Test User"},
	)
	require.NoError(t, err)

	// Create a test ChatCommand
	chatCmd := &ChatCommand{
		Interaction: Interaction{
			User:          user,
			UserID:        user.ID,
			InteractionID: "test-interaction",
		},
		State:                 ChatCommandStateCompleted,
		ThreadID:              "test-thread",
		RunID:                 "test-run",
		UsagePromptTokens:     25,
		UsageCompletionTokens: 25,
		UsageTotalTokens:      50,
		Prompt:                "Test question",
	}
	_, err = bot.writeDB.Create(chatCmd, "User")
	require.NoError(t, err)

	// Create related OpenAI API call records
	createThread := &OpenAICreateThread{
		OpenAIAPILog: OpenAIAPILog{
			ChatCommandID: &chatCmd.ID,
			RequestBody:   "create thread request",
			ResponseBody:  "create thread response",
		},
	}
	_, err = bot.writeDB.Create(createThread)
	require.NoError(t, err)

	createMessage := &OpenAICreateMessage{
		OpenAIAPILog: OpenAIAPILog{
			ChatCommandID: &chatCmd.ID,
			RequestBody:   "create message request",
			ResponseBody:  "create message response",
		},
	}
	_, err = bot.writeDB.Create(createMessage)
	require.NoError(t, err)

	listMessages := &OpenAIListMessages{
		OpenAIAPILog: OpenAIAPILog{
			ChatCommandID: &chatCmd.ID,
			RequestBody:   "list messages request",
			ResponseBody:  "list messages response",
		},
	}
	_, err = bot.writeDB.Create(listMessages)
	require.NoError(t, err)

	createRun := &OpenAICreateRun{
		OpenAIAPILog: OpenAIAPILog{
			ChatCommandID: &chatCmd.ID,
			RequestBody:   "create run request",
			ResponseBody:  "create run response",
		},
	}
	_, err = bot.writeDB.Create(createRun)
	require.NoError(t, err)

	retrieveRun := &OpenAIRetrieveRun{
		OpenAIAPILog: OpenAIAPILog{
			ChatCommandID: &chatCmd.ID,
			RequestBody:   "retrieve run request",
			ResponseBody:  "retrieve run response",
		},
	}
	_, err = bot.writeDB.Create(retrieveRun)
	require.NoError(t, err)

	listRunSteps := &OpenAIListRunSteps{
		OpenAIAPILog: OpenAIAPILog{
			ChatCommandID: &chatCmd.ID,
			RequestBody:   "list run steps request",
			ResponseBody:  "list run steps response",
		},
	}
	_, err = bot.writeDB.Create(listRunSteps)
	require.NoError(t, err)

	// Test cases
	testCases := []struct {
		name           string
		id             string
		expectedStatus int
		validate       func(t *testing.T, detail ChatCommandDetail)
	}{
		{
			name:           "Valid ChatCommand ID",
			id:             fmt.Sprintf("%d", chatCmd.ID),
			expectedStatus: http.StatusOK,
			validate: func(t *testing.T, detail ChatCommandDetail) {
				assert.Equal(t, chatCmd.ID, detail.ChatCommand.ID)
				assert.Equal(t, "Test question", detail.ChatCommand.Prompt)
				assert.NotNil(t, detail.CreateThread)
				assert.NotNil(t, detail.CreateMessage)
				assert.Len(t, detail.ListMessages, 1)
				assert.NotNil(t, detail.CreateRun)
				assert.Len(t, detail.RetrieveRuns, 1)
				assert.Len(t, detail.ListRunSteps, 1)
			},
		},
		{
			name:           "Invalid ChatCommand ID",
			id:             "999999",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "Invalid ID format",
			id:             "not-a-number",
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range testCases {
		t.Run(
			tc.name, func(t *testing.T) {
				req, e := http.NewRequest(
					http.MethodGet,
					fmt.Sprintf(
						"%s%s",
						apiPrefix,
						apiPathGetChatCommand,
					),
					http.NoBody,
				)
				require.NoError(t, e)

				rv := handleTestHTTPRequest(
					t,
					handlers.getChatCommandDetail,
					req,
					gin.Param{Key: "id", Value: tc.id},
				)

				assert.Equal(t, tc.expectedStatus, rv.StatusCode)

				if tc.expectedStatus == http.StatusOK {
					var detail ChatCommandDetail
					e = json.NewDecoder(rv.Body).Decode(&detail)
					require.NoError(t, e)

					if tc.validate != nil {
						tc.validate(t, detail)
					}
				}
			},
		)
	}
}

func TestAPI_GetDiscordMessages(t *testing.T) {
	bot, _ := newDisConcierge(t)
	handlers := NewAPIHandlers(bot)

	// Create sample discord messages
	sampleMessages := []DiscordMessage{
		{MessageID: "1", Content: "Test message 1", Payload: "Full payload 1"},
		{MessageID: "2", Content: "Test message 2", Payload: "Full payload 2"},
		{MessageID: "3", Content: "Test message 3", Payload: "Full payload 3"},
	}
	for _, msg := range sampleMessages {
		_, err := bot.writeDB.Create(&msg)
		require.NoError(t, err)
	}

	// Test cases
	testCases := []struct {
		name           string
		query          string
		expectedStatus int
		validate       func(t *testing.T, messages []DiscordMessage)
	}{
		{
			name:           "Default",
			query:          "",
			expectedStatus: http.StatusOK,
			validate: func(t *testing.T, messages []DiscordMessage) {
				assert.Len(t, messages, 3)
				assert.NotEmpty(t, messages[0].Payload)
			},
		},
		{
			name:           "Limit 2",
			query:          "?limit=2",
			expectedStatus: http.StatusOK,
			validate: func(t *testing.T, messages []DiscordMessage) {
				assert.Len(t, messages, 2)
			},
		},
		{
			name:           "Offset 1",
			query:          "?offset=1",
			expectedStatus: http.StatusOK,
			validate: func(t *testing.T, messages []DiscordMessage) {
				assert.Len(t, messages, 2)
				assert.Equal(t, "2", messages[0].MessageID)
			},
		},
		{
			name:           "Descending order",
			query:          "?order=desc",
			expectedStatus: http.StatusOK,
			validate: func(t *testing.T, messages []DiscordMessage) {
				assert.Len(t, messages, 3)
				assert.Equal(t, "3", messages[0].MessageID)
			},
		},
		{
			name:           "Include payload",
			query:          "?include_payload=true",
			expectedStatus: http.StatusOK,
			validate: func(t *testing.T, messages []DiscordMessage) {
				assert.Len(t, messages, 3)
				assert.NotEmpty(t, messages[0].Payload)
			},
		},
		{
			name:           "Invalid order",
			query:          "?order=invalid",
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range testCases {
		t.Run(
			tc.name, func(t *testing.T) {
				req, e := http.NewRequest(
					http.MethodGet,
					fmt.Sprintf(
						"%s%s%s",
						apiPrefix,
						apiPathGetDiscordMessages,
						tc.query,
					),
					http.NoBody,
				)
				require.NoError(t, e)

				resp := handleTestHTTPRequest(
					t,
					handlers.getDiscordMessages,
					req,
				)

				assert.Equal(t, tc.expectedStatus, resp.StatusCode)

				if tc.expectedStatus == http.StatusOK {
					var messages []DiscordMessage
					require.NoError(
						t,
						json.NewDecoder(resp.Body).Decode(&messages),
					)

					if tc.validate != nil {
						tc.validate(t, messages)
					}
				}
			},
		)
	}
}

func TestAPI_UpdateConfig_DiscordGateway(t *testing.T) {
	t.Parallel()
	bot, _ := newDisConcierge(t)
	handlers := NewAPIHandlers(bot)

	// Mock the Discord session
	mockSession := &MockDiscordSession{}
	bot.discord.session = mockSession

	baseConfig := *bot.runtimeConfig

	tests := []struct {
		name           string
		initialState   RuntimeConfig
		updatePayload  RuntimeConfigUpdate
		expectedCalls  []string
		expectedStatus string
	}{
		{
			name: "Disable Discord Gateway",
			initialState: func() RuntimeConfig {
				cfg := baseConfig
				cfg.DiscordGatewayEnabled = true
				return cfg
			}(),
			updatePayload: RuntimeConfigUpdate{
				DiscordGatewayEnabled: boolPtr(false),
			},
			expectedCalls: []string{"Close"},
		},
		{
			name: "Enable Discord Gateway",
			initialState: func() RuntimeConfig {
				cfg := baseConfig
				cfg.DiscordGatewayEnabled = false
				return cfg
			}(),
			updatePayload: RuntimeConfigUpdate{
				DiscordGatewayEnabled: boolPtr(true),
			},
			expectedCalls: []string{"SetIdentify", "Open"},
		},
		{
			// FIXME This test is flaky (fails intermittently)
			name: "Update Custom Status",
			initialState: func() RuntimeConfig {
				cfg := baseConfig
				cfg.DiscordGatewayEnabled = true
				cfg.DiscordCustomStatus = "Old Status"
				cfg.Paused = false
				return cfg
			}(),
			updatePayload: RuntimeConfigUpdate{
				DiscordCustomStatus: strPtr("New Status"),
			},
			expectedCalls:  []string{"UpdateCustomStatus"},
			expectedStatus: "New Status",
		},
		{
			name: "Pause Bot",
			initialState: func() RuntimeConfig {
				cfg := baseConfig
				cfg.DiscordGatewayEnabled = true
				cfg.Paused = false
				return cfg
			}(),
			updatePayload: RuntimeConfigUpdate{
				Paused: boolPtr(true),
			},
			expectedCalls: []string{"UpdateStatusComplex"},
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				// Reset mock and set initial state
				mockSession.Reset()

				bot.runtimeConfig = &tt.initialState

				t.Cleanup(
					func() {
						bot.triggerRuntimeConfigRefreshCh = make(chan bool, 1)
						bot.triggerUserUpdatedRefreshCh = make(chan string, 1)
						bot.triggerUserCacheRefreshCh = make(chan bool, 1)
					},
				)

				// Prepare and send update request
				payload, err := json.Marshal(tt.updatePayload)
				require.NoError(t, err)

				resp := handleTestRequest(
					t,
					handlers.updateRuntimeConfig,
					http.MethodPatch,
					bytes.NewReader(payload),
				)

				// Check response
				assert.Equal(t, http.StatusAccepted, resp.StatusCode)

				// Verify expected calls
				assert.Equal(t, tt.expectedCalls, mockSession.Calls)

				// Check specific expectations
				if tt.expectedStatus != "" {
					assert.Equal(t, tt.expectedStatus, mockSession.LastStatus)
				}

				// Verify final state
				updatedConfig := bot.RuntimeConfig()
				if tt.updatePayload.DiscordGatewayEnabled != nil {
					assert.Equal(
						t,
						*tt.updatePayload.DiscordGatewayEnabled,
						updatedConfig.DiscordGatewayEnabled,
					)
				}
				if tt.updatePayload.DiscordCustomStatus != nil {
					assert.Equal(
						t,
						*tt.updatePayload.DiscordCustomStatus,
						updatedConfig.DiscordCustomStatus,
					)
				}
				if tt.updatePayload.Paused != nil {
					assert.Equal(
						t,
						*tt.updatePayload.Paused,
						updatedConfig.Paused,
					)
				}
			},
		)
	}
}

// MockDiscordSession is a mock implementation of the DiscordSessionHandler interface
type MockDiscordSession struct {
	DiscordSessionHandler
	Calls      []string
	LastStatus string
}

func (m *MockDiscordSession) Close() error {
	m.Calls = append(m.Calls, "Close")
	return nil
}

func (m *MockDiscordSession) Open() error {
	m.Calls = append(m.Calls, "Open")
	return nil
}

func (m *MockDiscordSession) UpdateStatusComplex(data discordgo.UpdateStatusData) error {
	m.Calls = append(m.Calls, "UpdateStatusComplex")
	m.LastStatus = data.Status
	return nil
}

func (m *MockDiscordSession) UpdateCustomStatus(status string) error {
	m.Calls = append(m.Calls, "UpdateCustomStatus")
	m.LastStatus = status
	return nil
}

func (m *MockDiscordSession) SetIdentify(discordgo.Identify) {
	m.Calls = append(m.Calls, "SetIdentify")
}

func (m *MockDiscordSession) Reset() {
	m.Calls = []string{}
	m.LastStatus = ""
}

func TestAPI_GetOpenAIRetrieveRunLogs(t *testing.T) {
	t.Parallel()
	bot, _ := newDisConcierge(t)
	handlers := NewAPIHandlers(bot)

	// Create test users
	userFoo, _, err := bot.GetOrCreateUser(
		context.Background(),
		discordgo.User{ID: "foo", Username: "Foo User"},
	)
	require.NoError(t, err)

	userBar, _, err := bot.GetOrCreateUser(
		context.Background(),
		discordgo.User{ID: "bar", Username: "Bar User"},
	)
	require.NoError(t, err)

	// Create test ChatCommands
	now := time.Date(2024, 8, 28, 16, 0, 0, 0, time.UTC)

	chatCmdFoo := &ChatCommand{
		Interaction: Interaction{
			User:          userFoo,
			UserID:        userFoo.ID,
			InteractionID: "ifoo",
		},
		State:    ChatCommandStateCompleted,
		ThreadID: "threadFoo",
		RunID:    "runFoo",
	}
	chatCmdFoo.CreatedAt = now.Add(-1 * (24 * time.Hour)).UnixMilli()
	_, err = bot.writeDB.Create(chatCmdFoo, "User")
	require.NoError(t, err)

	chatCmdBar := &ChatCommand{
		Interaction: Interaction{
			User:          userBar,
			UserID:        userBar.ID,
			InteractionID: "ibar",
		},
		State:    ChatCommandStateCompleted,
		ThreadID: "threadBar",
		RunID:    "runBar",
	}
	chatCmdBar.CreatedAt = now.UnixMilli()
	_, err = bot.writeDB.Create(chatCmdBar, "User")
	require.NoError(t, err)

	// Create test OpenAIRetrieveRun records
	retrieveRunFoo1 := &OpenAIRetrieveRun{
		OpenAIAPILog: OpenAIAPILog{
			ChatCommandID:  &chatCmdFoo.ID,
			RequestStarted: now.Add(-1 * (24 * time.Hour)).UnixMilli(),
			RequestEnded:   now.Add(-1 * (24 * time.Hour)).Add(1 * time.Second).UnixMilli(),
		},
	}
	_, err = bot.writeDB.Create(retrieveRunFoo1)
	require.NoError(t, err)

	retrieveRunFoo2 := &OpenAIRetrieveRun{
		OpenAIAPILog: OpenAIAPILog{
			ChatCommandID:  &chatCmdFoo.ID,
			RequestStarted: now.Add(-23 * time.Hour).UnixMilli(),
			RequestEnded:   now.Add(-23 * time.Hour).Add(1 * time.Second).UnixMilli(),
		},
	}
	_, err = bot.writeDB.Create(retrieveRunFoo2)
	require.NoError(t, err)

	retrieveRunBar := &OpenAIRetrieveRun{
		OpenAIAPILog: OpenAIAPILog{
			ChatCommandID:  &chatCmdBar.ID,
			RequestStarted: now.UnixMilli(),
			RequestEnded:   now.Add(1 * time.Second).UnixMilli(),
		},
	}
	_, err = bot.writeDB.Create(retrieveRunBar)
	require.NoError(t, err)

	// Test cases
	testCases := []struct {
		name           string
		query          map[string]string
		expectedStatus int
		expectedTotal  int64
		validate       func(t *testing.T, response map[string]any)
	}{
		{
			name:           "Get all logs",
			query:          map[string]string{},
			expectedStatus: http.StatusOK,
			expectedTotal:  3,
			validate: func(t *testing.T, response map[string]any) {
				logs := response["logs"].([]any)
				assert.Equal(t, 3, len(logs))
				assert.Equal(t, float64(3), response["total"])
				assert.Equal(t, float64(0), response["offset"])
				assert.Equal(t, float64(25), response["limit"])
			},
		},
		{
			name: "Get logs with pagination",
			query: map[string]string{
				"limit":  "2",
				"offset": "1",
			},
			expectedStatus: http.StatusOK,
			expectedTotal:  3,
			validate: func(t *testing.T, response map[string]any) {
				logs := response["logs"].([]any)
				assert.Equal(t, 2, len(logs))
				assert.Equal(t, float64(3), response["total"])
				assert.Equal(t, float64(1), response["offset"])
				assert.Equal(t, float64(2), response["limit"])
			},
		},
		{
			name: "Get logs for specific chat command",
			query: map[string]string{
				"chat_command_id": fmt.Sprintf("%d", chatCmdFoo.ID),
			},
			expectedStatus: http.StatusOK,
			expectedTotal:  2,
			validate: func(t *testing.T, response map[string]any) {
				logs := response["logs"].([]any)
				assert.Equal(t, 2, len(logs))
				for _, log := range logs {
					logMap := log.(map[string]any)
					assert.Equal(t, float64(chatCmdFoo.ID), logMap["chat_command_id"])
				}
			},
		},
		{
			name: "Get logs in ascending order",
			query: map[string]string{
				"order": "asc",
			},
			expectedStatus: http.StatusOK,
			expectedTotal:  3,
			validate: func(t *testing.T, response map[string]any) {
				logs := response["logs"].([]any)
				assert.Equal(t, 3, len(logs))
				firstLog := logs[0].(map[string]any)
				lastLog := logs[2].(map[string]any)
				assert.Less(t, firstLog["request_started"], lastLog["request_started"])
			},
		},
	}

	for _, tc := range testCases {
		t.Run(
			tc.name, func(t *testing.T) {
				req, err := http.NewRequest(
					http.MethodGet,
					fmt.Sprintf("%s%s", apiPrefix, "/openai/logs/retrieve_run"),
					http.NoBody,
				)
				require.NoError(t, err)

				q := req.URL.Query()
				for key, value := range tc.query {
					q.Add(key, value)
				}
				req.URL.RawQuery = q.Encode()

				rv := handleTestHTTPRequest(
					t,
					handlers.getOpenAIRetrieveRunLogs,
					req,
				)

				assert.Equal(t, tc.expectedStatus, rv.StatusCode)

				var response map[string]any
				err = json.NewDecoder(rv.Body).Decode(&response)
				require.NoError(t, err)

				assert.Equal(t, tc.expectedTotal, int64(response["total"].(float64)))

				if tc.validate != nil {
					tc.validate(t, response)
				}
			},
		)
	}
}

func TestAPI_GetOpenAICreateThreadLogs(t *testing.T) {
	t.Parallel()
	bot, _ := newDisConcierge(t)
	handlers := NewAPIHandlers(bot)

	// Create test users
	userFoo, _, err := bot.GetOrCreateUser(
		context.Background(),
		discordgo.User{ID: "foo", Username: "Foo User"},
	)
	require.NoError(t, err)

	userBar, _, err := bot.GetOrCreateUser(
		context.Background(),
		discordgo.User{ID: "bar", Username: "Bar User"},
	)
	require.NoError(t, err)

	// Create test ChatCommands
	now := time.Date(2024, 8, 28, 16, 0, 0, 0, time.UTC)

	chatCmdFoo := &ChatCommand{
		Interaction: Interaction{
			User:          userFoo,
			UserID:        userFoo.ID,
			InteractionID: "ifoo",
		},
		State:    ChatCommandStateCompleted,
		ThreadID: "threadFoo",
		RunID:    "runFoo",
	}
	chatCmdFoo.CreatedAt = now.Add(-1 * (24 * time.Hour)).UnixMilli()
	_, err = bot.writeDB.Create(chatCmdFoo, "User")
	require.NoError(t, err)

	chatCmdBar := &ChatCommand{
		Interaction: Interaction{
			User:          userBar,
			UserID:        userBar.ID,
			InteractionID: "ibar",
		},
		State:    ChatCommandStateCompleted,
		ThreadID: "threadBar",
		RunID:    "runBar",
	}
	chatCmdBar.CreatedAt = now.UnixMilli()
	_, err = bot.writeDB.Create(chatCmdBar, "User")
	require.NoError(t, err)

	// Create test OpenAICreateThread records
	createThreadFoo1 := &OpenAICreateThread{
		OpenAIAPILog: OpenAIAPILog{
			ChatCommandID:  &chatCmdFoo.ID,
			RequestStarted: now.Add(-1 * (24 * time.Hour)).UnixMilli(),
			RequestEnded:   now.Add(-1 * (24 * time.Hour)).Add(1 * time.Second).UnixMilli(),
		},
	}
	_, err = bot.writeDB.Create(createThreadFoo1)
	require.NoError(t, err)

	createThreadFoo2 := &OpenAICreateThread{
		OpenAIAPILog: OpenAIAPILog{
			ChatCommandID:  &chatCmdFoo.ID,
			RequestStarted: now.Add(-23 * time.Hour).UnixMilli(),
			RequestEnded:   now.Add(-23 * time.Hour).Add(1 * time.Second).UnixMilli(),
		},
	}
	_, err = bot.writeDB.Create(createThreadFoo2)
	require.NoError(t, err)

	createThreadBar := &OpenAICreateThread{
		OpenAIAPILog: OpenAIAPILog{
			ChatCommandID:  &chatCmdBar.ID,
			RequestStarted: now.UnixMilli(),
			RequestEnded:   now.Add(1 * time.Second).UnixMilli(),
		},
	}
	_, err = bot.writeDB.Create(createThreadBar)
	require.NoError(t, err)

	// Test cases
	testCases := []struct {
		name           string
		query          map[string]string
		expectedStatus int
		expectedTotal  int64
		validate       func(t *testing.T, response map[string]any)
	}{
		{
			name:           "Get all logs",
			query:          map[string]string{},
			expectedStatus: http.StatusOK,
			expectedTotal:  3,
			validate: func(t *testing.T, response map[string]any) {
				logs := response["logs"].([]any)
				assert.Equal(t, 3, len(logs))
				assert.Equal(t, float64(3), response["total"])
				assert.Equal(t, float64(0), response["offset"])
				assert.Equal(t, float64(25), response["limit"])
			},
		},
		{
			name: "Get logs with pagination",
			query: map[string]string{
				"limit":  "2",
				"offset": "1",
			},
			expectedStatus: http.StatusOK,
			expectedTotal:  3,
			validate: func(t *testing.T, response map[string]any) {
				logs := response["logs"].([]any)
				assert.Equal(t, 2, len(logs))
				assert.Equal(t, float64(3), response["total"])
				assert.Equal(t, float64(1), response["offset"])
				assert.Equal(t, float64(2), response["limit"])
			},
		},
		{
			name: "Get logs for specific chat command",
			query: map[string]string{
				"chat_command_id": fmt.Sprintf("%d", chatCmdFoo.ID),
			},
			expectedStatus: http.StatusOK,
			expectedTotal:  2,
			validate: func(t *testing.T, response map[string]any) {
				logs := response["logs"].([]any)
				assert.Equal(t, 2, len(logs))
				for _, log := range logs {
					logMap := log.(map[string]any)
					assert.Equal(t, float64(chatCmdFoo.ID), logMap["chat_command_id"])
				}
			},
		},
		{
			name: "Get logs in ascending order",
			query: map[string]string{
				"order": "asc",
			},
			expectedStatus: http.StatusOK,
			expectedTotal:  3,
			validate: func(t *testing.T, response map[string]any) {
				logs := response["logs"].([]any)
				assert.Equal(t, 3, len(logs))
				firstLog := logs[0].(map[string]any)
				lastLog := logs[2].(map[string]any)
				assert.Less(t, firstLog["request_started"], lastLog["request_started"])
			},
		},
	}

	for _, tc := range testCases {
		t.Run(
			tc.name, func(t *testing.T) {
				req, err := http.NewRequest(
					http.MethodGet,
					fmt.Sprintf("%s%s", apiPrefix, "/openai/logs/create_thread"),
					http.NoBody,
				)
				require.NoError(t, err)

				q := req.URL.Query()
				for key, value := range tc.query {
					q.Add(key, value)
				}
				req.URL.RawQuery = q.Encode()

				rv := handleTestHTTPRequest(
					t,
					handlers.getOpenAICreateThreadLogs,
					req,
				)

				assert.Equal(t, tc.expectedStatus, rv.StatusCode)

				var response map[string]any
				err = json.NewDecoder(rv.Body).Decode(&response)
				require.NoError(t, err)

				assert.Equal(t, tc.expectedTotal, int64(response["total"].(float64)))

				if tc.validate != nil {
					tc.validate(t, response)
				}
			},
		)
	}
}

func TestAPI_GetOpenAICreateMessageLogs(t *testing.T) {
	t.Parallel()
	bot, _ := newDisConcierge(t)
	handlers := NewAPIHandlers(bot)

	// Create test users
	userFoo, _, err := bot.GetOrCreateUser(
		context.Background(),
		discordgo.User{ID: "foo", Username: "Foo User"},
	)
	require.NoError(t, err)

	userBar, _, err := bot.GetOrCreateUser(
		context.Background(),
		discordgo.User{ID: "bar", Username: "Bar User"},
	)
	require.NoError(t, err)

	// Create test ChatCommands
	now := time.Date(2024, 8, 28, 16, 0, 0, 0, time.UTC)

	chatCmdFoo := &ChatCommand{
		Interaction: Interaction{
			User:          userFoo,
			UserID:        userFoo.ID,
			InteractionID: "ifoo",
		},
		State:    ChatCommandStateCompleted,
		ThreadID: "threadFoo",
		RunID:    "runFoo",
	}
	chatCmdFoo.CreatedAt = now.Add(-1 * (24 * time.Hour)).UnixMilli()
	_, err = bot.writeDB.Create(chatCmdFoo, "User")
	require.NoError(t, err)

	chatCmdBar := &ChatCommand{
		Interaction: Interaction{
			User:          userBar,
			UserID:        userBar.ID,
			InteractionID: "ibar",
		},
		State:    ChatCommandStateCompleted,
		ThreadID: "threadBar",
		RunID:    "runBar",
	}
	chatCmdBar.CreatedAt = now.UnixMilli()
	_, err = bot.writeDB.Create(chatCmdBar, "User")
	require.NoError(t, err)

	// Create test OpenAICreateMessage records
	createMessageFoo1 := &OpenAICreateMessage{
		OpenAIAPILog: OpenAIAPILog{
			ChatCommandID:  &chatCmdFoo.ID,
			RequestStarted: now.Add(-1 * (24 * time.Hour)).UnixMilli(),
			RequestEnded:   now.Add(-1 * (24 * time.Hour)).Add(1 * time.Second).UnixMilli(),
		},
	}
	_, err = bot.writeDB.Create(createMessageFoo1)
	require.NoError(t, err)

	createMessageFoo2 := &OpenAICreateMessage{
		OpenAIAPILog: OpenAIAPILog{
			ChatCommandID:  &chatCmdFoo.ID,
			RequestStarted: now.Add(-23 * time.Hour).UnixMilli(),
			RequestEnded:   now.Add(-23 * time.Hour).Add(1 * time.Second).UnixMilli(),
		},
	}
	_, err = bot.writeDB.Create(createMessageFoo2)
	require.NoError(t, err)

	createMessageBar := &OpenAICreateMessage{
		OpenAIAPILog: OpenAIAPILog{
			ChatCommandID:  &chatCmdBar.ID,
			RequestStarted: now.UnixMilli(),
			RequestEnded:   now.Add(1 * time.Second).UnixMilli(),
		},
	}
	_, err = bot.writeDB.Create(createMessageBar)
	require.NoError(t, err)

	// Test cases
	testCases := []struct {
		name           string
		query          map[string]string
		expectedStatus int
		expectedTotal  int64
		validate       func(t *testing.T, response map[string]any)
	}{
		{
			name:           "Get all logs",
			query:          map[string]string{},
			expectedStatus: http.StatusOK,
			expectedTotal:  3,
			validate: func(t *testing.T, response map[string]any) {
				logs := response["logs"].([]any)
				assert.Equal(t, 3, len(logs))
				assert.Equal(t, float64(3), response["total"])
				assert.Equal(t, float64(0), response["offset"])
				assert.Equal(t, float64(25), response["limit"])
			},
		},
		{
			name: "Get logs with pagination",
			query: map[string]string{
				"limit":  "2",
				"offset": "1",
			},
			expectedStatus: http.StatusOK,
			expectedTotal:  3,
			validate: func(t *testing.T, response map[string]any) {
				logs := response["logs"].([]any)
				assert.Equal(t, 2, len(logs))
				assert.Equal(t, float64(3), response["total"])
				assert.Equal(t, float64(1), response["offset"])
				assert.Equal(t, float64(2), response["limit"])
			},
		},
		{
			name: "Get logs for specific chat command",
			query: map[string]string{
				"chat_command_id": fmt.Sprintf("%d", chatCmdFoo.ID),
			},
			expectedStatus: http.StatusOK,
			expectedTotal:  2,
			validate: func(t *testing.T, response map[string]any) {
				logs := response["logs"].([]any)
				assert.Equal(t, 2, len(logs))
				for _, log := range logs {
					logMap := log.(map[string]any)
					assert.Equal(t, float64(chatCmdFoo.ID), logMap["chat_command_id"])
				}
			},
		},
		{
			name: "Get logs in ascending order",
			query: map[string]string{
				"order": "asc",
			},
			expectedStatus: http.StatusOK,
			expectedTotal:  3,
			validate: func(t *testing.T, response map[string]any) {
				logs := response["logs"].([]any)
				assert.Equal(t, 3, len(logs))
				firstLog := logs[0].(map[string]any)
				lastLog := logs[2].(map[string]any)
				assert.Less(t, firstLog["request_started"], lastLog["request_started"])
			},
		},
	}

	for _, tc := range testCases {
		t.Run(
			tc.name, func(t *testing.T) {
				req, err := http.NewRequest(
					http.MethodGet,
					fmt.Sprintf("%s%s", apiPrefix, "/openai/logs/create_message"),
					http.NoBody,
				)
				require.NoError(t, err)

				q := req.URL.Query()
				for key, value := range tc.query {
					q.Add(key, value)
				}
				req.URL.RawQuery = q.Encode()

				rv := handleTestHTTPRequest(
					t,
					handlers.getOpenAICreateMessageLogs,
					req,
				)

				assert.Equal(t, tc.expectedStatus, rv.StatusCode)

				var response map[string]any
				err = json.NewDecoder(rv.Body).Decode(&response)
				require.NoError(t, err)

				assert.Equal(t, tc.expectedTotal, int64(response["total"].(float64)))

				if tc.validate != nil {
					tc.validate(t, response)
				}
			},
		)
	}
}

func TestAPI_GetOpenAICreateRunLogs(t *testing.T) {
	t.Parallel()
	bot, _ := newDisConcierge(t)
	handlers := NewAPIHandlers(bot)

	// Create test users
	userFoo, _, err := bot.GetOrCreateUser(
		context.Background(),
		discordgo.User{ID: "foo", Username: "Foo User"},
	)
	require.NoError(t, err)

	userBar, _, err := bot.GetOrCreateUser(
		context.Background(),
		discordgo.User{ID: "bar", Username: "Bar User"},
	)
	require.NoError(t, err)

	// Create test ChatCommands
	now := time.Date(2024, 8, 28, 16, 0, 0, 0, time.UTC)

	chatCmdFoo := &ChatCommand{
		Interaction: Interaction{
			User:          userFoo,
			UserID:        userFoo.ID,
			InteractionID: "ifoo",
		},
		State:    ChatCommandStateCompleted,
		ThreadID: "threadFoo",
		RunID:    "runFoo",
	}
	chatCmdFoo.CreatedAt = now.Add(-1 * (24 * time.Hour)).UnixMilli()
	_, err = bot.writeDB.Create(chatCmdFoo, "User")
	require.NoError(t, err)

	chatCmdBar := &ChatCommand{
		Interaction: Interaction{
			User:          userBar,
			UserID:        userBar.ID,
			InteractionID: "ibar",
		},
		State:    ChatCommandStateCompleted,
		ThreadID: "threadBar",
		RunID:    "runBar",
	}
	chatCmdBar.CreatedAt = now.UnixMilli()
	_, err = bot.writeDB.Create(chatCmdBar, "User")
	require.NoError(t, err)

	// Create test OpenAICreateRun records
	createRunFoo1 := &OpenAICreateRun{
		OpenAIAPILog: OpenAIAPILog{
			ChatCommandID:  &chatCmdFoo.ID,
			RequestStarted: now.Add(-1 * (24 * time.Hour)).UnixMilli(),
			RequestEnded:   now.Add(-1 * (24 * time.Hour)).Add(1 * time.Second).UnixMilli(),
		},
	}
	_, err = bot.writeDB.Create(createRunFoo1)
	require.NoError(t, err)

	createRunFoo2 := &OpenAICreateRun{
		OpenAIAPILog: OpenAIAPILog{
			ChatCommandID:  &chatCmdFoo.ID,
			RequestStarted: now.Add(-23 * time.Hour).UnixMilli(),
			RequestEnded:   now.Add(-23 * time.Hour).Add(1 * time.Second).UnixMilli(),
		},
	}
	_, err = bot.writeDB.Create(createRunFoo2)
	require.NoError(t, err)

	createRunBar := &OpenAICreateRun{
		OpenAIAPILog: OpenAIAPILog{
			ChatCommandID:  &chatCmdBar.ID,
			RequestStarted: now.UnixMilli(),
			RequestEnded:   now.Add(1 * time.Second).UnixMilli(),
		},
	}
	_, err = bot.writeDB.Create(createRunBar)
	require.NoError(t, err)

	// Test cases
	testCases := []struct {
		name           string
		query          map[string]string
		expectedStatus int
		expectedTotal  int64
		validate       func(t *testing.T, response map[string]any)
	}{
		{
			name:           "Get all logs",
			query:          map[string]string{},
			expectedStatus: http.StatusOK,
			expectedTotal:  3,
			validate: func(t *testing.T, response map[string]any) {
				logs := response["logs"].([]any)
				assert.Equal(t, 3, len(logs))
				assert.Equal(t, float64(3), response["total"])
				assert.Equal(t, float64(0), response["offset"])
				assert.Equal(t, float64(25), response["limit"])
			},
		},
		{
			name: "Get logs with pagination",
			query: map[string]string{
				"limit":  "2",
				"offset": "1",
			},
			expectedStatus: http.StatusOK,
			expectedTotal:  3,
			validate: func(t *testing.T, response map[string]any) {
				logs := response["logs"].([]any)
				assert.Equal(t, 2, len(logs))
				assert.Equal(t, float64(3), response["total"])
				assert.Equal(t, float64(1), response["offset"])
				assert.Equal(t, float64(2), response["limit"])
			},
		},
		{
			name: "Get logs for specific chat command",
			query: map[string]string{
				"chat_command_id": fmt.Sprintf("%d", chatCmdFoo.ID),
			},
			expectedStatus: http.StatusOK,
			expectedTotal:  2,
			validate: func(t *testing.T, response map[string]any) {
				logs := response["logs"].([]any)
				assert.Equal(t, 2, len(logs))
				for _, log := range logs {
					logMap := log.(map[string]any)
					assert.Equal(t, float64(chatCmdFoo.ID), logMap["chat_command_id"])
				}
			},
		},
		{
			name: "Get logs in ascending order",
			query: map[string]string{
				"order": "asc",
			},
			expectedStatus: http.StatusOK,
			expectedTotal:  3,
			validate: func(t *testing.T, response map[string]any) {
				logs := response["logs"].([]any)
				assert.Equal(t, 3, len(logs))
				firstLog := logs[0].(map[string]any)
				lastLog := logs[2].(map[string]any)
				assert.Less(t, firstLog["request_started"], lastLog["request_started"])
			},
		},
	}

	for _, tc := range testCases {
		t.Run(
			tc.name, func(t *testing.T) {
				req, err := http.NewRequest(
					http.MethodGet,
					fmt.Sprintf("%s%s", apiPrefix, "/openai/logs/create_run"),
					http.NoBody,
				)
				require.NoError(t, err)

				q := req.URL.Query()
				for key, value := range tc.query {
					q.Add(key, value)
				}
				req.URL.RawQuery = q.Encode()

				rv := handleTestHTTPRequest(
					t,
					handlers.getOpenAICreateRunLogs,
					req,
				)

				assert.Equal(t, tc.expectedStatus, rv.StatusCode)

				var response map[string]any
				err = json.NewDecoder(rv.Body).Decode(&response)
				require.NoError(t, err)

				assert.Equal(t, tc.expectedTotal, int64(response["total"].(float64)))

				if tc.validate != nil {
					tc.validate(t, response)
				}
			},
		)
	}
}

func TestAPI_GetOpenAIListMessagesLogs(t *testing.T) {
	t.Parallel()
	bot, _ := newDisConcierge(t)
	handlers := NewAPIHandlers(bot)

	// Create test users
	userFoo, _, err := bot.GetOrCreateUser(
		context.Background(),
		discordgo.User{ID: "foo", Username: "Foo User"},
	)
	require.NoError(t, err)

	userBar, _, err := bot.GetOrCreateUser(
		context.Background(),
		discordgo.User{ID: "bar", Username: "Bar User"},
	)
	require.NoError(t, err)

	// Create test ChatCommands
	now := time.Date(2024, 8, 28, 16, 0, 0, 0, time.UTC)

	chatCmdFoo := &ChatCommand{
		Interaction: Interaction{
			User:          userFoo,
			UserID:        userFoo.ID,
			InteractionID: "ifoo",
		},
		State:    ChatCommandStateCompleted,
		ThreadID: "threadFoo",
		RunID:    "runFoo",
	}
	chatCmdFoo.CreatedAt = now.Add(-1 * (24 * time.Hour)).UnixMilli()
	_, err = bot.writeDB.Create(chatCmdFoo, "User")
	require.NoError(t, err)

	chatCmdBar := &ChatCommand{
		Interaction: Interaction{
			User:          userBar,
			UserID:        userBar.ID,
			InteractionID: "ibar",
		},
		State:    ChatCommandStateCompleted,
		ThreadID: "threadBar",
		RunID:    "runBar",
	}
	chatCmdBar.CreatedAt = now.UnixMilli()
	_, err = bot.writeDB.Create(chatCmdBar, "User")
	require.NoError(t, err)

	// Create test OpenAIListMessages records
	listMessagesFoo1 := &OpenAIListMessages{
		OpenAIAPILog: OpenAIAPILog{
			ChatCommandID:  &chatCmdFoo.ID,
			RequestStarted: now.Add(-1 * (24 * time.Hour)).UnixMilli(),
			RequestEnded:   now.Add(-1 * (24 * time.Hour)).Add(1 * time.Second).UnixMilli(),
		},
	}
	_, err = bot.writeDB.Create(listMessagesFoo1)
	require.NoError(t, err)

	listMessagesFoo2 := &OpenAIListMessages{
		OpenAIAPILog: OpenAIAPILog{
			ChatCommandID:  &chatCmdFoo.ID,
			RequestStarted: now.Add(-23 * time.Hour).UnixMilli(),
			RequestEnded:   now.Add(-23 * time.Hour).Add(1 * time.Second).UnixMilli(),
		},
	}
	_, err = bot.writeDB.Create(listMessagesFoo2)
	require.NoError(t, err)

	listMessagesBar := &OpenAIListMessages{
		OpenAIAPILog: OpenAIAPILog{
			ChatCommandID:  &chatCmdBar.ID,
			RequestStarted: now.UnixMilli(),
			RequestEnded:   now.Add(1 * time.Second).UnixMilli(),
		},
	}
	_, err = bot.writeDB.Create(listMessagesBar)
	require.NoError(t, err)

	// Test cases
	testCases := []struct {
		name           string
		query          map[string]string
		expectedStatus int
		expectedTotal  int64
		validate       func(t *testing.T, response map[string]any)
	}{
		{
			name:           "Get all logs",
			query:          map[string]string{},
			expectedStatus: http.StatusOK,
			expectedTotal:  3,
			validate: func(t *testing.T, response map[string]any) {
				logs := response["logs"].([]any)
				assert.Equal(t, 3, len(logs))
				assert.Equal(t, float64(3), response["total"])
				assert.Equal(t, float64(0), response["offset"])
				assert.Equal(t, float64(25), response["limit"])
			},
		},
		{
			name: "Get logs with pagination",
			query: map[string]string{
				"limit":  "2",
				"offset": "1",
			},
			expectedStatus: http.StatusOK,
			expectedTotal:  3,
			validate: func(t *testing.T, response map[string]any) {
				logs := response["logs"].([]any)
				assert.Equal(t, 2, len(logs))
				assert.Equal(t, float64(3), response["total"])
				assert.Equal(t, float64(1), response["offset"])
				assert.Equal(t, float64(2), response["limit"])
			},
		},
		{
			name: "Get logs for specific chat command",
			query: map[string]string{
				"chat_command_id": fmt.Sprintf("%d", chatCmdFoo.ID),
			},
			expectedStatus: http.StatusOK,
			expectedTotal:  2,
			validate: func(t *testing.T, response map[string]any) {
				logs := response["logs"].([]any)
				assert.Equal(t, 2, len(logs))
				for _, log := range logs {
					logMap := log.(map[string]any)
					assert.Equal(t, float64(chatCmdFoo.ID), logMap["chat_command_id"])
				}
			},
		},
		{
			name: "Get logs in ascending order",
			query: map[string]string{
				"order": "asc",
			},
			expectedStatus: http.StatusOK,
			expectedTotal:  3,
			validate: func(t *testing.T, response map[string]any) {
				logs := response["logs"].([]any)
				assert.Equal(t, 3, len(logs))
				firstLog := logs[0].(map[string]any)
				lastLog := logs[2].(map[string]any)
				assert.Less(t, firstLog["request_started"], lastLog["request_started"])
			},
		},
	}

	for _, tc := range testCases {
		t.Run(
			tc.name, func(t *testing.T) {
				req, err := http.NewRequest(
					http.MethodGet,
					fmt.Sprintf("%s%s", apiPrefix, "/openai/logs/list_messages"),
					http.NoBody,
				)
				require.NoError(t, err)

				q := req.URL.Query()
				for key, value := range tc.query {
					q.Add(key, value)
				}
				req.URL.RawQuery = q.Encode()

				rv := handleTestHTTPRequest(
					t,
					handlers.getOpenAIListMessagesLogs,
					req,
				)

				assert.Equal(t, tc.expectedStatus, rv.StatusCode)

				var response map[string]any
				err = json.NewDecoder(rv.Body).Decode(&response)
				require.NoError(t, err)

				assert.Equal(t, tc.expectedTotal, int64(response["total"].(float64)))

				if tc.validate != nil {
					tc.validate(t, response)
				}
			},
		)
	}
}

func TestAPI_GetOpenAIListRunStepsLogs(t *testing.T) {
	t.Parallel()
	bot, _ := newDisConcierge(t)
	handlers := NewAPIHandlers(bot)

	// Create test users
	userFoo, _, err := bot.GetOrCreateUser(
		context.Background(),
		discordgo.User{ID: "foo", Username: "Foo User"},
	)
	require.NoError(t, err)

	userBar, _, err := bot.GetOrCreateUser(
		context.Background(),
		discordgo.User{ID: "bar", Username: "Bar User"},
	)
	require.NoError(t, err)

	// Create test ChatCommands
	now := time.Date(2024, 8, 28, 16, 0, 0, 0, time.UTC)

	chatCmdFoo := &ChatCommand{
		Interaction: Interaction{
			User:          userFoo,
			UserID:        userFoo.ID,
			InteractionID: "ifoo",
		},
		State:    ChatCommandStateCompleted,
		ThreadID: "threadFoo",
		RunID:    "runFoo",
	}
	chatCmdFoo.CreatedAt = now.Add(-1 * (24 * time.Hour)).UnixMilli()
	_, err = bot.writeDB.Create(chatCmdFoo, "User")
	require.NoError(t, err)

	chatCmdBar := &ChatCommand{
		Interaction: Interaction{
			User:          userBar,
			UserID:        userBar.ID,
			InteractionID: "ibar",
		},
		State:    ChatCommandStateCompleted,
		ThreadID: "threadBar",
		RunID:    "runBar",
	}
	chatCmdBar.CreatedAt = now.UnixMilli()
	_, err = bot.writeDB.Create(chatCmdBar, "User")
	require.NoError(t, err)

	// Create test OpenAIListRunSteps records
	listRunStepsFoo1 := &OpenAIListRunSteps{
		OpenAIAPILog: OpenAIAPILog{
			ChatCommandID:  &chatCmdFoo.ID,
			RequestStarted: now.Add(-1 * (24 * time.Hour)).UnixMilli(),
			RequestEnded:   now.Add(-1 * (24 * time.Hour)).Add(1 * time.Second).UnixMilli(),
		},
	}
	_, err = bot.writeDB.Create(listRunStepsFoo1)
	require.NoError(t, err)

	listRunStepsFoo2 := &OpenAIListRunSteps{
		OpenAIAPILog: OpenAIAPILog{
			ChatCommandID:  &chatCmdFoo.ID,
			RequestStarted: now.Add(-23 * time.Hour).UnixMilli(),
			RequestEnded:   now.Add(-23 * time.Hour).Add(1 * time.Second).UnixMilli(),
		},
	}
	_, err = bot.writeDB.Create(listRunStepsFoo2)
	require.NoError(t, err)

	listRunStepsBar := &OpenAIListRunSteps{
		OpenAIAPILog: OpenAIAPILog{
			ChatCommandID:  &chatCmdBar.ID,
			RequestStarted: now.UnixMilli(),
			RequestEnded:   now.Add(1 * time.Second).UnixMilli(),
		},
	}
	_, err = bot.writeDB.Create(listRunStepsBar)
	require.NoError(t, err)

	// Test cases
	testCases := []struct {
		name           string
		query          map[string]string
		expectedStatus int
		expectedTotal  int64
		validate       func(t *testing.T, response map[string]any)
	}{
		{
			name:           "Get all logs",
			query:          map[string]string{},
			expectedStatus: http.StatusOK,
			expectedTotal:  3,
			validate: func(t *testing.T, response map[string]any) {
				logs := response["logs"].([]any)
				assert.Equal(t, 3, len(logs))
				assert.Equal(t, float64(3), response["total"])
				assert.Equal(t, float64(0), response["offset"])
				assert.Equal(t, float64(25), response["limit"])
			},
		},
		{
			name: "Get logs with pagination",
			query: map[string]string{
				"limit":  "2",
				"offset": "1",
			},
			expectedStatus: http.StatusOK,
			expectedTotal:  3,
			validate: func(t *testing.T, response map[string]any) {
				logs := response["logs"].([]any)
				assert.Equal(t, 2, len(logs))
				assert.Equal(t, float64(3), response["total"])
				assert.Equal(t, float64(1), response["offset"])
				assert.Equal(t, float64(2), response["limit"])
			},
		},
		{
			name: "Get logs for specific chat command",
			query: map[string]string{
				"chat_command_id": fmt.Sprintf("%d", chatCmdFoo.ID),
			},
			expectedStatus: http.StatusOK,
			expectedTotal:  2,
			validate: func(t *testing.T, response map[string]any) {
				logs := response["logs"].([]any)
				assert.Equal(t, 2, len(logs))
				for _, log := range logs {
					logMap := log.(map[string]any)
					assert.Equal(t, float64(chatCmdFoo.ID), logMap["chat_command_id"])
				}
			},
		},
		{
			name: "Get logs in ascending order",
			query: map[string]string{
				"order": "asc",
			},
			expectedStatus: http.StatusOK,
			expectedTotal:  3,
			validate: func(t *testing.T, response map[string]any) {
				logs := response["logs"].([]any)
				assert.Equal(t, 3, len(logs))
				firstLog := logs[0].(map[string]any)
				lastLog := logs[2].(map[string]any)
				assert.Less(t, firstLog["request_started"], lastLog["request_started"])
			},
		},
	}

	for _, tc := range testCases {
		t.Run(
			tc.name, func(t *testing.T) {
				req, err := http.NewRequest(
					http.MethodGet,
					fmt.Sprintf("%s%s", apiPrefix, "/openai/logs/list_run_steps"),
					http.NoBody,
				)
				require.NoError(t, err)

				q := req.URL.Query()
				for key, value := range tc.query {
					q.Add(key, value)
				}
				req.URL.RawQuery = q.Encode()

				rv := handleTestHTTPRequest(
					t,
					handlers.getOpenAIListRunStepsLogs,
					req,
				)

				assert.Equal(t, tc.expectedStatus, rv.StatusCode)

				var response map[string]any
				err = json.NewDecoder(rv.Body).Decode(&response)
				require.NoError(t, err)

				assert.Equal(t, tc.expectedTotal, int64(response["total"].(float64)))

				if tc.validate != nil {
					tc.validate(t, response)
				}
			},
		)
	}
}

// TestAPIHandlers_UpdateConfig_OpenAIMaxRequestsPerSecond validates that
// when [RuntimeConfig.OpenAIMaxRequestsPerSecond] is updated via the API,
// the `OpenAI.requestLimiter` limit is also updated.
func TestAPIHandlers_UpdateConfig_OpenAIMaxRequestsPerSecond(t *testing.T) {
	bot, _ := newDisConcierge(t)
	handlers := NewAPIHandlers(bot)

	initialRate := bot.openai.requestLimiter.Limit()
	newRate := initialRate * 2

	updateData := RuntimeConfigUpdate{
		OpenAIMaxRequestsPerSecond: intPtr(int(newRate)),
	}
	payload, err := json.Marshal(updateData)
	require.NoError(t, err)

	resp := handleTestRequest(
		t,
		handlers.updateRuntimeConfig,
		http.MethodPatch,
		bytes.NewReader(payload),
	)

	assert.Equal(t, http.StatusAccepted, resp.StatusCode)

	assert.Equal(t, rate.Limit(newRate), bot.openai.requestLimiter.Limit())

	updatedConfig := bot.RuntimeConfig()
	assert.Equal(t, int(newRate), updatedConfig.OpenAIMaxRequestsPerSecond)
}

func TestAPI_GetUserFeedback(t *testing.T) {
	t.Parallel()
	bot, _ := newDisConcierge(t)
	handlers := NewAPIHandlers(bot)

	// Create test users
	userFoo, _, err := bot.GetOrCreateUser(
		context.Background(),
		discordgo.User{ID: "foo", Username: "Foo User"},
	)
	require.NoError(t, err)

	userBar, _, err := bot.GetOrCreateUser(
		context.Background(),
		discordgo.User{ID: "bar", Username: "Bar User"},
	)
	require.NoError(t, err)

	// Create test ChatCommands
	now := time.Date(2024, 8, 28, 16, 0, 0, 0, time.UTC)

	chatCmdFoo := &ChatCommand{
		Interaction: Interaction{
			User:          userFoo,
			UserID:        userFoo.ID,
			InteractionID: "ifoo",
		},
		State:    ChatCommandStateCompleted,
		ThreadID: "threadFoo",
		RunID:    "runFoo",
	}
	chatCmdFoo.CreatedAt = now.Add(-1 * (24 * time.Hour)).UnixMilli()
	_, err = bot.writeDB.Create(chatCmdFoo, "User")
	require.NoError(t, err)

	chatCmdBar := &ChatCommand{
		Interaction: Interaction{
			User:          userBar,
			UserID:        userBar.ID,
			InteractionID: "ibar",
		},
		State:    ChatCommandStateCompleted,
		ThreadID: "threadBar",
		RunID:    "runBar",
	}
	chatCmdBar.CreatedAt = now.UnixMilli()
	_, err = bot.writeDB.Create(chatCmdBar, "User")
	require.NoError(t, err)

	// Create test UserFeedback records
	feedbackFoo1 := &UserFeedback{
		ChatCommandID: &chatCmdFoo.ID,
		UserID:        &userFoo.ID,
		Type:          string(UserFeedbackGood),
		Description:   "Good response",
		ModelUnixTime: ModelUnixTime{CreatedAt: now.Add(-1 * (24 * time.Hour)).UnixMilli()},
	}
	_, err = bot.writeDB.Create(feedbackFoo1)
	require.NoError(t, err)

	feedbackFoo2 := &UserFeedback{
		ChatCommandID: &chatCmdFoo.ID,
		UserID:        &userFoo.ID,
		Type:          string(UserFeedbackOutdated),
		Description:   "Information is outdated",
		ModelUnixTime: ModelUnixTime{CreatedAt: now.Add(-23 * time.Hour).UnixMilli()},
	}
	_, err = bot.writeDB.Create(feedbackFoo2)
	require.NoError(t, err)

	feedbackBar := &UserFeedback{
		ChatCommandID: &chatCmdBar.ID,
		UserID:        &userBar.ID,
		Type:          string(UserFeedbackHallucinated),
		Description:   "Response contains inaccuracies",
		ModelUnixTime: ModelUnixTime{CreatedAt: now.UnixMilli()},
	}
	_, err = bot.writeDB.Create(feedbackBar)
	require.NoError(t, err)

	// Test cases
	testCases := []struct {
		name           string
		query          map[string]string
		expectedStatus int
		expectedTotal  int64
		validate       func(t *testing.T, response map[string]any)
	}{
		{
			name:           "Get all feedback",
			query:          map[string]string{},
			expectedStatus: http.StatusOK,
			expectedTotal:  3,
			validate: func(t *testing.T, response map[string]any) {
				feedback := response["feedback"].([]any)
				assert.Equal(t, 3, len(feedback))
				assert.Equal(t, float64(3), response["total"])
				assert.Equal(t, float64(0), response["offset"])
				assert.Equal(t, float64(25), response["limit"])
			},
		},
		{
			name: "Get feedback with pagination",
			query: map[string]string{
				"limit":  "2",
				"offset": "1",
			},
			expectedStatus: http.StatusOK,
			expectedTotal:  3,
			validate: func(t *testing.T, response map[string]any) {
				feedback := response["feedback"].([]any)
				assert.Equal(t, 2, len(feedback))
				assert.Equal(t, float64(3), response["total"])
				assert.Equal(t, float64(1), response["offset"])
				assert.Equal(t, float64(2), response["limit"])
			},
		},
		{
			name: "Get feedback for specific chat command",
			query: map[string]string{
				"chat_command_id": fmt.Sprintf("%d", chatCmdFoo.ID),
			},
			expectedStatus: http.StatusOK,
			expectedTotal:  2,
			validate: func(t *testing.T, response map[string]any) {
				feedback := response["feedback"].([]any)
				assert.Equal(t, 2, len(feedback))
				for _, fb := range feedback {
					fbMap := fb.(map[string]any)
					assert.Equal(t, float64(chatCmdFoo.ID), fbMap["chat_command_id"])
				}
			},
		},
		{
			name: "Get feedback for specific user",
			query: map[string]string{
				"user_id": userBar.ID,
			},
			expectedStatus: http.StatusOK,
			expectedTotal:  1,
			validate: func(t *testing.T, response map[string]any) {
				feedback := response["feedback"].([]any)
				assert.Equal(t, 1, len(feedback))
				fbMap := feedback[0].(map[string]any)
				assert.Equal(t, userBar.ID, fbMap["user_id"])
			},
		},
		{
			name: "Get feedback in ascending order",
			query: map[string]string{
				"order": "asc",
			},
			expectedStatus: http.StatusOK,
			expectedTotal:  3,
			validate: func(t *testing.T, response map[string]any) {
				feedback := response["feedback"].([]any)
				assert.Equal(t, 3, len(feedback))
				firstFeedback := feedback[0].(map[string]any)
				lastFeedback := feedback[2].(map[string]any)
				assert.Less(t, firstFeedback["created_at"], lastFeedback["created_at"])
			},
		},
	}

	for _, tc := range testCases {
		t.Run(
			tc.name, func(t *testing.T) {
				req, err := http.NewRequest(
					http.MethodGet,
					fmt.Sprintf("%s%s", apiPrefix, "/user_feedback"),
					http.NoBody,
				)
				require.NoError(t, err)

				q := req.URL.Query()
				for key, value := range tc.query {
					q.Add(key, value)
				}
				req.URL.RawQuery = q.Encode()

				rv := handleTestHTTPRequest(
					t,
					handlers.getUserFeedback,
					req,
				)

				assert.Equal(t, tc.expectedStatus, rv.StatusCode)

				var response map[string]any
				err = json.NewDecoder(rv.Body).Decode(&response)
				require.NoError(t, err)

				assert.Equal(t, tc.expectedTotal, int64(response["total"].(float64)))

				if tc.validate != nil {
					tc.validate(t, response)
				}
			},
		)
	}
}

func TestAPIHandlers_ReloadUsers(t *testing.T) {
	t.Parallel()
	bot, _ := newDisConcierge(t)
	handlers := NewAPIHandlers(bot)

	// Create initial users
	userFoo, _, err := bot.GetOrCreateUser(
		context.Background(),
		discordgo.User{ID: "foo", Username: "Foo User"},
	)
	require.NoError(t, err)

	userBar, isNew, err := bot.GetOrCreateUser(
		context.Background(),
		discordgo.User{ID: "bar", Username: "Bar User"},
	)
	require.NoError(t, err)
	require.NotNil(t, userBar)
	assert.True(t, isNew)

	// Modify a user directly in the database
	_, err = bot.writeDB.Update(userFoo, "username", "Updated Foo User")
	require.NoError(t, err)

	// Add a new user directly to the database
	newUser := &User{
		ID:       "baz",
		Username: "Baz User",
	}
	_, err = bot.writeDB.Create(newUser)
	require.NoError(t, err)

	// Call the reloadUsers handler
	resp := handleTestRequest(
		t,
		handlers.reloadUsers,
		http.MethodPost,
		http.NoBody,
	)

	// Check the response
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)

	time.Sleep(2 * time.Second)

	var users []*User

	for _, u := range bot.writeDB.UserCache() {
		users = append(users, u)
	}

	// Verify the results
	assert.Equal(t, 3, len(users), "Expected 3 users after reload")

	// Check if the users are correctly updated/added
	var foundFoo, foundBar, foundBaz bool
	for _, user := range users {
		switch user.ID {
		case "foo":
			assert.Equal(
				t,
				"Updated Foo User",
				user.Username,
				"Foo user should have updated username",
			)
			foundFoo = true
		case "bar":
			assert.Equal(t, "Bar User", user.Username, "Bar user should remain unchanged")
			foundBar = true
		case "baz":
			assert.Equal(t, "Baz User", user.Username, "Baz user should be added")
			foundBaz = true
		}
	}

	assert.True(t, foundFoo, "Updated Foo user should be present")
	assert.True(t, foundBar, "Bar user should be present")
	assert.True(t, foundBaz, "New Baz user should be present")

	// Verify that the user cache is updated
	cachedUsers := bot.writeDB.UserCache()
	assert.Equal(t, 3, len(cachedUsers), "User cache should contain 3 users")
	assert.Equal(
		t,
		"Updated Foo User",
		cachedUsers["foo"].Username,
		"Foo user in cache should have updated username",
	)
	assert.NotNil(t, cachedUsers["baz"], "Baz user should be present in the cache")
}
