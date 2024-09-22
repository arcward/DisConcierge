package disconcierge

import (
	"container/heap"
	"context"
	"encoding/json"
	"fmt"
	"github.com/bwmarrin/discordgo"
	"github.com/sashabaranov/go-openai"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestPriorityQueue verifies the ordering logic of the PriorityQueue used
// for ChatCommand requests.
// It tests the following priority rules:
//  1. Priority requests are always placed before non-priority requests.
//  2. Among priority requests, older requests (earlier CreatedAt) are placed first.
func TestPriorityQueue(t *testing.T) {
	ts := time.Now()
	priorityRequest := &ChatCommand{
		Priority:      true,
		ModelUnixTime: ModelUnixTime{CreatedAt: ts.UnixMilli()},
		Interaction: Interaction{
			User: &User{ID: "priorityNow"},
		},
	}
	priorityNewRequest := &ChatCommand{
		Priority:      true,
		ModelUnixTime: ModelUnixTime{CreatedAt: ts.Add(10 * time.Minute).UnixMilli()},
		Interaction: Interaction{
			User: &User{ID: "priorityInFuture"},
		},
	}
	normalRequest := &ChatCommand{
		Priority:      false,
		ModelUnixTime: ModelUnixTime{CreatedAt: ts.UnixMilli()},
		Interaction: Interaction{
			User: &User{ID: "normalNow"},
		},
	}
	normalOldRequest := &ChatCommand{
		Priority:      false,
		ModelUnixTime: ModelUnixTime{CreatedAt: ts.Add(-time.Minute).UnixMilli()},
		Interaction: Interaction{
			User: &User{ID: "normalOld"},
		},
	}

	allRequests := []*ChatCommand{
		priorityRequest,
		priorityNewRequest,
		normalRequest,
		normalOldRequest,
	}

	expectedOrder := []string{
		priorityRequest.User.ID,
		priorityNewRequest.User.ID,
		normalOldRequest.User.ID,
		normalRequest.User.ID,
	}

	// Test with different push orders
	pushOrders := generatePermutations(allRequests)

	getIDs := func(requests []*ChatCommand) []string {
		ids := make([]string, len(requests))
		for i, req := range requests {
			ids[i] = req.User.ID
		}
		return ids
	}

	for _, order := range pushOrders {
		t.Run(
			fmt.Sprintf("PushOrder_%v", getIDs(order)), func(t *testing.T) {
				pq := &PriorityQueue{}
				heap.Init(pq)

				for _, i := range order {
					heap.Push(pq, i)
				}

				result := []*ChatCommand{}
				for pq.Len() > 0 {
					result = append(result, heap.Pop(pq).(*ChatCommand))
				}

				require.Equal(t, len(allRequests), len(result))
				for i, expected := range expectedOrder {
					assert.Equal(
						t,
						expected,
						result[i].User.ID,
						"Mismatch at position %d",
						i,
					)
				}
			},
		)
	}
}

func TestChatCommandQueue(t *testing.T) {
	db := gormDB(t)
	writeDB := NewDatabase(db, nil, false)

	ts := time.Now()
	maxAge := 5 * time.Minute
	maxSize := 3

	priorityNowUser := &User{ID: "priorityNow"}
	priorityInFutureUser := &User{ID: "priorityInFuture"}
	normalNowUser := &User{ID: "normalNow"}
	normalOldUser := &User{ID: "normalOld"}
	priorityExpiredUser := &User{ID: "priorityExpired"}

	users := []*User{
		priorityNowUser,
		priorityInFutureUser,
		normalNowUser,
		normalOldUser,
		priorityExpiredUser,
	}
	if err := db.Create(&users).Error; err != nil {
		t.Fatal(err)
	}

	interactionIDCounter := 0
	randomInteractionID := func() string {
		interactionIDCounter++
		return fmt.Sprintf("%s/%d", t.Name(), interactionIDCounter)
	}

	priorityRequest := &ChatCommand{
		Priority:      true,
		ModelUnixTime: ModelUnixTime{CreatedAt: ts.UnixMilli()},
		Interaction: Interaction{
			InteractionID: randomInteractionID(),
			UserID:        priorityNowUser.ID,
			User:          priorityNowUser,
		},
	}
	priorityNewRequest := &ChatCommand{
		Priority:      true,
		ModelUnixTime: ModelUnixTime{CreatedAt: ts.Add(10 * time.Minute).UnixMilli()},
		Interaction: Interaction{
			InteractionID: randomInteractionID(),
			UserID:        priorityInFutureUser.ID,
			User:          priorityInFutureUser,
		},
	}

	normalRequest := &ChatCommand{
		Priority:      false,
		ModelUnixTime: ModelUnixTime{CreatedAt: ts.UnixMilli()},
		Interaction: Interaction{
			InteractionID: randomInteractionID(),
			UserID:        normalNowUser.ID,
			User:          normalNowUser,
		},
	}
	normalOldRequest := &ChatCommand{
		Priority:      false,
		ModelUnixTime: ModelUnixTime{CreatedAt: ts.Add(-time.Minute).UnixMilli()},
		Interaction: Interaction{
			InteractionID: randomInteractionID(),
			UserID:        normalOldUser.ID,
			User:          normalOldUser,
		},
	}
	priorityExpiredRequest := &ChatCommand{
		Priority:      false,
		ModelUnixTime: ModelUnixTime{CreatedAt: ts.Add(-maxAge - time.Minute).UnixMilli()},
		Interaction: Interaction{
			InteractionID: randomInteractionID(),
			UserID:        priorityExpiredUser.ID,
			User:          priorityExpiredUser,
		},
	}

	queueCfg := &QueueConfig{
		Size:        maxSize,
		MaxAge:      maxAge,
		SleepPaused: 1 * time.Second,
		SleepEmpty:  1 * time.Second,
	}
	ctx := context.Background()
	pq := NewChatCommandMemoryQueue(queueCfg, slog.Default())

	pushErr := pq.Push(ctx, priorityExpiredRequest, writeDB)
	require.ErrorIsf(
		t,
		pushErr,
		ErrChatCommandTooOld,
		"error msg: %#v",
		pushErr,
	)
	n := pq.Pop(context.Background())
	if n != nil {
		t.Fatalf("expected nil, got %#v with age %s", n, n.Age().String())
	}

	require.NoError(t, pq.Push(ctx, normalOldRequest, writeDB))
	require.NoError(t, pq.Push(ctx, normalRequest, writeDB))
	require.NoError(t, pq.Push(ctx, priorityNewRequest, writeDB))
	require.NoError(t, pq.Push(ctx, priorityRequest, writeDB))
	require.Equal(t, pq.Len(), maxSize)

	result := []*ChatCommand{}
	for pq.Len() > 0 {
		result = append(result, pq.Pop(context.Background()))
	}

	require.Len(t, result, maxSize)
	assert.Equal(t, priorityRequest.User.ID, result[0].User.ID)
	assert.Equal(t, priorityNewRequest.User.ID, result[1].User.ID)
	assert.Equal(t, normalRequest.User.ID, result[2].User.ID)
}

func TestNextRequestAvailable(t *testing.T) {
	limit := 4
	timespan := 1 * time.Hour
	currentTime := time.Date(2024, 10, 31, 12, 0, 0, 0, time.UTC)

	notIncluded := time.Date(2024, 10, 31, 8, 0, 0, 0, time.UTC)
	exactWindow := time.Date(2024, 10, 31, 11, 0, 0, 0, time.UTC)
	oneMinAfter := time.Date(2024, 10, 31, 11, 1, 0, 0, time.UTC)
	fiveMinAfter := time.Date(2024, 10, 31, 11, 5, 0, 0, time.UTC)
	fifteenMinAfter := time.Date(2024, 10, 31, 11, 15, 0, 0, time.UTC)
	thirtyMinAfter := time.Date(2024, 10, 31, 11, 30, 0, 0, time.UTC)

	requests := []time.Time{
		exactWindow,
		notIncluded,
		oneMinAfter,
		fiveMinAfter,
		fifteenMinAfter,
		thirtyMinAfter,
	}
	timeAvailable, ok := nextRequestAvailable(
		context.Background(),
		requests,
		limit,
		timespan,
		currentTime,
	)
	assert.False(t, ok)
	expectAvailable := oneMinAfter.Add(time.Minute)
	assert.Equal(t, expectAvailable, timeAvailable)

}

func Test6HrLimit(t *testing.T) {
	t.Parallel()
	bot, _ := newDisConcierge(t)
	bot.requestQueue.config.Size = 100
	bot.requestQueue.config.SleepEmpty = 1 * time.Second
	bot.requestQueue.config.SleepPaused = 1 * time.Second
	cfg := bot.RuntimeConfig()
	if _, err := bot.writeDB.Updates(
		context.TODO(), &cfg, map[string]any{
			columnRuntimeConfigUserChatCommandLimit6h: 2,
		},
	); err != nil {
		t.Fatalf("err: %s", err.Error())
	}
	bot.runtimeConfig = &cfg
	assert.Equal(t, 2, cfg.UserChatCommandLimit6h)

	ts := time.Now()

	u, _, err := bot.GetOrCreateUser(context.Background(), discordgo.User{ID: "foo"})
	require.NoError(t, err)

	cutoff := ts.Add(-(6 * time.Hour))

	interactionIDCounter := 0
	randomInteractionID := func() string {
		interactionIDCounter++
		return fmt.Sprintf("%s/%d", t.Name(), interactionIDCounter)
	}

	oldRequest := &ChatCommand{
		Priority:      false,
		ModelUnixTime: ModelUnixTime{CreatedAt: cutoff.Add(-time.Hour).UnixMilli()},
		RunStatus:     openai.RunStatusCompleted,
		Interaction: Interaction{
			InteractionID: randomInteractionID(),
			User:          u,
			UserID:        u.ID,
		},
	}
	_, err = bot.writeDB.Create(context.TODO(), oldRequest)
	require.NoError(t, err)

	cutoffRequest := &ChatCommand{
		Priority:      false,
		ModelUnixTime: ModelUnixTime{CreatedAt: cutoff.Add(2 * time.Minute).UnixMilli()},
		RunStatus:     openai.RunStatusCompleted,
		Interaction: Interaction{
			InteractionID: randomInteractionID(),
			User:          u,
			UserID:        u.ID,
		},
	}
	_, err = bot.writeDB.Create(context.TODO(), cutoffRequest)
	require.NoError(t, err)

	afterCutoff := &ChatCommand{
		Priority:      false,
		ModelUnixTime: ModelUnixTime{CreatedAt: cutoff.Add(5 * time.Minute).UnixMilli()},
		RunStatus:     openai.RunStatusCompleted,
		Interaction: Interaction{
			InteractionID: randomInteractionID(),
			User:          u,
			UserID:        u.ID,
		},
	}
	_, err = bot.writeDB.Create(context.TODO(), afterCutoff)
	require.NoError(t, err)

	rejectedRequest := &ChatCommand{
		Priority:      false,
		ModelUnixTime: ModelUnixTime{CreatedAt: cutoff.Add(15 * time.Minute).UnixMilli()},
		Prompt:        "tell me stuff",
		Interaction: Interaction{
			InteractionID: randomInteractionID(),
			User:          u,
			UserID:        u.ID,
		},
	}
	pollCtx, pollCancel := context.WithTimeout(
		context.Background(),
		15*time.Second,
	)
	t.Cleanup(pollCancel)

	if _, err = bot.writeDB.Create(context.TODO(), rejectedRequest); err != nil {
		t.Fatal(err)
	}
	rejectedRequest.handler = bot.getInteractionHandlerFunc(
		context.Background(),
		&discordgo.InteractionCreate{Interaction: &discordgo.Interaction{ID: "foo"}},
	)
	rejectedRequest.enqueue(
		pollCtx,
		bot,
	)

	finalState := waitOnChatCommandFinalState(
		t,
		pollCtx,
		bot.db,
		500*time.Millisecond,
		rejectedRequest.ID,
	)
	if finalState == nil {
		t.Fatal("expected final state, got nil")

	}
	assert.Equal(t, ChatCommandStateRateLimited, *finalState)

}

func TestTimeStuff(t *testing.T) {
	unixTimes := []int64{
		1720206887015,
		1720206877953,
		1720206860829,
		1720206847471,
		1720206839652,
		1720206830291,
		1720200588372,
		1720199929147,
		1720199920845,
		1720198811355,
	}
	prevTimes := make([]time.Time, 0, len(unixTimes))
	for _, unixTime := range unixTimes {
		prevTimes = append(prevTimes, time.UnixMilli(unixTime))
	}

	oldest := unixTimes[len(unixTimes)-1]
	t.Logf("oldest: %s", time.UnixMilli(oldest).String())

	var nowUnixMilli int64 = 1720209987028
	currentTime := time.UnixMilli(nowUnixMilli)
	nextAvailable, ok := nextRequestAvailable(
		context.Background(),
		prevTimes,
		10,
		6*time.Hour,
		currentTime,
	)
	t.Logf(
		"available: %s (%d)",
		nextAvailable.String(),
		nextAvailable.UnixMilli(),
	)
	assert.False(t, ok)

	expected := time.UnixMilli(1720220471355)
	timeStrings := []string{}
	for _, p := range prevTimes {
		timeStrings = append(timeStrings, p.String())
	}
	t.Logf("actual result: %v", nextAvailable.UnixMilli())
	assert.Equalf(
		t,
		expected,
		nextAvailable,
		"times:\n%s\nFrom: %s\n",
		strings.Join(timeStrings, "\n"),
		currentTime.String(),
	)
}

func Test6HrLimitIncludeIncomplete(t *testing.T) {
	bot, _ := newDisConcierge(t)
	bot.requestQueue.config.Size = 100
	bot.requestQueue.config.SleepEmpty = 1 * time.Second
	bot.requestQueue.config.SleepPaused = 1 * time.Second
	cfg := bot.RuntimeConfig()
	if _, err := bot.writeDB.Updates(
		context.TODO(), &cfg, map[string]any{
			columnRuntimeConfigUserChatCommandLimit6h: 2,
		},
	); err != nil {
		t.Fatalf("err: %s", err.Error())
	}
	bot.runtimeConfig = &cfg
	assert.Equal(t, 2, cfg.UserChatCommandLimit6h)

	ts := time.Now()

	u, _, err := bot.GetOrCreateUser(
		context.Background(),
		discordgo.User{
			ID: "foo",
		},
	)
	require.NoError(t, err)
	require.NoError(t, err)
	cutoff := ts.Add(-(6 * time.Hour))

	interactionIDCounter := 0
	randomInteractionID := func() string {
		interactionIDCounter++
		return fmt.Sprintf("%s/%d", t.Name(), interactionIDCounter)
	}

	oldRequest := &ChatCommand{
		Priority:      false,
		ModelUnixTime: ModelUnixTime{CreatedAt: cutoff.Add(-time.Hour).UnixMilli()},
		RunStatus:     openai.RunStatusCompleted,
		Interaction: Interaction{
			InteractionID: randomInteractionID(),
			User:          u,
			UserID:        u.ID,
		},
	}
	_, err = bot.writeDB.Create(context.TODO(), oldRequest)
	require.NoError(t, err)

	cutoffRequest := &ChatCommand{
		Priority:      false,
		ModelUnixTime: ModelUnixTime{CreatedAt: cutoff.Add(2 * time.Minute).UnixMilli()},
		RunStatus:     openai.RunStatusCompleted,
		Interaction: Interaction{
			InteractionID: randomInteractionID(),
			User:          u,
			UserID:        u.ID,
		},
	}
	_, err = bot.writeDB.Create(context.TODO(), cutoffRequest)
	require.NoError(t, err)

	afterCutoff := &ChatCommand{
		Priority:         false,
		ModelUnixTime:    ModelUnixTime{CreatedAt: cutoff.Add(5 * time.Minute).UnixMilli()},
		RunStatus:        openai.RunStatusIncomplete,
		UsageTotalTokens: 100,
		Interaction: Interaction{
			InteractionID: randomInteractionID(),
			User:          u,
			UserID:        u.ID,
		},
	}
	_, err = bot.writeDB.Create(context.TODO(), afterCutoff)
	require.NoError(t, err)

	rejectedRequest := &ChatCommand{
		Priority:      false,
		ModelUnixTime: ModelUnixTime{CreatedAt: cutoff.Add(15 * time.Minute).UnixMilli()},
		Prompt:        "tell me stuff",
		Interaction: Interaction{
			InteractionID: randomInteractionID(),
			User:          u,
			UserID:        u.ID,
		},
	}
	rejectedRequest.handler = bot.getInteractionHandlerFunc(
		context.Background(),
		&discordgo.InteractionCreate{Interaction: &discordgo.Interaction{ID: "foo"}},
	)
	pollCtx, pollCancel := context.WithTimeout(
		context.Background(),
		15*time.Second,
	)
	t.Cleanup(pollCancel)

	if _, err = bot.writeDB.Create(context.TODO(), rejectedRequest); err != nil {
		t.Fatal(err)
	}
	rejectedRequest.enqueue(
		pollCtx,
		bot,
	)

	finalState := waitOnChatCommandFinalState(
		t,
		pollCtx,
		bot.db,
		500*time.Millisecond,
		rejectedRequest.ID,
	)
	if finalState == nil {
		t.Fatal("expected final state, got nil")

	}
	assert.Equal(t, ChatCommandStateRateLimited, *finalState)
}

func TestChatCommandQueue_CommandExpired(t *testing.T) {
	t.Parallel()
	bot, _ := newDisConcierge(t)
	ts := time.Now()
	maxAge := time.Duration(5 * time.Minute)

	ids := newCommandData(t)
	discordUser := newDiscordUser(t)
	interaction := newDiscordInteraction(
		t,
		discordUser,
		ids.InteractionID,
		t.Name(),
	)
	ctx := context.Background()
	u, _, err := bot.GetOrCreateUser(ctx, *discordUser)
	require.NoError(t, err)

	chatCommand, err := NewChatCommand(u, interaction)
	require.NoError(t, err)

	_, err = bot.writeDB.Create(context.TODO(), chatCommand)
	require.NoError(t, bot.hydrateChatCommand(ctx, chatCommand))
	bot.config.Queue.MaxAge = maxAge

	_, err = bot.writeDB.Update(
		context.TODO(),
		chatCommand,
		columnChatCommandCreatedAt,
		ts.Add(-1*(maxAge*2)).UnixMilli(),
	)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(ctx, 150*time.Second)
	t.Cleanup(cancel)
	chatCommand.enqueue(ctx, bot)

	chatCommand = waitForChatCommandFinish(t, ctx, bot.db, interaction.ID)
	assert.Equal(t, ChatCommandStateExpired, chatCommand.State)
	assert.Equal(t, ChatCommandStepEnqueue, chatCommand.Step)
	assert.Nil(t, chatCommand.Response)

	assert.Equal(t, 0, chatCommand.UsageTotalTokens)
	assert.Equal(t, 0, chatCommand.UsagePromptTokens)
	assert.Equal(t, 0, chatCommand.UsageCompletionTokens)

	cmdStats, err := chatCommand.User.getStats(ctx, bot.db)
	require.NoError(t, err)

	assert.Equal(t, 0, cmdStats.ChatCommandUsage.Billable6h)
	assert.Equal(t, 1, cmdStats.ChatCommandUsage.Attempted6h)
}

func TestChatCommandQueue_RejectOnQueuePop(t *testing.T) {
	t.Parallel()
	bot, _ := newDisConcierge(t)
	ts := time.Now()
	maxAge := 5 * time.Minute

	ids := newCommandData(t)
	discordUser := newDiscordUser(t)
	interaction := newDiscordInteraction(
		t,
		discordUser,
		ids.InteractionID,
		t.Name(),
	)
	ctx := context.Background()
	u, _, e := bot.GetOrCreateUser(ctx, *discordUser)
	require.NoError(t, e)

	t.Run(
		"Command age greater than max age", func(t *testing.T) {
			chatCommand, err := NewChatCommand(u, interaction)
			require.NoError(t, err)
			chatCommand.Prompt = t.Name()

			_, err = bot.writeDB.Create(context.TODO(), chatCommand)
			require.NoError(t, bot.hydrateChatCommand(ctx, chatCommand))
			bot.config.Queue.MaxAge = maxAge

			_, err = bot.writeDB.Update(
				context.TODO(),
				chatCommand,
				columnChatCommandCreatedAt,
				ts.Add(-1*(maxAge*2)),
			)
			require.NoError(t, err)
			ctx, cancel := context.WithTimeout(ctx, 150*time.Second)
			t.Cleanup(cancel)
			require.ErrorIs(
				t,
				bot.requestQueue.Push(ctx, chatCommand, bot.writeDB),
				ErrChatCommandTooOld,
			)

			chatCommand = waitForChatCommandFinish(
				t,
				ctx,
				bot.db,
				interaction.ID,
			)
			assert.Equal(t, ChatCommandStateExpired, chatCommand.State)
			assert.Nil(t, chatCommand.Response)

			assert.Equal(t, 0, chatCommand.UsageTotalTokens)
			assert.Equal(t, 0, chatCommand.UsagePromptTokens)
			assert.Equal(t, 0, chatCommand.UsageCompletionTokens)

			cmdStats, err := chatCommand.User.getStats(ctx, bot.db)
			require.NoError(t, err)

			assert.Equal(t, 0, cmdStats.ChatCommandUsage.Billable6h)
			assert.Equal(t, 1, cmdStats.ChatCommandUsage.Attempted6h)
		},
	)

	t.Run(
		"User ignored", func(t *testing.T) {
			newInteraction := newDiscordInteraction(
				t,
				discordUser,
				fmt.Sprintf("%s-2", t.Name()),
				t.Name(),
			)
			ignoredChatCommand, err := NewChatCommand(u, newInteraction)
			require.NoError(t, err)
			ignoredChatCommand.Prompt = t.Name()

			_, err = bot.writeDB.Create(context.TODO(), ignoredChatCommand)
			require.NoError(t, err)
			require.NoError(t, bot.hydrateChatCommand(ctx, ignoredChatCommand))

			_, err = bot.writeDB.Update(context.TODO(), u, columnUserIgnored, true)
			require.NoError(t, err)
			u = bot.writeDB.ReloadUser(u.ID)
			ctx, cancel := context.WithTimeout(ctx, 150*time.Second)
			t.Cleanup(cancel)

			bot.requestQueue.requestCh <- ignoredChatCommand

			ignoredChatCommand = waitForChatCommandFinish(
				t,
				ctx,
				bot.db,
				newInteraction.ID,
			)
			assert.Equal(t, ChatCommandStateIgnored, ignoredChatCommand.State)
			assert.Nil(t, ignoredChatCommand.Response)

			assert.Equal(t, 0, ignoredChatCommand.UsageTotalTokens)
			assert.Equal(t, 0, ignoredChatCommand.UsagePromptTokens)
			assert.Equal(t, 0, ignoredChatCommand.UsageCompletionTokens)

			cmdStats, err := ignoredChatCommand.User.getStats(ctx, bot.db)
			require.NoError(t, err)

			assert.Equal(t, 0, cmdStats.ChatCommandUsage.Billable6h)
			assert.Equal(t, 2, cmdStats.ChatCommandUsage.Attempted6h)
		},
	)

}

func generatePermutations[T any](arr []T) [][]T {
	var result [][]T
	var backtrack func(int)
	backtrack = func(start int) {
		if start == len(arr) {
			permutation := make([]T, len(arr))
			copy(permutation, arr)
			result = append(result, permutation)
			return
		}
		for i := start; i < len(arr); i++ {
			arr[start], arr[i] = arr[i], arr[start]
			backtrack(start + 1)
			arr[start], arr[i] = arr[i], arr[start]
		}
	}
	backtrack(0)
	return result
}

func TestWatchQueue_Reject(t *testing.T) {
	bot, _ := newDisConcierge(t)

	// Create a user
	discordUser := newDiscordUser(t)
	user, _, err := bot.GetOrCreateUser(context.Background(), *discordUser)
	require.NoError(t, err)

	// Start watching the queue
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	t.Cleanup(cancel)

	go bot.watchQueue(ctx, nil)

	t.Run(
		"expired interaction", func(tt *testing.T) {
			// Create an old chat command
			originalMaxAge := bot.config.Queue.MaxAge

			maxAge := 1 * time.Second
			bot.config.Queue.MaxAge = maxAge
			tt.Cleanup(
				func() {
					bot.config.Queue.MaxAge = originalMaxAge
				},
			)

			oldCommand := &ChatCommand{
				Interaction: Interaction{
					UserID:        user.ID,
					InteractionID: "old-interaction-id",
					Token:         "old-token",
					TokenExpires:  time.Now().Add(15 * time.Minute).UnixMilli(),
					User:          user,
				},
				State:  ChatCommandStateQueued,
				Prompt: "This is an old command",
			}

			// Set the creation time to be older than MaxAge
			oldCommand.CreatedAt = time.Now().Add(-2 * maxAge).UnixMilli()

			// Add the old command to the database
			_, err = bot.writeDB.Create(context.TODO(), oldCommand)
			require.NoError(t, err)

			// Push the old command to the queue
			bot.requestQueue.requestCh <- oldCommand
			// err = bot.requestQueue.Push(context.Background(), oldCommand, bot.writeDB)
			// require.NoError(t, err)

			// Wait for a short period to allow the watchQueue function to process
			time.Sleep(2 * time.Second)

			// Check if the command was marked as expired
			var updatedCommand ChatCommand
			err = bot.db.First(
				&updatedCommand,
				"interaction_id = ?",
				oldCommand.InteractionID,
			).Error
			require.NoError(tt, err)

			assert.Equal(
				tt,
				ChatCommandStateExpired,
				updatedCommand.State,
				"Old command should be marked as expired",
			)

			// Verify that the command is no longer in the queue
			assert.Equal(
				tt,
				0,
				bot.requestQueue.Len(),
				"Queue should be empty after discarding old command",
			)
		},
	)
	t.Run(
		"user ignored", func(tt *testing.T) {
			// set User.Ignored=true
			bot.config.Queue.MaxAge = DefaultQueueMaxAge
			user.Ignored = true

			_, err = bot.writeDB.Update(context.TODO(), user, columnUserIgnored, true)
			require.NoError(tt, err)

			ignoredUserCommand := &ChatCommand{
				Interaction: Interaction{
					UserID:        user.ID,
					InteractionID: "ignored-interaction-id",
					Token:         "ignored-token",
					TokenExpires:  time.Now().Add(15 * time.Minute).UnixMilli(),
					User:          user,
				},
				State:  ChatCommandStateQueued,
				Prompt: "This user was ignored",
			}

			// Add the old command to the database
			_, err = bot.writeDB.Create(context.TODO(), ignoredUserCommand)
			require.NoError(tt, err)

			// Push the old command to the queue
			bot.requestQueue.requestCh <- ignoredUserCommand

			// Wait for a short period to allow the watchQueue function to process
			time.Sleep(2 * time.Second)

			// Check if the command was marked as expired
			var updatedCommand ChatCommand
			err = bot.db.First(
				&updatedCommand,
				"interaction_id = ?",
				ignoredUserCommand.InteractionID,
			).Error
			require.NoError(t, err)

			assert.Equal(
				tt,
				ChatCommandStateIgnored,
				updatedCommand.State,
				"Command should have been ignored",
			)

			// Verify that the command is no longer in the queue
			assert.Equal(
				tt,
				0,
				bot.requestQueue.Len(),
				"Queue should be empty after discarding ignored command",
			)
		},
	)

}

// TestHandleWorkerSendTimeout validates that, when a send to a
// userCommandWorker channel times out, the ChatCommand is updated
// appropriately, and a message is sent to the user. The message should
// also be deleted after a default of 20 seconds, or the context passed
// to the function is cancelled (basically flushing any goroutines waiting
// to delete)
func TestHandleWorkerSendTimeout(t *testing.T) {
	bot, _ := newDisConcierge(t)

	discordUser := newDiscordUser(t)
	user, _, err := bot.GetOrCreateUser(context.Background(), *discordUser)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	t.Cleanup(cancel)

	chatCommand := &ChatCommand{
		Interaction: Interaction{
			UserID:        user.ID,
			InteractionID: "interaction-id",
			Token:         "token",
			TokenExpires:  time.Now().Add(15 * time.Minute).UnixMilli(),
			User:          user,
		},
		State:  ChatCommandStateQueued,
		Prompt: "I'm going to timeout on send!",
	}

	chatCommand.CreatedAt = time.Now().UnixMilli()
	_, err = bot.writeDB.Create(context.TODO(), chatCommand)
	require.NoError(t, err)

	handler := newStubInteractionHandler(t)
	chatCommand.handler = handler

	wg := &sync.WaitGroup{}
	startedAt := time.Now()
	sendCtx, sendCancel := context.WithTimeout(ctx, 30*time.Second)
	t.Cleanup(sendCancel)
	bot.handleWorkerSendTimeout(sendCtx, wg, startedAt, chatCommand)

	var interactionEdit *discordgo.WebhookEdit
	select {
	case <-ctx.Done():
		t.Fatalf("context should not have been cancelled")
	case ie := <-handler.callEdit:
		interactionEdit = ie.WebhookEdit
		break
	}
	require.NotNil(t, interactionEdit)

	require.NotNil(t, interactionEdit.Content)
	data, _ := json.Marshal(interactionEdit)
	t.Logf("saw interaction: %s", string(data))
	assert.Equal(t, bot.runtimeConfig.DiscordRateLimitMessage, *interactionEdit.Content)

	require.NoError(t, bot.db.Last(&chatCommand).Error)

	assert.Equal(t, ChatCommandStateRateLimited, chatCommand.State)
	assert.Equal(t, "", chatCommand.Step.String())
	assert.NotNil(t, chatCommand.FinishedAt)
	assert.NotNil(t, chatCommand.StartedAt)
	require.NotNil(t, chatCommand.Response)
	assert.Equal(t, bot.runtimeConfig.DiscordRateLimitMessage, *chatCommand.Response)
	sendCancel()

	select {
	case <-ctx.Done():
		t.Fatalf("timed out")
	case <-handler.callDelete:
		t.Logf("saw delete")
	}

}
