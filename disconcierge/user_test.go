package disconcierge

import (
	"context"
	"errors"
	"fmt"
	"github.com/bwmarrin/discordgo"
	"github.com/stretchr/testify/assert"
	"log/slog"
	"testing"
	"time"
)

func TestTokenUsageSince(t *testing.T) {
	t.Parallel()
	cfg := DefaultTestConfig(t)

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
	user := User{ID: t.Name(), Username: t.Name(), GlobalName: t.Name()}
	if err = db.Create(&user).Error; err != nil {
		t.Fatalf("error creating user: %v", err)
	}
	createdRecently := time.Now().Add(-time.Hour)
	createdOld := time.Now().Add(-48 * time.Hour)
	chatCommands := []ChatCommand{
		{
			UsageTotalTokens: 500,
			Interaction: Interaction{
				UserID:        user.ID,
				InteractionID: fmt.Sprintf("%s-1", t.Name()),
			},
			ModelUnixTime: ModelUnixTime{CreatedAt: createdOld.UnixMilli()},
		},
		{
			UsageTotalTokens: 500,
			Interaction: Interaction{
				UserID:        user.ID,
				InteractionID: fmt.Sprintf("%s-2", t.Name()),
			},
			ModelUnixTime: ModelUnixTime{CreatedAt: createdRecently.UnixMilli()},
		},
	}

	if err = db.Create(&chatCommands).Error; err != nil {
		t.Fatalf("error creating chat commands: %v", err)
	}
	rv, err := user.TokenUsageSince(db, time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("error getting token usage: %v", err)
	}
	assert.Equal(t, int64(500), rv)

	nextCmd := ChatCommand{
		UsageTotalTokens: 500,
		Interaction: Interaction{
			UserID:        user.ID,
			InteractionID: fmt.Sprintf("%s-3", t.Name()),
		},
		ModelUnixTime: ModelUnixTime{CreatedAt: time.Now().Add(time.Hour).UnixMilli()},
	}
	if err = db.Create(&nextCmd).Error; err != nil {
		t.Fatalf("error creating chat commands: %v", err)
	}

	rv, err = user.TokenUsageSince(db, time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("error getting token usage: %v", err)
	}
	assert.Equal(t, int64(1000), rv)
}

func TestUpdateChatCommandStateAndDeleteInteraction(t *testing.T) {
	ctx := context.Background()
	logger := slog.Default()
	mockDB := &mockDatabase{}
	mockHandler := &mockInteractionHandler{}

	tests := []struct {
		name         string
		chatCommand  *ChatCommand
		newState     ChatCommandState
		expectUpdate bool
		expectDelete bool
		updateError  error
	}{
		{
			name: "Update state and delete interaction",
			chatCommand: &ChatCommand{

				Interaction: Interaction{
					TokenExpires: time.Now().Add(time.Hour).UnixMilli(),
					Acknowledged: true,
				},
				handler: mockHandler,
			},
			newState:     ChatCommandStateCompleted,
			expectUpdate: true,
			expectDelete: true,
		},
		{
			name: "Update state only (token expired)",
			chatCommand: &ChatCommand{
				Interaction: Interaction{
					TokenExpires: time.Now().Add(-time.Hour).UnixMilli(),
					Acknowledged: true,
				},
				handler: mockHandler,
			},
			newState:     ChatCommandStateFailed,
			expectUpdate: true,
			expectDelete: false,
		},
		{
			name: "Update state only (not acknowledged)",
			chatCommand: &ChatCommand{
				Interaction: Interaction{
					Acknowledged: false,
				},

				handler: mockHandler,
			},
			newState:     ChatCommandStateIgnored,
			expectUpdate: true,
			expectDelete: false,
		},
		{
			name: "Update fails",
			chatCommand: &ChatCommand{

				Interaction: Interaction{
					Acknowledged: true,
					TokenExpires: time.Now().Add(time.Hour).UnixMilli(),
				},
				handler: mockHandler,
			},
			newState:     ChatCommandStateAborted,
			expectUpdate: true,
			expectDelete: true,
			updateError:  errors.New("update failed"),
		},
	}

	for _, tc := range tests {
		t.Run(
			tc.name, func(t *testing.T) {
				// Reset mocks
				mockDB.updateCalled = false
				mockDB.updateError = tc.updateError
				mockHandler.deleteCalled = false

				updateChatCommandStateAndDeleteInteraction(
					ctx,
					logger.With("test", tc.name),
					mockDB,
					tc.chatCommand,
					tc.newState,
				)

				if tc.expectUpdate != mockDB.updateCalled {
					t.Errorf(
						"Expected update to be called: %v, but was: %v",
						tc.expectUpdate,
						mockDB.updateCalled,
					)
				}

				if tc.expectDelete != mockHandler.deleteCalled {
					t.Errorf(
						"Expected delete to be called: %v, but was: %v",
						tc.expectDelete,
						mockHandler.deleteCalled,
					)
				}

				if tc.expectUpdate && tc.updateError == nil {
					if tc.chatCommand.State != tc.newState {
						t.Errorf(
							"Expected state to be %v, but got %v",
							tc.newState,
							tc.chatCommand.State,
						)
					}
				}
			},
		)
	}
}

// Mock database
type mockDatabase struct {
	updateCalled bool
	updateError  error
	DBI
}

func (m *mockDatabase) Update(model any, _ string, value any) (int64, error) {
	m.updateCalled = true
	if m.updateError != nil {
		return 0, m.updateError
	}
	if ac, ok := model.(*ChatCommand); ok {
		ac.State = value.(ChatCommandState)
	}
	return 1, nil
}

// Mock interaction handler
type mockInteractionHandler struct {
	InteractionHandler
	deleteCalled bool
}

func (m *mockInteractionHandler) Delete(
	_ context.Context,
	_ ...discordgo.RequestOption,
) {
	m.deleteCalled = true
}

func TestUserCommandWorker_IdleTimeout(t *testing.T) {
	t.Parallel()
	worker := newUserWorker(&DisConcierge{}, &User{})
	expireAt := time.Now().Add(3 * time.Second)
	worker.limiter.IdleTimeout = time.Until(expireAt)
	worker.idleTimeoutCheckInterval = 500 * time.Millisecond

	startCh := make(chan struct{}, 1)

	ctx, cancel := context.WithTimeout(
		context.Background(),
		5*time.Until(expireAt),
	)
	t.Cleanup(
		func() {
			cancel()
		},
	)
	go worker.Run(ctx, startCh)

	select {
	case <-ctx.Done():
		t.Fatal("timed out waiting on worker")
	case stoppedAt := <-worker.stopped:
		assert.True(t, stoppedAt.After(expireAt))
	}
}
