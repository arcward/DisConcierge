package disconcierge

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/bwmarrin/discordgo"
	"github.com/lmittmann/tint"
	"github.com/sashabaranov/go-openai"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"log/slog"
	mathrand "math/rand"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

var (
	randomGenerator = mathrand.New(mathrand.NewSource(1))
)

func TestCustomID(t *testing.T) {
	reportType := UserFeedbackHallucinated
	customID, err := newCustomID(t, reportType)
	require.NoError(t, err)
	t.Logf("id: %s", customID)
	assert.Equal(
		t,
		fmt.Sprintf(
			"%s:%s",
			customID.ReportType,
			customID.ID,
		),
		customID.String(),
	)

	rv, err := decodeCustomID(customID.String())
	require.NoError(t, err)
	assert.Equal(t, rv.ReportType, reportType)
	assert.NotEmpty(t, rv.ID)
	t.Logf("%#v", rv)
	assert.Equal(t, 34, len(customID.String()))
}

func TestCustomID_Error(t *testing.T) {
	reportType := UserFeedbackHallucinated
	customID, err := newCustomID(t, reportType)
	require.NoError(t, err)
	t.Logf("id: %s", customID)
	assert.Equal(
		t,
		fmt.Sprintf(
			"%s:%s",
			customID.ReportType,
			customID.ID,
		),
		customID.String(),
	)
	badID := fmt.Sprintf("%s:%s", customID.String(), "foo")
	rv, err := decodeCustomID(badID)
	require.Error(t, err)
	assert.Empty(t, rv.ID)
}

func TestShortenString(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		limit    int
		expected string
	}{
		{
			name:     "String shorter than limit",
			input:    "Short string",
			limit:    20,
			expected: "Short string",
		},
		{
			name:     "String equal to limit",
			input:    "Exactly twenty chars",
			limit:    20,
			expected: "Exactly twenty chars",
		},
		{
			name:     "String with double newlines",
			input:    "Line 1\n\nLine 2\n\nLine 3",
			limit:    15,
			expected: "Line 1\nLine 2\nL",
		},
		{
			name:     "String with bold markdown",
			input:    "Some **bold** text here",
			limit:    15,
			expected: "Some bold text",
		},
	}

	for _, tc := range testCases {
		t.Run(
			tc.name, func(t *testing.T) {
				result := minifyString(tc.input, tc.limit)
				assert.Equal(t, tc.expected, result)
				assert.LessOrEqual(t, len(result), tc.limit)
			},
		)
	}
}

func TestGetDiscordgoLogLevel(t *testing.T) {
	testCases := []struct {
		name           string
		inputLogLevel  int
		expectedSLevel slog.Level
	}{
		{
			name:           "Debug level",
			inputLogLevel:  discordgo.LogDebug,
			expectedSLevel: slog.LevelDebug,
		},
		{
			name:           "Error level",
			inputLogLevel:  discordgo.LogError,
			expectedSLevel: slog.LevelError,
		},
		{
			name:           "Warning level",
			inputLogLevel:  discordgo.LogWarning,
			expectedSLevel: slog.LevelWarn,
		},
		{
			name:           "Informational level",
			inputLogLevel:  discordgo.LogInformational,
			expectedSLevel: slog.LevelInfo,
		},
		{
			name:           "Unknown level",
			inputLogLevel:  999,           // Some arbitrary number not matching any defined level
			expectedSLevel: slog.Level(0), // Default zero value for slog.Level
		},
	}

	for _, tc := range testCases {
		t.Run(
			tc.name, func(t *testing.T) {
				result := getDiscordgoLogLevel(tc.inputLogLevel)
				assert.Equal(
					t,
					tc.expectedSLevel,
					result,
					"Unexpected slog level for input %d",
					tc.inputLogLevel,
				)
			},
		)
	}
}

func TestHashPasswordAndVerify(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name     string
		password string
	}{
		{"Simple password", "password123"},
		{"Complex password", "C0mpl3x!P@ssw0rd"},
		{"Empty password", ""},
		{"Unicode password", "пароль123"},
		{"Very long password", strings.Repeat("a", 1000)},
	}

	for _, tc := range testCases {
		t.Run(
			tc.name, func(t *testing.T) {
				hash, err := HashPassword(tc.password)
				if err != nil {
					t.Fatalf("HashPassword failed: %v", err)
				}

				if !strings.HasPrefix(hash, "$argon2id$v=19$m=") {
					t.Errorf("Incorrect hash format: %s", hash)
				}

				// Test VerifyPassword with correct password
				valid, err := VerifyPassword(hash, tc.password)
				if err != nil {
					t.Fatalf("VerifyPassword failed: %v", err)
				}
				if !valid {
					t.Errorf("VerifyPassword returned false for correct password")
				}

				// Test VerifyPassword with incorrect password
				valid, err = VerifyPassword(hash, tc.password+"wrong")
				if err != nil {
					t.Fatalf("VerifyPassword failed: %v", err)
				}
				if valid {
					t.Errorf("VerifyPassword returned true for incorrect password")
				}
			},
		)
	}
}

func TestVerifyPassword_InvalidHash(t *testing.T) {
	invalidHashes := []string{
		"not a valid hash",
		"$argon2id$v=19$m=65536,t=1,p=4$invalidbase64$invalidbase64",
		"$argon2id$v=19$m=invalid,t=1,p=4$c29tZXNhbHQ$c29tZWhhc2g=",
	}

	for _, invalidHash := range invalidHashes {
		t.Run(
			invalidHash, func(t *testing.T) {
				_, err := VerifyPassword(invalidHash, "anypassword")
				if err == nil {
					t.Errorf(
						"VerifyPassword should have failed for invalid hash: %s",
						invalidHash,
					)
				}
			},
		)
	}
}

func TestHashPassword_Uniqueness(t *testing.T) {
	password := "samepassword"
	hash1, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}
	hash2, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	if hash1 == hash2 {
		t.Errorf("HashPassword should generate unique hashes for the same password")
	}
}

func BenchmarkHashPassword(b *testing.B) {
	password := "benchmark_password"
	for i := 0; i < b.N; i++ {
		_, err := HashPassword(password)
		if err != nil {
			b.Fatalf("HashPassword failed: %v", err)
		}
	}
}

func BenchmarkVerifyPassword(b *testing.B) {
	password := "benchmark_password"
	hash, err := HashPassword(password)
	if err != nil {
		b.Fatalf("HashPassword failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := VerifyPassword(hash, password)
		if err != nil {
			b.Fatalf("VerifyPassword failed: %v", err)
		}
	}
}

func TestChunkItems(t *testing.T) {
	tests := []struct {
		name           string
		maxRowLength   int
		items          []int
		expectedResult [][]int
	}{
		{
			name:           "exactly divisible",
			maxRowLength:   3,
			items:          []int{1, 2, 3, 4, 5, 6, 7, 8, 9},
			expectedResult: [][]int{{1, 2, 3}, {4, 5, 6}, {7, 8, 9}},
		},
		{
			name:           "not exactly divisible",
			maxRowLength:   4,
			items:          []int{1, 2, 3, 4, 5, 6, 7},
			expectedResult: [][]int{{1, 2, 3, 4}, {5, 6, 7}},
		},
		{
			name:           "single item per row",
			maxRowLength:   1,
			items:          []int{1, 2, 3},
			expectedResult: [][]int{{1}, {2}, {3}},
		},
		{
			name:           "max row length greater than items",
			maxRowLength:   5,
			items:          []int{1, 2, 3},
			expectedResult: [][]int{{1, 2, 3}},
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				result := chunkItems(tt.maxRowLength, tt.items...)

				if !reflect.DeepEqual(result, tt.expectedResult) {
					t.Errorf(
						"expected %#v, got %#v",
						tt.expectedResult,
						result,
					)
				}
			},
		)
	}
}

func TestPollDuration(t *testing.T) {
	tests := []struct {
		name     string
		input    float64
		expected time.Duration
	}{
		{"Quarter Second", 0.25, 250 * time.Millisecond},
		{"Half Second", 0.5, 500 * time.Millisecond},
		{"One Second", 1, 1 * time.Second},
		{"One and a Half Seconds", 1.5, 1500 * time.Millisecond},
		{"Two Seconds", 2, 2 * time.Second},
		{"Small Fraction", 0.1, 100 * time.Millisecond},
		{"Large Number", 3600, 1 * time.Hour},
		{"Zero", 0, 0},
		{"Negative Number", -1, -1 * time.Second},
	}

	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				result := pollInterval(tt.input)
				if result != tt.expected {
					t.Errorf(
						"PollDuration(%f) = %v; want %v",
						tt.input,
						result,
						tt.expected,
					)
				}
			},
		)
	}
}

func TestGenerateRandomHexString(t *testing.T) {
	length := 32
	s, err := generateRandomHexString(length)
	require.NoError(t, err)
	assert.Len(t, s, length)
}

func TestIsShutdownErr(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())

	cancel(NewShutdownError("received shutdown signal"))
	cc, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.com", http.NoBody)
	require.NoError(t, err)
	rv, err := http.DefaultClient.Do(cc)
	if err != nil && rv != nil && rv.Body != nil {
		t.Cleanup(
			func() {
				_ = rv.Body.Close()
			},
		)
	}
	assert.True(t, isShutdownErr(ctx, err))
}

// DefaultTestRuntimeConfig returns a default RuntimeConfig for testing purposes.
// It primarily sets more verbose log levels and shorter poll intervals.
func DefaultTestRuntimeConfig(t testing.TB) *RuntimeConfig {
	t.Helper()
	cfg := DefaultRuntimeConfig()

	cfg.AssistantPollInterval = Duration{250 * time.Millisecond}
	cfg.AssistantMaxPollInterval = Duration{250 * time.Millisecond}

	logLevel := DBLogLevelWarn

	cfg.LogLevel = logLevel
	cfg.DiscordLogLevel = logLevel
	cfg.DatabaseLogLevel = logLevel
	cfg.DiscordGoLogLevel = logLevel
	cfg.APILogLevel = logLevel
	cfg.OpenAILogLevel = logLevel
	cfg.RecoverPanic = false
	cfg.AdminUsername = fmt.Sprintf("user_%s", t.Name())
	password := fmt.Sprintf("password_%s", t.Name())
	hashedPassword, err := HashPassword(password)
	require.NoError(t, err)
	cfg.AdminPassword = hashedPassword
	return &cfg
}

// commandData holds common IDs, generated based on the current test
type commandData struct {
	RunID                string
	ThreadID             string
	InteractionID        string
	StepID               string
	MessageID            string
	UserID               string
	AssistantID          string
	Username             string
	CustomID             string
	OpenAIToken          string
	DiscordToken         string
	DiscordApplicationID string
	t                    testing.TB
}

func newCommandData(t testing.TB) commandData {
	t.Helper()
	return commandData{
		ThreadID:             fmt.Sprintf("thread_%s", t.Name()),
		RunID:                fmt.Sprintf("run_%s", t.Name()),
		InteractionID:        fmt.Sprintf("i_%s", t.Name()),
		MessageID:            fmt.Sprintf("msg_%s", t.Name()),
		StepID:               fmt.Sprintf("step_%s", t.Name()),
		UserID:               fmt.Sprintf("userid_%s", t.Name()),
		Username:             fmt.Sprintf("user_%s", t.Name()),
		CustomID:             fmt.Sprintf("customid_%s", t.Name()),
		AssistantID:          fmt.Sprintf("asst_%s", t.Name()),
		OpenAIToken:          fmt.Sprintf("openai_token-%s", t.Name()),
		DiscordToken:         fmt.Sprintf("discord_token-%s", t.Name()),
		DiscordApplicationID: fmt.Sprintf("discord_app_id-%s", t.Name()),
		t:                    t,
	}
}

func (c commandData) newChatCommandInteraction(prompt string) *discordgo.InteractionCreate {
	c.t.Helper()

	return &discordgo.InteractionCreate{
		Interaction: &discordgo.Interaction{
			Type: discordgo.InteractionApplicationCommand,
			ID:   c.InteractionID,
			User: &discordgo.User{
				ID:         c.UserID,
				Username:   c.Username,
				GlobalName: c.Username,
			},
			Context: discordgo.InteractionContextBotDM,
			Data: discordgo.ApplicationCommandInteractionData{
				CommandType: discordgo.ChatApplicationCommand,
				Name:        DiscordSlashCommandChat,
				Options: []*discordgo.ApplicationCommandInteractionDataOption{
					{
						Name:  chatCommandQuestionOption,
						Type:  discordgo.ApplicationCommandOptionString,
						Value: prompt,
					},
				},
			},
		},
	}
}

func (c commandData) populateChatCommand(chatCommand *ChatCommand) *ChatCommand {
	c.t.Helper()

	interaction := c.newChatCommandInteraction(c.t.Name())
	u, err := NewUser(*interaction.User)
	require.NoError(c.t, err)

	i := NewUserInteraction(interaction, u)

	if chatCommand == nil {
		chatCommand, err = NewChatCommand(u, interaction)
		require.NoError(c.t, err)
	}

	interactionData, err := json.Marshal(i)
	require.NoError(c.t, err)
	chatCommand.Content = string(interactionData)
	chatCommand.ThreadID = c.ThreadID
	chatCommand.MessageID = c.MessageID
	chatCommand.RunID = c.RunID
	chatCommand.CustomID = c.CustomID
	chatCommand.UserID = u.ID
	chatCommand.User = u
	require.Equal(c.t, interaction.User.ID, u.ID)
	require.Equal(c.t, interaction.User.ID, c.UserID)
	chatCommand.InteractionID = c.InteractionID
	chatCommand.Token = c.DiscordToken
	chatCommand.TokenExpires = time.Now().UTC().Add(15 * time.Minute).UnixMilli()
	chatCommand.AppID = c.DiscordApplicationID
	chatCommand.CommandContext = discordgo.InteractionContextBotDM.String()

	return chatCommand
}

// Helper functions to create pointers
func boolPtr(b bool) *bool                                                          { return &b }
func strPtr(s string) *string                                                       { return &s }
func intPtr(i int) *int                                                             { return &i }
func float32Ptr(f float32) *float32                                                 { return &f }
func durationPtr(d time.Duration) *Duration                                         { return &Duration{d} }
func truncationStrategyPtr(ts openai.TruncationStrategy) *openai.TruncationStrategy { return &ts }
func dbLogLevelPtr(level DBLogLevel) *DBLogLevel                                    { return &level }

func newCustomID(t testing.TB, reportType FeedbackButtonType) (
	CustomID,
	error,
) {
	t.Helper()

	customID := CustomID{ReportType: reportType}
	randomID, err := generateRandomHexString(32)
	if err != nil {
		return customID, err
	}
	customID.ID = randomID
	if len(customID.ID) > 100 {
		return customID, fmt.Errorf("custom_id too long")
	}
	return customID, nil
}

// gormDB creates a temporary SQLite database for testing purposes.
//
// The function creates a temporary directory, constructs a SQLite database file path within it,
// and initializes the database using the CreateDB function. If there is an error during database
// creation, the test fails with a fatal error.
func gormDB(t testing.TB) *gorm.DB {
	t.Helper()
	tmpdir := t.TempDir()
	dbfile := filepath.Join(tmpdir, fmt.Sprintf("%s.sqlite3", t.Name()))

	db, err := CreateDB(context.Background(), "sqlite", dbfile)
	if err != nil {
		t.Fatalf("error creating db: %v", err)
	}
	return db
}

// setLoggers configures the loggers for the DisConcierge bot and its components.
//
// The function sets up loggers with test-specific attributes and reverts
// the loggers to their original state when the test finishes.
func setLoggers(t testing.TB, bot *DisConcierge) {
	t.Helper()

	originalDefault := slog.Default()
	slog.SetDefault(originalDefault.With("test", t.Name()))
	t.Cleanup(
		func() {
			slog.SetDefault(originalDefault)
		},
	)

	baseLogger := bot.logger
	bot.logger = baseLogger.With("test", t.Name())
	bot.openai.logger = bot.openai.logger.With("test", t.Name())
	bot.discord.logger = bot.discord.logger.With("test", t.Name())
	bot.api.logger = bot.api.logger.With("test", t.Name())
	dbLogHandler := tint.NewHandler(
		os.Stdout, &tint.Options{
			Level:     bot.config.DatabaseLogLevel,
			AddSource: true,
		},
	).WithAttrs([]slog.Attr{slog.String("test", t.Name())})
	if bot.db != nil {
		bot.db.Logger = newGORMLogger(
			dbLogHandler,
			bot.config.DatabaseSlowThreshold,
		)
	}

	discordgo.Logger = discordgoLoggerFunc(context.Background(), dbLogHandler)
	bot.requestQueue.logger = bot.requestQueue.logger.With("test", t.Name())
}
