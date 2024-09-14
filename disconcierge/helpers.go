package disconcierge

import (
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/bwmarrin/discordgo"
	"log/slog"
	"reflect"
	"regexp"
	"strings"
	"unicode/utf8"

	"context"
	"golang.org/x/crypto/argon2"
)

const loggerContextKey contextKey = "logger"

var (
	argon2Time    uint32 = 1
	argon2Memory  uint32 = 64 * 1024
	argon2Threads uint8  = 4
	argon2KeyLen  uint32 = 32
)

type contextKey string

// removeCitations removes OpenAI assistant response citation patterns
// from the input string.
func removeCitations(input string) string {
	pattern := `【\d+:\d+†[^】]+】`
	re := regexp.MustCompile(pattern)
	output := re.ReplaceAllString(input, "")
	return output
}

// minifyString reduces the size of the input string to a specified limit.
//
// This function attempts to minimize the input string by removing double newlines
// and asterisks. If the string is still too long, it truncates the string and appends
// a suffix indicating that the output limit was reached.
//
// Parameters:
//   - s: The input string to be minified.
//   - limit: The maximum length of the output string.
//
// Returns:
//   - string: The minified string, possibly truncated with a suffix.
func minifyString(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	s = strings.ReplaceAll(s, "\n\n", "\n")
	if len(s) <= limit {
		return s
	}
	s = strings.ReplaceAll(s, "**", "")
	if len(s) <= limit {
		return s
	}
	suffix := "\n\n**(output limit reached)**"
	return fmt.Sprintf(
		"%s%s",
		string([]rune(s)[:limit-1-len([]rune(suffix))]),
		suffix,
	)
}

// shortenString reduces the size of the input string to a specified limit.
//
// This function attempts to minimize the input string by removing double newlines
// and asterisks. If the string is still too long, it truncates the string and appends
// a suffix indicating that the output limit was reached.
//
// Parameters:
//   - s: The input string to be shortened.
//   - limit: The maximum length of the output string.
//
// Returns:
//   - string: The shortened string, possibly truncated with a suffix.
func shortenString(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	s = strings.ReplaceAll(s, "\n\n", "\n")
	if len(s) <= limit {
		return s
	}
	s = strings.ReplaceAll(s, "**", "")
	if len(s) <= limit {
		return s
	}
	suffix := "\n\n**(output limit reached)**"
	suffixChars := []rune(suffix)
	if limit-len(suffixChars) <= 0 {
		return strings.TrimSpace(string([]rune(s)[:limit]))
	}

	return strings.TrimSpace(
		fmt.Sprintf(
			"%s%s",
			string([]rune(s)[:limit-len([]rune(suffix))]),
			suffix,
		),
	)
}

// discordInteractionOptions extracts the interaction options from a
// Discord interaction.
//
// This function takes a Discord interaction and returns a map of the
// interaction's options, where the keys are the option names and the
// values are the corresponding option data.
func discordInteractionOptions(
	i *discordgo.InteractionCreate,
) map[string]*discordgo.ApplicationCommandInteractionDataOption {
	options := i.ApplicationCommandData().Options
	optionMap := make(
		map[string]*discordgo.ApplicationCommandInteractionDataOption,
		len(options),
	)
	for _, option := range options {
		optionMap[option.Name] = option
	}
	return optionMap
}

func getDiscordgoLogLevel(msgL int) slog.Level {
	var slogLevel slog.Level

	switch msgL {
	case discordgo.LogDebug:
		slogLevel = slog.LevelDebug
	case discordgo.LogError:
		slogLevel = slog.LevelError
	case discordgo.LogWarning:
		slogLevel = slog.LevelWarn
	case discordgo.LogInformational:
		slogLevel = slog.LevelInfo
	}
	return slogLevel
}

var discordGoLogLevels = map[int]slog.Level{
	discordgo.LogDebug:         slog.LevelDebug,
	discordgo.LogError:         slog.LevelError,
	discordgo.LogWarning:       slog.LevelWarn,
	discordgo.LogInformational: slog.LevelInfo,
}

func tlsConfig(certfile string, keyfile string, minVersion uint16) (
	*tls.Config,
	error,
) {
	certs := make([]tls.Certificate, 1)

	cert, err := tls.LoadX509KeyPair(
		certfile,
		keyfile,
	)
	if err != nil {
		return nil, err
	}
	certs[0] = cert
	return &tls.Config{
		Certificates: certs,
		MinVersion:   minVersion,
		ClientAuth:   tls.NoClientCert,
	}, nil
}

// structToSlogValue converts a struct to a slog.Value, using the struct's
// JSON tag as the key for each field, if set.
// If the `log` tag is set, the value specified will override the
// field's actual value. Ex: `log:"REDACTED"` will cause "REDACTED" to
// be shown as the field's value.
func structToSlogValue(v any) slog.Value {
	typ := reflect.TypeOf(v)
	if typ == nil {
		return slog.AnyValue(nil)
	}
	val := reflect.ValueOf(v)

	if typ.Kind() == reflect.Ptr {
		if val.IsNil() {
			return slog.AnyValue(nil)
		}
		val = val.Elem()
		typ = typ.Elem()
	}

	if typ.Kind() != reflect.Struct {
		return slog.AnyValue(v)
	}

	var groupAttrs []slog.Attr

	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		jsonTag, _, _ := strings.Cut(field.Tag.Get("json"), ",")

		if jsonTag == "" {
			jsonTag = field.Name
		}

		fv := val.Field(i)
		if !fv.CanInterface() {
			continue
		}

		logTag := field.Tag.Get("log")
		if logTag != "" {
			groupAttrs = append(
				groupAttrs,
				slog.Attr{Key: jsonTag, Value: slog.StringValue(logTag)},
			)
			continue
		}

		// skip struct values that are nil or empty
		skip := false
		switch fv.Kind() {
		case reflect.Ptr:
			if fv.IsNil() {
				skip = true
			}
		case reflect.Map, reflect.Slice:
			if fv.IsNil() || fv.Len() == 0 {
				skip = true
			}
		case reflect.String:
			if fv.String() == "" || fv.Len() == 0 {
				skip = true
			}
		}

		if skip {
			continue
		}

		fieldValue := fv.Interface()
		groupAttrs = append(
			groupAttrs,
			slog.Attr{Key: jsonTag, Value: structToSlogValue(fieldValue)},
		)
	}
	rv := slog.GroupValue(groupAttrs...)

	return rv
}

// WithLogger returns a new context with the given logger added.
func WithLogger(ctx context.Context, logger *slog.Logger) context.Context {
	var ctxLogger *slog.Logger
	if logger == nil {
		ctxLogger = slog.Default()
	} else {
		ctxLogger = logger
	}
	return context.WithValue(ctx, loggerContextKey, ctxLogger)
}

// ContextLogger returns a logger from the given context if one
// is present, and a boolean indicating whether a logger was found.
func ContextLogger(ctx context.Context) (*slog.Logger, bool) {
	logger, ok := ctx.Value(loggerContextKey).(*slog.Logger)
	return logger, ok
}

func chatCommandLogAttrs(c ChatCommand) []any {
	attrs := []any{
		"id", c.ID,
		columnUserID, c.UserID,
		columnChatCommandPriority, c.Priority,
		"custom_id", c.CustomID,
	}
	if c.Private {
		attrs = append(attrs, columnChatCommandClear, c.Private)
	}

	return attrs
}

func interactionLogAttrs(i discordgo.InteractionCreate) []any {
	logAttrs := []any{
		"id", i.ID,
		"type", i.Type.String(),
		"command_context", i.Context.String(),
	}
	if i.ChannelID != "" {
		logAttrs = append(logAttrs, "channel_id", i.ChannelID)
	}
	if i.GuildID != "" {
		logAttrs = append(logAttrs, "guild_id", i.GuildID)
	}
	if i.AppID != "" {
		logAttrs = append(logAttrs, "app_id", i.AppID)
	}

	return logAttrs
}

func userLogAttrs(u User) []any {
	return []any{
		"id", u.ID,
		"username", u.Username,
		"global_name", u.GlobalName,
	}
}

// truncate shortens the input string to a specified number of characters.
func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	runes := []rune(s)
	return string(runes[:n])
}

func derive64ByteKey(input string) []byte {
	hash := sha512.Sum512([]byte(input))
	return hash[:]
}

// hashPassword securely hashes a password using Argon2id
func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		argon2Time,
		argon2Memory,
		argon2Threads,
		argon2KeyLen,
	)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	// Format: $argon2id$v=19$m=65536,t=1,p=4$<salt>$<hash>
	encodedHash := fmt.Sprintf(
		"$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argon2Memory,
		argon2Time,
		argon2Threads,
		b64Salt,
		b64Hash,
	)

	return encodedHash, nil
}

// verifyPassword checks if the provided password matches the stored hash
func verifyPassword(storedHash, password string) (bool, error) {
	parts := strings.Split(storedHash, "$")
	if len(parts) != 6 {
		return false, errors.New("invalid hash format")
	}

	var memory, argonTime, threads int
	_, err := fmt.Sscanf(
		parts[3],
		"m=%d,t=%d,p=%d",
		&memory,
		&argonTime,
		&threads,
	)
	if err != nil {
		return false, errors.New("invalid hash format")
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, errors.New("invalid salt")
	}

	decodedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, errors.New("invalid hash")
	}

	hashToCompare := argon2.IDKey(
		[]byte(password),
		salt,
		uint32(argonTime),
		uint32(memory),
		uint8(threads),
		uint32(len(decodedHash)),
	)

	return subtle.ConstantTimeCompare(decodedHash, hashToCompare) == 1, nil
}

// chunkItems splits the input items into chunks of maxRowLength
func chunkItems[T any](maxRowLength int, items ...T) [][]T {
	var result [][]T
	for len(items) > 0 {
		end := maxRowLength
		if len(items) < maxRowLength {
			end = len(items)
		}
		result = append(result, items[:end])
		items = items[end:]
	}
	return result
}

func stringPointerValue(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
