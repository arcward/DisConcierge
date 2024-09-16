package disconcierge

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lmittmann/tint"
	"gorm.io/gorm/logger"
	"log/slog"
	"strings"
	"time"
)

const loggerNameKey = "logger"

func discordgoLoggerFunc(ctx context.Context, handler slog.Handler) func(
	msgL int,
	caller int,
	format string,
	args ...any,
) {
	log := slog.New(handler)
	return func(
		msgL int,
		_ int,
		format string,
		args ...any,
	) {
		level, ok := discordGoLogLevels[msgL]
		if !ok {
			level = slog.LevelInfo
		}
		log.LogAttrs(
			ctx,
			level,
			strings.ReplaceAll(fmt.Sprintf(format, args...), "\n", ""),
		)
	}
}

var (
	DBLogLevelInfo  = DBLogLevel(slog.LevelInfo.String())
	DBLogLevelWarn  = DBLogLevel(slog.LevelWarn.String())
	DBLogLevelError = DBLogLevel(slog.LevelError.String())
	DBLogLevelDebug = DBLogLevel(slog.LevelDebug.String())
)

type gormStructuredLogger struct {
	logger        *slog.Logger
	handler       slog.Handler
	SlowThreshold time.Duration
}

// DBLogLevel is a wrapper for slog.Level that implements
// the necessary methods for GORM to treat it as a custom type.
type DBLogLevel string

// Scan implements the sql.Scanner interface.
func (l *DBLogLevel) Scan(value any) error {
	switch v := value.(type) {
	case []byte:
		return l.parseLevel(string(v))
	case string:
		return l.parseLevel(v)
	default:
		return errors.New("invalid type for DBLogLevel")
	}
}

// Value implements the driver.Valuer interface.
func (l DBLogLevel) Value() (driver.Value, error) {
	return l.String(), nil
}

// GormDataType implements the gorm.GormDataTypeInterface interface.
func (DBLogLevel) GormDataType() string {
	return "string"
}

// MarshalJSON implements the json.Marshaller interface.
func (l DBLogLevel) MarshalJSON() ([]byte, error) {
	return json.Marshal(l.String())
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (l *DBLogLevel) UnmarshalJSON(data []byte) error {
	var levelString string
	if err := json.Unmarshal(data, &levelString); err != nil {
		return err
	}
	return l.parseLevel(levelString)
}

// String returns the string representation of the log level.
func (l DBLogLevel) String() string {
	return string(l)
}

// parseLevel parses a string into a DBLogLevel.
func (l *DBLogLevel) parseLevel(s string) error {
	switch strings.ToUpper(s) {
	case "DEBUG":
		*l = DBLogLevel(slog.LevelDebug.String())
	case "INFO":
		*l = DBLogLevel(slog.LevelInfo.String())
	case "WARN":
		*l = DBLogLevel(slog.LevelWarn.String())
	case "ERROR":
		*l = DBLogLevel(slog.LevelError.String())
	default:
		return fmt.Errorf("unknown log level: %s", s)
	}
	return nil
}

// Level returns the underlying slog.Level value.
func (l DBLogLevel) Level() slog.Level {
	switch strings.ToUpper(string(l)) {
	case "DEBUG":
		return slog.LevelDebug
	case "INFO":
		return slog.LevelInfo
	case "WARN":
		return slog.LevelWarn
	case "ERROR":
		return slog.LevelError
	default:
		slog.Default().Error(fmt.Sprintf("unknown log level '%s'", string(l)))
		return slog.LevelInfo
	}
}

// Set sets the log level from a string.
func (l *DBLogLevel) Set(s string) error {
	return l.parseLevel(s)
}

func newGORMLogger(
	handler slog.Handler,
	slowThreshold time.Duration,
) *gormStructuredLogger {
	return &gormStructuredLogger{
		logger: slog.New(handler).With(
			loggerNameKey,
			"gorm",
		), SlowThreshold: slowThreshold,
	}
}

func (g gormStructuredLogger) LogMode(_ logger.LogLevel) logger.Interface {
	return gormStructuredLogger{
		logger: slog.New(g.handler).With(
			loggerNameKey,
			"gorm",
		),
	}
}

func (g gormStructuredLogger) Info(
	ctx context.Context,
	s string,
	i ...any,
) {
	g.logger.InfoContext(ctx, fmt.Sprintf(s, i...))
}

func (g gormStructuredLogger) Warn(
	ctx context.Context,
	s string,
	i ...any,
) {
	g.logger.WarnContext(ctx, fmt.Sprintf(s, i...))
}

func (g gormStructuredLogger) Error(
	ctx context.Context,
	s string,
	i ...any,
) {
	g.logger.ErrorContext(ctx, fmt.Sprintf(s, i...))
}

func (g gormStructuredLogger) Trace(
	ctx context.Context,
	begin time.Time,
	fc func() (sql string, rowsAffected int64),
	err error,
) {
	elapsed := time.Since(begin)
	switch {
	case elapsed > g.SlowThreshold*time.Millisecond && g.SlowThreshold != 0:
		s, rowsAffected := fc()
		if rowsAffected == -1 {
			g.logger.Warn(
				"slow sql",
				"elapsed", elapsed.Seconds()*1e3,
				"threshold", g.SlowThreshold,
				"rows", "-",
				"sql", s,
				tint.Err(err),
			)
		} else {
			g.logger.Warn(
				"slow sql",
				"elapsed", elapsed.Seconds()*1e3,
				"threshold", g.SlowThreshold,
				"rows", rowsAffected,
				"sql", s,
				tint.Err(err),
			)
		}
	default:
		s, rowsAffected := fc()
		if rowsAffected == -1 {
			g.logger.DebugContext(
				ctx,
				"sql completed",
				"elapsed", time.Duration(float64(elapsed.Nanoseconds())/1e6),
				"threshold", g.SlowThreshold,
				"rows", "-",
				"sql", s,
				tint.Err(err),
			)
		} else {
			g.logger.DebugContext(
				ctx,
				"sql completed",
				"elapsed", time.Duration(float64(elapsed.Nanoseconds())/1e6),
				"threshold", g.SlowThreshold,
				"rows", rowsAffected,
				"sql", s,
				tint.Err(err),
			)
		}
	}
}
