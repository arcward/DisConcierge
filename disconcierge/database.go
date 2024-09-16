package disconcierge

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"github.com/bwmarrin/discordgo"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lmittmann/tint"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	customIDFormat                            = "%s:%s"
	dbTypeSQLite                              = "sqlite"
	dbTypePostgres                            = "postgres"
	postgresNotifyChannelRuntimeConfigUpdated = "disconcierge_reload_runtime_config"
	postgresNotifyChannelReloadUserCache      = "disconcierge_reload_user_cache"
	postgresNotifyChannelUserUpdated          = "disconcierge_user_updated"
	postgresNotifyChannelStop                 = "disconcierge_stop"
	recordSeparator                           = string(rune(30))
)

var (
	sqliteMaxOpenConns    = 1
	sqliteMaxIdleConns    = 1
	sqliteMaxConnLifetime = 5 * time.Minute
	sqliteExecPragma      = []string{
		"pragma journal_mode=WAL;",
		"pragma synchronous = normal;",
		"pragma temp_store = memory;",
		"pragma foreign_keys = ON;",
		"pragma mmap_size = 8000000000;",
	}
	dbOperationTimeout    = 30 * time.Second
	dbNotifierSendTimeout = 15 * time.Second
)

// ModelUnixTime is an embeddable model with Unix timestamps for
// creation, update, and deletion.
//
// Fields:
//   - CreatedAt: The timestamp when the record was created, stored in milliseconds.
//   - UpdatedAt: The timestamp when the record was last updated, stored in milliseconds.
//   - DeletedAt: The timestamp when the record was deleted, stored as a gorm.DeletedAt type.
type ModelUnixTime struct {
	CreatedAt int64          `gorm:"autoCreateTime:milli" json:"created_at,omitempty"`
	UpdatedAt int64          `gorm:"autoUpdateTime:milli" json:"updated_at,omitempty"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`
}

type ModelStringID struct {
	ID string `gorm:"primaryKey" json:"id"`
}

type ModelUintID struct {
	ID uint `gorm:"primaryKey" json:"id"`
}

// database represents a database connection and provides methods for
// interacting with the database.
//
// It encapsulates the GORM database connection, logging, user caching, and
// concurrency controls.
// The struct implements the DBI interface, providing a consistent API for
// database operations.
//
// Fields:
//   - db: The underlying GORM database connection.
//   - mu: Mutex for synchronizing access to the database in non-concurrent write mode.
//   - logger: Logger for database-related events.
//   - userCache: In-memory cache of User objects, keyed by user ID.
//   - cacheMu: Mutex for synchronizing access to the user cache.
//   - enableConcurrentWrites: Flag to enable or disable concurrent write operations.
//
// The database struct provides methods for CRUD operations, transaction management,
// and user-related operations. It also handles caching of user data for improved performance.
//
// Usage:
//
//	db := NewDatabase(gormDB, logger, true)
//	user := db.GetUser("123456789")
//	db.Create(newObject)
//
// The database struct is designed to be thread-safe when concurrent writes are disabled,
// using mutex locks to prevent race conditions during database operations.
type database struct {
	db                     *gorm.DB
	mu                     sync.Mutex
	logger                 *slog.Logger
	userCache              map[string]*User
	cacheMu                sync.Mutex
	enableConcurrentWrites bool
}

// NewDatabase initializes a new database instance.
//
// This function creates a new database object with the provided GORM database connection,
// logger, and a flag to enable or disable concurrent writes. It sets up the user cache
// and logger for the database operations.
//
// Parameters:
//   - db: A pointer to the GORM database connection.
//   - log: A pointer to the slog.Logger instance for logging events.
//     If nil, a default logger is used.
//   - enableConcurrentWrites: A boolean flag to enable or disable concurrent writes.
//
// Returns:
//   - DBI: An interface for database operations.
func NewDatabase(
	db *gorm.DB,
	log *slog.Logger,
	enableConcurrentWrites bool,
) DBI {
	if log == nil {
		log = slog.Default()
	}
	d := &database{
		db:                     db,
		userCache:              map[string]*User{},
		logger:                 log.With(loggerNameKey, "writedb"),
		enableConcurrentWrites: enableConcurrentWrites,
	}
	return d
}

func (d *database) UserCache() map[string]*User {
	return d.userCache
}

func (d *database) UserCacheLock() {
	d.cacheMu.Lock()
}

func (d *database) UserCacheUnlock() {
	d.cacheMu.Unlock()
}

func (d *database) DB() *gorm.DB {
	return d.db
}

func (d *database) Lock() {
	if d.enableConcurrentWrites {
		return
	}
	d.mu.Lock()
}

func (d *database) Unlock() {
	if d.enableConcurrentWrites {
		return
	}
	d.mu.Unlock()
}

// LoadUsers returns a slice of [User] records for users that have
// been seen in the last 24 hours, or who do not have [User.LastSeen] set.
func (d *database) LoadUsers() []User {
	d.userCache = map[string]*User{}

	var users []User
	_ = d.db.Omit(columnUserContent).Where(
		"last_seen is null OR last_seen = 0 OR last_seen >= ?",
		time.Now().Add(-24*time.Hour).UnixMilli(),
	).Find(&users)
	for i := 0; i < len(users); i++ {
		u := users[i]
		d.userCache[u.ID] = &u
	}
	return users
}

func (d *database) GetUser(userID string) *User {
	d.cacheMu.Lock()
	defer d.cacheMu.Unlock()
	return d.userCache[userID]
}

func (d *database) ReloadUser(userID string) *User {
	d.cacheMu.Lock()
	defer d.cacheMu.Unlock()
	var user User
	if err := d.db.Where("id = ?", userID).Last(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			delete(d.userCache, userID)
		}
		return nil
	}
	d.userCache[userID] = &user

	return &user
}

// GetOrCreateUser retrieves a user from the cache or the database,
// and creates a new user if one does not exist.
func (d *database) GetOrCreateUser(
	ctx context.Context,
	dc *DisConcierge,
	u discordgo.User,
) (*User, bool, error) {
	d.cacheMu.Lock()
	defer d.cacheMu.Unlock()

	log, ok := ContextLogger(ctx)
	if log == nil || !ok {
		log = slog.Default()
	}

	if user, cachedUser := d.userCache[u.ID]; cachedUser {
		// FIXME This isn't particularly concurrency-safe, as the cached
		//  record may be read by another goroutine while we're updating it.
		log.InfoContext(ctx, "found existing user", "user", user)
		user.LastSeen = time.Now().UTC().UnixMilli()
		updates := map[string]any{columnUserLastSeen: user.LastSeen}

		if user.userChangedDiscordUsername(u) {
			log.Info(
				"user changed username since last seen",
				slog.Group(
					"old",
					"username", user.Username,
					"global_name", user.GlobalName,
				),
				slog.Group(
					"new",
					"username", u.Username,
					"global_name", u.GlobalName,
				),
			)
			user.Username = u.Username
			user.GlobalName = u.GlobalName
			updates[columnUserUsername] = u.Username
			updates[columnUserGlobalName] = u.GlobalName
		}
		if _, err := d.Updates(context.TODO(), user, updates); err != nil {
			log.Error("error updating user", "user", user, tint.Err(err))
		}
		return user, false, nil
	}

	log.Info("creating new user", "user", u)
	user, _ := NewUser(u)
	if dc != nil {
		config := dc.RuntimeConfig()
		user.UserChatCommandLimit6h = config.UserChatCommandLimit6h
		user.OpenAIRunSettings = config.OpenAIRunSettings
	}

	log.InfoContext(ctx, "creating new user", "user", user)

	_, err := d.Create(ctx, user)
	if err != nil {
		log.Error("error creating user", "user", user, tint.Err(err))
		return nil, true, err
	}

	d.userCache[u.ID] = user
	return user, true, nil
}

func (d *database) Create(ctx context.Context, value any, omit ...string) (
	rowsAffected int64,
	err error,
) {
	if !d.enableConcurrentWrites {
		d.mu.Lock()
		defer d.mu.Unlock()
	}
	db := d.db
	_, ok := ctx.Deadline()
	if !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, dbOperationTimeout)
		defer cancel()
	}
	db = db.WithContext(ctx)

	if len(omit) > 0 {
		rv := db.Omit(omit...).Create(value)
		return rv.RowsAffected, rv.Error
	}
	rv := db.Create(value)
	return rv.RowsAffected, rv.Error
}

func (d *database) Updates(ctx context.Context, model, values any) (
	rowsAffected int64,
	err error,
) {
	if !d.enableConcurrentWrites {
		d.mu.Lock()
		defer d.mu.Unlock()
	}
	_, ok := ctx.Deadline()
	if !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, dbOperationTimeout)
		defer cancel()
	}
	rv := d.db.WithContext(ctx).Model(model).Updates(values)
	return rv.RowsAffected, rv.Error
}

func (d *database) ChatCommandUpdates(
	ctx context.Context,
	model *ChatCommand,
	values any,
) (rowsAffected int64, err error) {
	return d.Updates(ctx, model, values)
}

func (d *database) Transaction(
	ctx context.Context,
	fc func(tx *gorm.DB) error,
	opts ...*sql.TxOptions,
) (err error) {
	if !d.enableConcurrentWrites {
		d.mu.Lock()
		defer d.mu.Unlock()
	}
	_, ok := ctx.Deadline()
	if !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, dbOperationTimeout)
		defer cancel()
	}
	rv := d.db.WithContext(ctx).Transaction(fc, opts...)
	return rv
}

func (d *database) Save(ctx context.Context, value any, omit ...string) (
	rowsAffected int64,
	err error,
) {
	if !d.enableConcurrentWrites {
		d.mu.Lock()
		defer d.mu.Unlock()
	}
	_, ok := ctx.Deadline()
	if !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, dbOperationTimeout)
		defer cancel()
	}

	if len(omit) > 0 {
		rv := d.db.WithContext(ctx).Omit(omit...).Save(value)
		return rv.RowsAffected, rv.Error
	}
	rv := d.db.WithContext(ctx).Save(value)
	return rv.RowsAffected, rv.Error
}

func (d *database) Update(
	ctx context.Context,
	model any,
	column string,
	value any,
) (rowsAffected int64, err error) {
	if !d.enableConcurrentWrites {
		d.mu.Lock()
		defer d.mu.Unlock()
	}
	_, ok := ctx.Deadline()
	if !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, dbOperationTimeout)
		defer cancel()
	}

	rv := d.db.WithContext(ctx).Model(model).Update(column, value)
	return rv.RowsAffected, rv.Error
}

func (d *database) UpdatesWhere(
	ctx context.Context,
	model any,
	values map[string]any,
	query any,
	conds ...any,
) (rowsAffected int64, err error) {
	if !d.enableConcurrentWrites {
		d.mu.Lock()
		defer d.mu.Unlock()
	}
	_, ok := ctx.Deadline()
	if !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, dbOperationTimeout)
		defer cancel()
	}

	rv := d.db.WithContext(ctx).Model(model).Where(query, conds...).Updates(values)
	return rv.RowsAffected, rv.Error
}

func (d *database) Delete(
	value any,
	conds ...any,
) (rowsAffected int64, err error) {
	if !d.enableConcurrentWrites {
		d.mu.Lock()
		defer d.mu.Unlock()
	}
	rv := d.db.Delete(value, conds...)
	return rv.RowsAffected, rv.Error
}

// Duration is a wrapper for time.Duration that implements
// SQL Scanner and Valuer interfaces for GORM.
type Duration struct {
	time.Duration
}

// Scan implements the sql.Scanner interface.
func (d *Duration) Scan(value any) error {
	switch v := value.(type) {
	case []byte:
		return d.parse(string(v))
	case string:
		return d.parse(v)
	default:
		return fmt.Errorf("unexpected type for Duration: %T", value)
	}
}

// Value implements the driver.Valuer interface.
func (d Duration) Value() (driver.Value, error) {
	return d.String(), nil
}

func (d *Duration) parse(value string) error {
	duration, err := time.ParseDuration(value)
	if err != nil {
		return err
	}
	d.Duration = duration
	return nil
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (d *Duration) UnmarshalJSON(b []byte) error {
	s := string(b)
	if s == "null" {
		return nil
	}
	// Remove quotes
	s = s[1 : len(s)-1]
	return d.parse(s)
}

// MarshalJSON implements the json.Marshaller interface.
func (d Duration) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`%q`, d.String())), nil
}

// GormDataType is used by GORM to determine the default data type for a field.
func (Duration) GormDataType() string {
	return "string"
}

// DBI defines the interface for database operations. This is here primarily
// to enable mocking of the database operations for testing.
// [database] implements this interface for 'real' DB operations.
type DBI interface {
	// UserCacheLock locks the in-memory User cache
	UserCacheLock()

	// UserCacheUnlock unlocks the in-memory User cache
	UserCacheUnlock()

	// UserCache returns the in-memory cache of User objects
	UserCache() map[string]*User

	Lock()
	Unlock()

	DB() *gorm.DB
	LoadUsers() []User
	GetUser(userID string) *User
	ReloadUser(userID string) *User
	GetOrCreateUser(ctx context.Context, dc *DisConcierge, u discordgo.User) (*User, bool, error)
	Create(ctx context.Context, value any, omit ...string) (rowsAffected int64, err error)
	Updates(ctx context.Context, model any, values any) (rowsAffected int64, err error)
	Delete(value any, conds ...any) (rowsAffected int64, err error)
	ChatCommandUpdates(ctx context.Context, model *ChatCommand, values any) (
		rowsAffected int64,
		err error,
	)
	Transaction(
		ctx context.Context,
		fc func(tx *gorm.DB) error,
		opts ...*sql.TxOptions,
	) (err error)
	Save(ctx context.Context, value any, omit ...string) (rowsAffected int64, err error)
	Update(ctx context.Context, model any, column string, value any) (
		rowsAffected int64,
		err error,
	)
	UpdatesWhere(
		ctx context.Context,
		model any,
		values map[string]any,
		query any,
		conds ...any,
	) (rowsAffected int64, err error)
}

// CreateDB initializes and returns a GORM database connection based on the specified database type.
// It also performs auto-migration for the specified models.
//
// Parameters:
//   - ctx: The context for the database operations.
//   - databaseType: The type of the database, must be 'sqlite' or 'postgres'.
//   - database: The database connection string, or SQLite file path.
//
// Returns:
//   - *gorm.DB: A pointer to the initialized GORM database connection.
//   - error: An error object if any error occurs during the initialization or migration.
func CreateDB(ctx context.Context, databaseType string, database string) (*gorm.DB, error) {
	handler := tint.NewHandler(
		os.Stdout,
		&tint.Options{
			Level:     slog.LevelWarn,
			AddSource: true,
		},
	)

	gormLogger := newGORMLogger(handler, 500*time.Millisecond)
	dbLogger := slog.New(handler)

	dbLogger.InfoContext(
		ctx,
		"Initializing database",
		"database_type", databaseType,
		"database", database,
	)
	db, err := getDB(databaseType, database, gormLogger)
	if err != nil {
		return db, err
	}

	txn := db.WithContext(ctx).Begin()

	mg := txn.Migrator()
	err = mg.AutoMigrate(
		&OpenAICreateThread{},
		&OpenAICreateMessage{},
		&OpenAICreateRun{},
		&OpenAIRetrieveRun{},
		&OpenAIListMessages{},
		&OpenAIListRunSteps{},
		&User{},
		&ChatCommand{},
		&ClearCommand{},
		&UserFeedback{},
		&RuntimeConfig{},
		&InteractionLog{},
		&DiscordMessage{},
	)
	if err != nil {
		return db, err
	}

	commitErr := txn.Commit().Error
	if commitErr != nil {
		return db, err
	}

	return db, nil
}

// getDB initializes and returns a GORM database connection based on the
// specified database type.
//
// Parameters:
//   - databaseType: Must be 'sqlite' or 'postgres'
//   - database: Database connection string, or SQLite file path.
//   - gormLogger: A pointer to a gormStructuredLogger instance for
//     logging database operations.
func getDB(
	databaseType string,
	database string,
	gormLogger *gormStructuredLogger,
) (*gorm.DB, error) {
	switch databaseType {
	case dbTypeSQLite:
		parentDir := filepath.Dir(database)
		if parentDir != "" {
			if err := os.MkdirAll(parentDir, 0755); err != nil {
				if !errors.Is(err, os.ErrExist) {
					return nil, err
				}
			}
		}
		return gorm.Open(
			sqlite.Open(database),
			&gorm.Config{
				Logger: gormLogger,
				NowFunc: func() time.Time {
					return time.Now().UTC()
				},
			},
		)
	case dbTypePostgres:
		return gorm.Open(
			postgres.Open(database), &gorm.Config{
				Logger: gormLogger,
				NowFunc: func() time.Time {
					return time.Now().UTC()
				},
			},
		)
	default:
		return nil, fmt.Errorf(
			"unsupported database type: %s (must be %q or %q)",
			databaseType, dbTypeSQLite, dbTypePostgres,
		)
	}
}

// DBNotifier defines the interface for notifying bot instances of database
// changes and other events.
// TODO there's a cleaner way to implement this notifier stuff
type DBNotifier interface {
	UserCacheChannelName() string

	// ReloadUserCache sends a notification to bot instances to fully
	// reload their user cache
	ReloadUserCache(context.Context) bool

	RuntimeConfigChannelName() string

	// ReloadRuntimeConfig sends a notification to bot instances to
	// reload their runtime configuration from the DB
	ReloadRuntimeConfig(context.Context) bool

	UserUpdateChannelName() string

	// UserUpdated sends a notification to bot instances that a user
	// record has been updated, and should be reloaded.
	UserUpdated(ctx context.Context, userID string) bool

	StopChannelName() string

	// Stop sends a shutdown signal to all bots
	Stop(context.Context) bool

	// ID returns the identifier for this notifier. DBNotifier instances
	// should use this ID to filter out their own notifications.
	ID() string
	Listen(ctx context.Context, channel string) error
}

func newDBNotifier(d *DisConcierge) (DBNotifier, error) {
	notifyID, err := generateRandomHexString(16)
	if err != nil {
		return nil, err
	}
	log := d.logger.With(loggerNameKey, "db_notifier")
	var notifier DBNotifier
	switch d.config.DatabaseType {
	case dbTypeSQLite:
		notifier = &sqliteNotifier{
			logger:         log,
			d:              d,
			sqliteNotifyID: notifyID,
		}
	case dbTypePostgres:
		notifier = &postgresNotifier{
			d:          d,
			logger:     log,
			pgNotifyID: notifyID,
		}
	default:
		return nil, errors.New("invalid database type")
	}
	return notifier, nil
}

type sqliteNotifier struct {
	logger         *slog.Logger
	d              *DisConcierge
	sqliteNotifyID string
}

func (s *sqliteNotifier) Listen(_ context.Context, channel string) error {
	s.logger.Debug("listener called", "channel", channel)
	return nil
}

func (sqliteNotifier) StopChannelName() string {
	return ""
}

func (s *sqliteNotifier) Stop(ctx context.Context) bool {
	s.logger.Info("notifying stop signal")
	select {
	case s.d.signalStop <- struct{}{}:
	//
	case <-ctx.Done():
		s.logger.Warn("timeout sending stop signal")
		return false
	}
	return true
}

func (sqliteNotifier) UserUpdateChannelName() string {
	return ""
}

func (s *sqliteNotifier) UserUpdated(ctx context.Context, userID string) bool {
	s.logger.Info("got user update notification", "user_id", userID)
	select {
	case s.d.triggerUserUpdatedRefreshCh <- userID:
	//
	case <-ctx.Done():
		s.logger.Warn("timeout sending user refresh", "user_id", userID)
		return false
	}
	return true
}

func (s *sqliteNotifier) ID() string {
	return s.sqliteNotifyID
}

func (s *sqliteNotifier) ReloadRuntimeConfig(ctx context.Context) bool {
	s.logger.Info("got runtime config reload notification")
	select {
	case s.d.triggerRuntimeConfigRefreshCh <- true:
	//
	case <-ctx.Done():
		s.logger.Warn("timeout sending user cache refresh signal")
		return false
	}
	return true
}

func (s *sqliteNotifier) ReloadUserCache(ctx context.Context) bool {
	s.logger.Info("got user cache reload notification")
	select {
	case s.d.triggerUserCacheRefreshCh <- true:
	//
	case <-ctx.Done():
		s.logger.Warn("timeout sending user cache refresh signal")
	}
	return true
}

func (sqliteNotifier) UserCacheChannelName() string {
	return ""
}

func (sqliteNotifier) RuntimeConfigChannelName() string {
	return ""
}

type postgresNotifier struct {
	d          *DisConcierge
	logger     *slog.Logger
	pgNotifyID string
}

func (postgresNotifier) UserCacheChannelName() string {
	return postgresNotifyChannelReloadUserCache
}

func (postgresNotifier) RuntimeConfigChannelName() string {
	return postgresNotifyChannelRuntimeConfigUpdated
}

func (p *postgresNotifier) ID() string {
	return p.pgNotifyID
}

func (p *postgresNotifier) DB() DBI {
	return p.d.writeDB
}

func (postgresNotifier) UserUpdateChannelName() string {
	return postgresNotifyChannelUserUpdated
}

func (postgresNotifier) StopChannelName() string {
	return postgresNotifyChannelStop
}

func (p *postgresNotifier) Stop(ctx context.Context) bool {
	var sent bool

	notifyErr := p.d.writeDB.DB().WithContext(ctx).Exec(
		"SELECT pg_notify(?, ?)",
		p.StopChannelName(),
		p.ID(),
	).Error
	if notifyErr != nil {
		p.logger.ErrorContext(ctx, "Error sending NOTIFY to stop bot", tint.Err(notifyErr))
	} else {
		p.logger.Info("sent stop signal", "pg_notify_id", p.ID())
		sent = true
	}

	return sent
}

func (p *postgresNotifier) Listen(ctx context.Context, channel string) error {
	p.logger.Info("starting db listener", "channel", channel)

	config, err := pgxpool.ParseConfig(p.d.config.Database)
	if err != nil {
		p.logger.ErrorContext(ctx, "Error parsing database config", tint.Err(err))
		return err
	}

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		p.logger.ErrorContext(ctx, "Error creating connection pool", tint.Err(err))
		return err
	}
	defer pool.Close()

	// Start listening for notifications
	conn, err := pool.Acquire(ctx)
	if err != nil {
		p.logger.ErrorContext(ctx, "Error acquiring connection", tint.Err(err))
		return err
	}
	defer conn.Release()

	_, err = conn.Exec(ctx, fmt.Sprintf("LISTEN %s", channel))
	if err != nil {
		p.logger.ErrorContext(ctx, "Error setting up listener", tint.Err(err))
		return err
	}
	logger := p.logger.With("channel", channel)
	logger.InfoContext(ctx, "Started listening on channel")

	for ctx.Err() == nil {
		notification, e := conn.Conn().WaitForNotification(ctx)
		if e != nil {
			logger.ErrorContext(ctx, "Error waiting for notification", tint.Err(err))
			time.Sleep(5 * time.Second) // Wait before retrying
			continue
		}
		if notification.Payload == p.ID() {
			logger.Info(
				"Received notification from self, ignoring",
				"payload",
				notification.Payload,
			)
			continue
		}

		switch channel {
		case p.UserCacheChannelName():
			logger.InfoContext(ctx, "Received notification to reload user cache")
			select {
			case p.d.triggerUserCacheRefreshCh <- true:
				logger.Info("sent cache refresh signal from postgres listener")
			case <-time.After(dbNotifierSendTimeout):
				logger.Warn("timed out sending config refresh signal")
			}
		case p.RuntimeConfigChannelName():
			logger.InfoContext(ctx, "Received notification for runtime config update")
			select {
			case p.d.triggerRuntimeConfigRefreshCh <- true:
				logger.Info("sent runtime config refresh signal from postgres listener")
			case <-time.After(dbNotifierSendTimeout):
				logger.Warn("timed out sending config refresh signal")
			}
		case p.UserUpdateChannelName():
			notifierID, userID := parseUserUpdatedNotification(notification.Payload)
			if notifierID == p.ID() {
				logger.Info("Received user update notification from self, ignoring")
				continue
			}
			select {
			case p.d.triggerUserUpdatedRefreshCh <- userID:
				logger.Info("sent signal to update user", "user_id", userID)
			case <-time.After(dbNotifierSendTimeout):
				logger.Warn("timed out sending user refresh signal", "user_id", userID)
			}
		case p.StopChannelName():
			logger.InfoContext(ctx, "received stop signal via NOTIFY")
			select {
			case p.d.signalStop <- struct{}{}:
				logger.Info("forwarded stop signal")
			case <-time.After(dbNotifierSendTimeout):
				logger.Warn("timed out forwarding stop signal")
			}
		default:
			logger.Warn("Received unknown notification", "channel", notification.Channel)
		}
	}

	return nil
}

func parseUserUpdatedNotification(s string) (notifierID, userID string) {
	before, after, _ := strings.Cut(s, recordSeparator)
	return before, after
}

func newUserUpdatedNotificationMessage(notifierID string, userID string) string {
	return strings.Join([]string{notifierID, userID}, recordSeparator)
}

func (p *postgresNotifier) UserUpdated(ctx context.Context, userID string) bool {
	var sent bool

	msg := newUserUpdatedNotificationMessage(p.ID(), userID)

	notifyErr := p.d.writeDB.DB().WithContext(ctx).Exec(
		"SELECT pg_notify(?, ?)",
		p.UserUpdateChannelName(),
		msg,
	).Error
	if notifyErr != nil {
		p.logger.ErrorContext(
			ctx,
			"Error sending NOTIFY to update user",
			tint.Err(notifyErr),
			"user_id", userID,
		)
	} else {
		p.logger.Info(
			"sent runtime config refresh notification",
			"pg_notify_id", p.ID(),
			"user_id", userID,
			"message", msg,
		)
		sent = true
	}

	return sent
}

func (p *postgresNotifier) ReloadRuntimeConfig(ctx context.Context) bool {
	var sent bool

	notifyErr := p.d.writeDB.DB().WithContext(ctx).Exec(
		"SELECT pg_notify(?, ?)",
		p.RuntimeConfigChannelName(),
		p.ID(),
	).Error
	if notifyErr != nil {
		p.logger.ErrorContext(
			ctx,
			"Error sending NOTIFY to reload runtime config",
			tint.Err(notifyErr),
		)
	} else {
		p.logger.Info(
			"sent runtime config refresh notification",
			"pg_notify_id", p.ID(),
		)
		sent = true
	}

	return sent
}

func (p *postgresNotifier) ReloadUserCache(ctx context.Context) bool {
	var sent bool

	notifyErr := p.d.writeDB.DB().WithContext(ctx).Exec(
		"SELECT pg_notify(?, ?)",
		p.UserCacheChannelName(),
		p.ID(),
	).Error
	if notifyErr != nil {
		p.logger.ErrorContext(
			ctx,
			"Error sending NOTIFY to reload runtime config",
			tint.Err(notifyErr),
		)
	} else {
		p.logger.Info(
			"sent runtime config refresh notification",
			"pg_notify_id", p.ID(),
		)
		sent = true
	}

	select {
	case p.d.triggerUserCacheRefreshCh <- true:
	//
	case <-ctx.Done():
		p.logger.Warn("timeout sending user cache refresh signal")
	}

	return sent
}
