package disconcierge

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bwmarrin/discordgo"
	"github.com/gin-gonic/gin"
	"github.com/lmittmann/tint"
	openai "github.com/sashabaranov/go-openai"
	"golang.org/x/time/rate"
	"gorm.io/gorm"
	"io"
	"log/slog"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	assistantVersion = "v2"
	openaiUserRole   = "user"
)

var (
	// When building, set these like:
	// -ldflags "-X github.com/arcward/disconcierge/disconcierge.Version=$$(date +'%Y%m%d')"

	Version   = "dev"
	CommitSHA = "unknown"
	BuildTime = "unknown"
)

var (
	// WaitForResumeCheckInterval is the duration to sleep between checking
	// whether the bot has been un-paused/resumed (when [RuntimeConfig.Paused is
	// no longer true).
	// For example, if [OpenAI.CreateRun] is called while the bot is paused,
	// it will only actually execute the API call once the bot is unpaused.
	// Until then, it will check every [WaitForResumeCheckInterval] to see if
	// it's been un-paused/resumed.
	WaitForResumeCheckInterval = 5 * time.Second
	UserWorkerSendTimeout      = time.Second
)

var (
	ErrChatCommandTooOld = errors.New("request too old")
)

var (
	// busyInteractionDeleteDelay is the amount of time to wait
	// before deleting a 'busy' interaction that was sent to
	// the user (ex: when they use /chat while their previous
	// /chat hasn't finished yet)
	busyInteractionDeleteDelay = 20 * time.Second
)

var (
	defaultLogWriter io.Writer = os.Stdout
)

// DisConcierge represents the main application struct for the DisConcierge bot.
// It encapsulates all the core components and configurations necessary
// for the bot's operation.
//
// DisConcierge manages interactions with Discord, OpenAI, the database,
// API endpoints, and various other functionalities of the bot.
//
// Fields:
//
//   - config: Pointer to the main configuration struct.
//
//   - userWorkers: Map of user-specific command workers.
//
//   - userWorkerMu: Mutex for synchronizing access to userWorkers.
//
//   - fileUploadCh: Channel for file upload processing.
//
//   - pendingSetup: Atomic boolean indicating if initial setup is pending.
//
//   - getInteractionHandlerFunc: Function to get the appropriate interaction handler.
//
//   - runtimeConfig: Pointer to the current runtime configuration.
//
//   - cfgMu: RWMutex for synchronizing access to configuration.
//
// DisConcierge coordinates all aspects of the bot's functionality, including
// command processing, API interactions, database operations, and integration with
// external services like Discord and OpenAI.
type DisConcierge struct {
	// pgNotifyID is a random ID generated at startup. When using postgres,
	// this is used as the NOTIFY payload, so the bot can determine when
	// it's receiving a message from itself (and ignore it).

	dbNotifier DBNotifier
	config     *Config

	// Pointer to a read-only GORM connection. This is from an
	// overabundance of caution for using SQLite.
	db *gorm.DB

	// gorm.DB wrapper for write/update/delete operations.
	// The only difference between this an [DisConcierge.db]
	// is that, when using sqlite, a mutex is used. Otherwise,
	// just use [DisConcierge.db].
	writeDB DBI

	// Standard logger. Missing loggers will try to use this,
	// and fall back to slog.Default()
	logger *slog.Logger

	// Handler to use for the above
	logHandler slog.Handler

	// Handles discord integration, sessions
	discord *Discord

	// Handles OpenAI API integration
	openai *OpenAI

	// Provides the back-end API, and serves the React
	// front-end when embedded
	api *API

	// Provides a webhook endpoint to use to receive Discord
	// interactions when the websocket/gateway isn't being used
	discordWebhookServer *DiscordWebhookServer

	// Handler for interactions received via webhook
	webhookInteractionHandler func(c *gin.Context)

	// signalStop enables an explicit stop signal to be sent to the bot,
	// such as by the `/api/quit` endpoint
	signalStop chan struct{}

	// signalReady has a value sent on it when Run is called. This happens
	// after:
	// - initializing database connections
	// - getting current state from the DB
	// - loading stats from the DB
	// - loading the OpenAI assistant
	// - starting the API
	// - running the 'catchup' process
	// - opening a discord session
	// - registering any discord commands
	// - adding the discord handler
	signalReady chan struct{}

	// A signal is sent on this channel when the
	// [DisConcierge.shutdown] function finished
	eventShutdown chan struct{}

	// prevents Run from executing concurrently
	runMu sync.Mutex

	// Queues and manages priority for ChatCommand requests
	requestQueue *ChatCommandMemoryQueue

	// If true, the bot will ignore new commands from
	// non-priority users, and queue commands from priority users.
	paused atomic.Bool

	// The time Run was called
	startedAt time.Time

	// A map of user IDs to user workers
	userWorkers map[string]*userCommandWorker

	// protecc the map
	userWorkerMu sync.RWMutex

	// Indicates whether admin credentials have been set.
	// If they haven't, Run will hold just after the init
	// process is done and API has started, prior to starting
	// any other processes - this ensures the bot doesn't enqueue
	// responding to commands before the bot can be configured/stopped
	// via UI.
	pendingSetup atomic.Bool

	// getInteractionHandlerFunc should be a callable to be used
	// when an interaction is received, which returns an appropriate
	// InteractionHandler. This enables command execution to remain the
	// same across webhook/gateway handlers, adjusting only the
	// request-specific discord interactions
	getInteractionHandlerFunc func(
		ctx context.Context,
		i *discordgo.InteractionCreate,
	) InteractionHandler

	// Runtime-configurable settings - things you may want to
	// change without restarting the bot.
	runtimeConfig *RuntimeConfig

	// protecc the runtime config
	cfgMu sync.RWMutex

	// chatCommandsInProgress indicates the number of ChatCommand runs
	// actively in progress ([userCommandWorker.runChatCommand])
	chatCommandsInProgress atomic.Int64

	// buttonTimersRunning indicates the number of
	// [DisConcierge.chatCommandUnselectedButtonTimer] goroutines currently
	// running. These goroutines are used to remove any unselected discord
	// message component buttons ([UserFeedback]) before the discord interaction
	// token expires (and keep, but disable, any buttons that were selected).
	buttonTimersRunning            atomic.Int64
	messageDeleteTimersRunning     atomic.Int64
	usageCommandsInProgress        atomic.Int64
	clearCommandsInProgress        atomic.Int64
	happeningNowCommandsInProgress atomic.Int64
	userWorkersRunning             atomic.Int64

	triggerRuntimeConfigRefreshCh chan bool
	triggerUserCacheRefreshCh     chan bool
	triggerUserUpdatedRefreshCh   chan string
}

func (d *DisConcierge) getLogger(ctx context.Context) (
	context.Context,
	*slog.Logger,
) {
	logger, ok := ContextLogger(ctx)
	if logger == nil || !ok {
		logger = d.logger
		ctx = WithLogger(ctx, logger)
	}
	return ctx, logger
}

// handleDiscordMessage processes incoming Discord messages that mention the
// bot or are in response to a bot interaction.
//
// This method is typically called as a goroutine for each new message
// received through the Discord gateway.
// It filters and handles messages that are relevant to the bot, such as direct
// mentions or replies to bot messages.
//
// Messages which are replies to a known bot interaction are
// saved as a DiscordMessage.
//
// If the message is a reply to a known bot interaction, or mentions the
// bot, it's saved as DiscordMessage.
//
// If the message is a reply to a known bot interaction, and the associated
// [ChatCommand.DiscordMessageID] is empty, it will be set to the referenced
// interaction message ID.
//
// If the message isn't a reply to a bot interaction, and mentions ONLY
// the bot, the bot will reply with a greeting message and example slash
// command usage.
// This greeting message is only sent if the user doesn't have [User.Ignored]
// set, and if the user doesn't already have a [userCommandWorker] running.
// [userCommandWorker] will only reply to the first message it receives
// while it's running, so at minimum once every two minutes (this is to
// prevent spamming @mentions at the bot).
func (d *DisConcierge) handleDiscordMessage(
	ctx context.Context,
	m *discordgo.MessageCreate,
) {
	ctx, logger := d.getLogger(ctx)

	logger.DebugContext(ctx, "saw message", "message", structToSlogValue(m))

	if m.MentionEveryone {
		logger.DebugContext(
			ctx,
			"ignoring message mentioning everyone",
			"message",
			structToSlogValue(m),
		)
		return
	}

	if len(m.Mentions) == 0 && m.ReferencedMessage == nil {
		logger.DebugContext(
			ctx,
			"ignoring message with no mentions or interaction",
			"message",
			structToSlogValue(m),
		)
		return
	}

	user := m.Author
	if user == nil && m.Member != nil {
		user = m.Member.User
	}
	if user == nil {
		logger.WarnContext(ctx, "couldn't find user in discord message")
		return
	}

	if user.Bot || user.ID == d.config.Discord.ApplicationID {
		logger.DebugContext(ctx, "ignoring message from bot", "user", user)
		return
	}

	dm := NewDiscordMessage(m.Message)

	mentionsBot := messageMentionsUser(
		m.Message,
		d.config.Discord.ApplicationID,
	)

	// if the bot isn't mentioned, and this isn't a reply to one of the bot's
	// own interactions, we ignore the message entirely
	if dm.InteractionID == "" && !mentionsBot {
		logger.Debug("no interaction, no mentions, ignoring")
		return
	}

	// that leaves us with these possibilities, where we save the message for each:
	// - the reply is to a known bot interaction (we don't respond)
	// - the message mentions the bot and others (we don't respond)
	// - the message mentions ONLY the bot  (we potentially respond)
	//
	// If we 'potentially' respond, we enqueue the user worker and send the
	// message to replyCh. The worker tracks whether it's received a message
	// on that channel before. If it has, it ignores the message.
	// This means the bot will respond in this way to a user at most
	// once for the lifetime of the worker, so a minimum of 2 minutes.
	// This prevents a user from spamming @mentions at the bot and hitting
	// Discord rate limits.

	wg := &sync.WaitGroup{}
	defer wg.Wait()

	defer func() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := d.writeDB.Create(&dm); err != nil {
				logger.ErrorContext(
					ctx,
					"error creating discord message log",
					tint.Err(err), "discord_message",
					dm,
				)
			} else {
				logger.InfoContext(
					ctx,
					"created new discord_message mentioning bot",
					"discord_message",
					dm,
				)
			}
		}()
	}()

	switch {
	case dm.InteractionID == "" && mentionsBot:
		mentionCount := len(m.Mentions)
		if mentionCount != 1 {
			logger.InfoContext(
				ctx,
				"multiple mentions, will not respond to message",
			)
			return
		}
		u, _, err := d.GetOrCreateUser(ctx, *user)
		if err != nil {
			logger.ErrorContext(ctx, "error getting or creating user", tint.Err(err))
			return
		}
		if u.Ignored {
			logger.WarnContext(
				ctx,
				"ignoring direct message from ignored user",
				"user", u,
			)
			return
		}
	case dm.InteractionID != "":
		chatCommand := ChatCommand{}

		err := d.db.Select("id", columnChatCommandInteractionID).Take(
			&chatCommand,
			"interaction_id = ?",
			dm.InteractionID,
		).Error
		if err != nil {
			switch {
			case errors.Is(err, gorm.ErrRecordNotFound):
				logger.InfoContext(
					ctx,
					"no ChatCommand found for interaction",
					"interaction_id",
					dm.InteractionID,
				)
			default:
				logger.ErrorContext(ctx, "error finding chat command", tint.Err(err))
			}
			return
		}

		logger.DebugContext(
			ctx,
			fmt.Sprintf(
				"chat_command.interaction_id=%#v discord_message.interaction_id=%#v",
				chatCommand.InteractionID,
				dm.InteractionID,
			),
		)
		if chatCommand.InteractionID != dm.InteractionID {
			logger.WarnContext(
				ctx,
				fmt.Sprintf(
					"why do these not match: %s / %s",
					chatCommand.InteractionID,
					dm.InteractionID,
				),
			)
			return
		}
		logger.InfoContext(
			ctx,
			"found matching message",
			"discord_message",
			dm,
		)
		if chatCommand.DiscordMessageID == "" {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, updErr := d.writeDB.Update(
					&chatCommand,
					columnChatCommandDiscordMessageID,
					dm.ReferencedMessageID,
				); updErr != nil {
					logger.Error(
						"error updating chat_command with new discord_message_id",
						tint.Err(updErr),
					)
				}
			}()
		}
	}
}

// RuntimeConfig returns a copy of the current runtime configuration
func (d *DisConcierge) RuntimeConfig() RuntimeConfig {
	d.cfgMu.RLock()
	defer d.cfgMu.RUnlock()
	return *d.runtimeConfig
}

// New creates and initializes a new DisConcierge instance.
//
// This function sets up the core components of the DisConcierge bot, including
// the configuration, logging, database connections, API handlers, and integrations
// with external services like Discord and OpenAI.
//
// It performs the following main tasks:
//  1. Validates the provided configuration.
//  2. Sets up logging for various components.
//  3. Initializes the database connection.
//  4. Sets up the OpenAI client and configuration.
//  5. Configures the Discord integration.
//  6. Initializes the API server and handlers.
//  7. Sets up the request queue for processing commands.
//  8. Configures the web crawler (if enabled).
//
// If any errors occur during initialization, they are collected and returned as a single error.
//
// Parameters:
//   - config: A pointer to the Config struct containing all necessary configuration options.
//
// Returns:
//   - *DisConcierge: A pointer to the newly created and initialized DisConcierge instance.
//   - error: An error if any part of the initialization process fails. This may be a
//     collection of multiple errors.
//
// Usage:
//
//	config := &Config{...}
//	bot, err := New(config)
//	if err != nil {
//	    log.Fatalf("Failed to initialize DisConcierge: %v", err)
//	}
//
// Note: After calling New(), you typically need to call the Run() method on the returned
// DisConcierge instance to enqueue the bot's main loop and begin processing commands.
func New(config *Config) (*DisConcierge, error) {
	var errs []error

	switch config.DatabaseType {
	case dbTypeSQLite, dbTypePostgres:
		//
	default:
		errs = append(
			errs,
			errors.New("invalid database type (must be 'sqlite' or 'postgres'"),
		)
	}

	if config.HTTPClient == nil {
		config.HTTPClient = http.DefaultClient
	}

	d := &DisConcierge{
		config:                        config,
		signalReady:                   make(chan struct{}, 1),
		userWorkers:                   map[string]*userCommandWorker{},
		userWorkerMu:                  sync.RWMutex{},
		eventShutdown:                 make(chan struct{}, 1),
		triggerRuntimeConfigRefreshCh: make(chan bool, 1),
		triggerUserCacheRefreshCh:     make(chan bool, 1),
		triggerUserUpdatedRefreshCh:   make(chan string, 1),
	}

	d.logHandler = tint.NewHandler(
		defaultLogWriter, &tint.Options{
			Level:     d.config.LogLevel,
			AddSource: true,
		},
	)

	d.logger = slog.New(d.logHandler)
	slog.SetDefault(d.logger)

	d.openai = newOpenAI(d, d.config.HTTPClient)

	d.config.Discord.httpClient = d.config.HTTPClient

	disc, err := newDiscord(d.config.Discord)
	if err != nil {
		errs = append(errs, err)
	}

	discordgo.Logger = discordgoLoggerFunc(
		context.Background(),
		tint.NewHandler(
			defaultLogWriter, &tint.Options{
				Level:     d.config.Discord.DiscordGoLogLevel,
				AddSource: true,
			},
		).WithAttrs([]slog.Attr{slog.String(loggerNameKey, "discordgo")}),
	)

	disc.logger = slog.New(
		tint.NewHandler(
			defaultLogWriter, &tint.Options{
				Level:     d.config.Discord.LogLevel,
				AddSource: true,
			},
		),
	).With(loggerNameKey, "discord")

	d.discord = disc
	disc.dc = d

	d.requestQueue = NewChatCommandQueue(
		d.config.Queue,
		d.logger.With(loggerNameKey, "queue"),
	)

	api, err := newAPI(d, config.API)
	errs = append(errs, err)
	d.api = api

	if config.Discord.WebhookServer.Enabled {
		webhookServer, e := newWebhookServer(d, config.Discord.WebhookServer)
		errs = append(errs, e)
		d.discordWebhookServer = webhookServer
	}

	return d, errors.Join(errs...)
}

func (d *DisConcierge) ValidateConfig() error {
	err := structValidator.Struct(d.config)
	if err != nil {
		return err
	}

	return nil
}

// RegisterSlashCommands registers the slash commands for the DisConcierge bot.
//
// This function sends a request to the Discord API to register the application commands
// (slash commands) defined for the bot. It uses the provided options for the request.
func (d *DisConcierge) RegisterSlashCommands(options ...discordgo.RequestOption) (
	[]*discordgo.ApplicationCommand,
	error,
) {
	return d.discord.registerCommands(d.RuntimeConfig(), options...)
}

// getUserWorker retrieves or creates a user command worker for the given user.
//
// This function ensures that each user has a dedicated command worker to handle
// their commands. If a worker already exists for the user, it is returned. If not,
// a new worker is created, started, and returned.
//
// Parameters:
//   - ctx: The context for managing the lifecycle of the user worker.
//   - u: A pointer to the User struct representing the user.
//
// Returns:
//   - *userCommandWorker: A pointer to the user command worker for the given user.
func (d *DisConcierge) getUserWorker(
	ctx context.Context,
	u *User,
) *userCommandWorker {
	d.userWorkerMu.Lock()
	defer d.userWorkerMu.Unlock()

	userWorker := d.userWorkers[u.ID]
	if userWorker != nil {
		return userWorker
	}

	startSignal := make(chan struct{}, 1)

	userWorker = newUserWorker(d, u)

	go func() {
		d.userWorkersRunning.Add(1)
		defer d.userWorkersRunning.Add(-1)

		userWorker.Run(ctx, startSignal)

		d.userWorkerMu.Lock()
		defer d.userWorkerMu.Unlock()

		w, ok := d.userWorkers[u.ID]
		if ok && w == userWorker {
			delete(d.userWorkers, u.ID)
		}
	}()

	d.userWorkers[u.ID] = userWorker
	<-startSignal
	return userWorker
}

// catchupInterruptedRuns looks for ChatCommand records that have been
// submitted for an OpenAI run, but aren't in a 'final' state, and resumes
// polling them and responding via discord - if the token isn't expired yet
func (d *DisConcierge) catchupInterruptedRuns(ctx context.Context) error {
	d.waitForPause(ctx)
	var inProgress []ChatCommand
	logger, ok := ContextLogger(ctx)
	if logger == nil || !ok {
		logger = d.logger
		if logger == nil {
			logger = slog.Default()
		}
		ctx = WithLogger(ctx, logger)
	}
	rv := d.db.WithContext(ctx).Order("priority desc, created_at asc").Find(
		&inProgress,
		"state IN ? OR run_status IN ? OR step = ?",
		[]string{
			ChatCommandStateReceived.String(),
			ChatCommandStateInProgress.String(),
			ChatCommandStateQueued.String(),
		}, []string{
			string(openai.RunStatusInProgress),
			string(openai.RunStatusQueued),
		}, ChatCommandStepFeedbackOpen,
	)

	if rv.Error != nil {
		logger.ErrorContext(
			ctx,
			"error performing catchup query",
			tint.Err(rv.Error),
		)
		return rv.Error
	}

	if len(inProgress) == 0 || inProgress == nil {
		logger.InfoContext(ctx, "no interrupted runs to catch up")
	}
	wg := &sync.WaitGroup{}

	for i := 0; i < len(inProgress); i++ {
		c := inProgress[i]
		wg.Add(1)
		go func(chatCommand ChatCommand) {
			defer wg.Done()

			cmdCtx := ctx
			chatCmd := &chatCommand

			d.waitForPause(cmdCtx)

			if err := d.hydrateChatCommand(ctx, chatCmd); err != nil {
				logger.ErrorContext(ctx, "error hydrating", tint.Err(err))
				c.handleError(ctx, d)
				return
			}
			if err := d.resumeChatCommand(cmdCtx, chatCmd); err != nil {
				logger.ErrorContext(cmdCtx, "error resuming run", tint.Err(err))
			}
		}(c)
	}
	wg.Wait()

	return nil
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

// Run starts the main loop of the DisConcierge bot.
//
// This function initializes the bot's runtime environment, validates the configuration,
// and starts the primary application functions, including broadcasting events to
// websocket subscribers and monitoring/handling the ChatCommand queue.
//
// Parameters:
//   - ctx: The context for managing the lifecycle of the bot's runtime.
//
// Returns:
//   - error: An error if any part of the runtime initialization or execution fails.
func (d *DisConcierge) Run(ctx context.Context) error {
	// prevents concurrent runs
	d.runMu.Lock()
	defer d.runMu.Unlock()

	d.signalStop = make(chan struct{}, 1)

	d.startedAt = time.Now()
	logger := d.logger

	if err := d.ValidateConfig(); err != nil {
		logger.Error("invalid config", tint.Err(err))
		return err
	}

	notifier, err := newDBNotifier(d)
	if err != nil {
		logger.Error("error creating db notifier", tint.Err(err))
		return err
	}
	d.dbNotifier = notifier

	ctx = WithLogger(ctx, logger)

	// primary application functions - broadcasting events to
	// websocket subscribers, and monitoring/handling the ChatCommand queue
	runtimeWG := &sync.WaitGroup{}

	d.webhookInteractionHandler = webhookReceiveHandler(ctx, d)

	logger.LogAttrs(ctx, slog.LevelInfo, "starting", slog.Any("config", d.config))
	if d.signalReady == nil {
		d.signalReady = make(chan struct{}, 1)
	}

	// this is the 'runtime' context, which triggers a graceful shutdown
	// when canceled
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		select {
		case <-d.signalStop:
			d.logger.Warn("got stop signal, canceling")
			cancel()
		case <-ctx.Done():
			d.logger.Warn("context canceled, sending stop signal")
			d.signalStop <- struct{}{}
			return
		}
	}()

	go func() {
		httpErr := d.api.Serve(ctx)
		if httpErr != nil && !errors.Is(httpErr, http.ErrServerClosed) {
			d.logger.ErrorContext(ctx, "error serving api HTTP", tint.Err(httpErr))
		}
	}()

	startCtx, startCancel := context.WithTimeout(ctx, d.config.StartupTimeout)
	defer startCancel()

	initErr := make(chan error, 1)
	go func() {
		logger.Debug("initializing run...")
		initErr <- d.initRun(startCtx, ctx)
	}()

	select {
	case <-startCtx.Done():
		return fmt.Errorf("startup cancelled or timed out")
	case err := <-initErr:
		if err != nil {
			logger.ErrorContext(ctx, "init error", tint.Err(err))
			if d.api != nil && d.api.listener != nil {
				go func() {
					if e := d.api.listener.Close(); e != nil {
						logger.ErrorContext(ctx, "error closing listener", tint.Err(e))
					}
				}()
			}
			return err
		} else {
			logger.WarnContext(ctx, "init complete")
		}
	}

	if setupErr := d.waitOnSetup(ctx, logger, runtimeWG); setupErr != nil {
		return setupErr
	}

	if d.openai.requestLimiter == nil {
		d.openai.requestLimiter = rate.NewLimiter(
			rate.Limit(d.RuntimeConfig().OpenAIMaxRequestsPerSecond),
			1,
		)
	}

	runtimeWG.Add(1)
	go func() {
		defer runtimeWG.Done()
		d.catchupAndWatchQueue(ctx, logger)
	}()

	runtimeCfg := d.RuntimeConfig()

	if d.config.Discord.WebhookServer.Enabled {
		d.startWebhookServer(ctx, runtimeWG)
	} else if !runtimeCfg.DiscordGatewayEnabled {
		logger.WarnContext(ctx, "discord gateway and webhook server disabled")
	}

	if discErr := d.initDiscordSession(ctx, runtimeWG); discErr != nil {
		d.logger.ErrorContext(ctx, "error creating discord session", tint.Err(discErr))
		return discErr
	}

	if err := d.discordInit(ctx, runtimeCfg, logger); err != nil {
		return err
	}

	d.startRuntimeConfigRefresher(ctx, runtimeWG, logger)
	d.startUserCacheRefresher(ctx, runtimeWG)
	d.startUserUpdatedListener(ctx, runtimeWG)

	d.signalReady <- struct{}{}
	d.logger.InfoContext(ctx, "sent ready signal")

	runtimeWG.Add(1)
	go func() {
		defer runtimeWG.Done()
		if e := d.dbNotifier.Listen(ctx, d.dbNotifier.RuntimeConfigChannelName()); e != nil {
			d.logger.ErrorContext(ctx, "error listening to runtime config channel", tint.Err(e))
		}
	}()

	runtimeWG.Add(1)
	go func() {
		defer runtimeWG.Done()
		if e := d.dbNotifier.Listen(ctx, d.dbNotifier.UserCacheChannelName()); e != nil {
			d.logger.ErrorContext(ctx, "error listening to user cache channel", tint.Err(e))
		}
	}()

	runtimeWG.Add(1)
	go func() {
		defer runtimeWG.Done()
		if e := d.dbNotifier.Listen(ctx, d.dbNotifier.UserUpdateChannelName()); e != nil {
			d.logger.ErrorContext(ctx, "error listening to user update channel", tint.Err(e))
		}
	}()

	// block until something cancels the main runtime context - generally
	// from an interrupt, or the `/api/quit` endpoint
	stopCh := make(chan struct{}, 1)
	go func() {
		<-ctx.Done()
		stopCh <- struct{}{}
	}()
	<-stopCh

	// Commence shutdown
	return d.shutdown(ctx, runtimeWG)
}

func (d *DisConcierge) waitOnSetup(
	ctx context.Context,
	logger *slog.Logger,
	runtimeWG *sync.WaitGroup,
) error {
	if !d.pendingSetup.Load() {
		return nil
	}

	logger.WarnContext(
		ctx,
		fmt.Sprintf(
			"pending initial setup at: %s%s",
			d.api.listener.Addr().String(),
			apiAdminSetup,
		),
	)
	pendingStateCh := make(chan struct{}, 1)
	go func() {
		for ctx.Err() == nil {
			var runtimeState RuntimeConfig
			logger.InfoContext(ctx, "checking if runtime config exists yet")
			getRuntimeStateErr := d.db.Last(&runtimeState).Error
			if getRuntimeStateErr != nil {
				logger.ErrorContext(
					ctx,
					"error getting runtime state",
					tint.Err(getRuntimeStateErr),
				)
			}
			if runtimeState.AdminUsername != "" && runtimeState.AdminPassword != "" {
				pendingStateCh <- struct{}{}
				return
			}
			time.Sleep(5 * time.Second)
		}
	}()

	select {
	case <-ctx.Done():
		logger.WarnContext(ctx, "context cancelled waiting on setup, exiting")
		return d.shutdown(ctx, runtimeWG)
	case <-pendingStateCh:
		d.pendingSetup.Store(false)
	}

	return nil
}

// discordInit opens the discord websocket connection and registers commands,
// if the gateway is enabled
func (d *DisConcierge) discordInit(
	ctx context.Context,
	runtimeCfg RuntimeConfig,
	logger *slog.Logger,
) error {
	if !runtimeCfg.DiscordGatewayEnabled {
		return nil
	}
	// Open the discord websocket connection and register commands
	d.logger.InfoContext(ctx, "connecting to discord")
	if err := d.discord.session.Open(); err != nil {
		logger.ErrorContext(ctx, "error connecting to discord!", tint.Err(err))
		return fmt.Errorf("error connecting to discord: %w", err)
	}
	if runtimeCfg.DiscordCustomStatus != "" && !d.paused.Load() {
		go func() {
			if statusErr := d.discord.session.UpdateCustomStatus(
				runtimeCfg.DiscordCustomStatus,
			); statusErr != nil {
				logger.Error("error updating discord status", tint.Err(statusErr))
			}
		}()
	}
	return nil
}

func (d *DisConcierge) startWebhookServer(ctx context.Context, runtimeWG *sync.WaitGroup) {
	// TODO set up a run mode where only the API and database
	//   are enabled (ex: for 'offline' bot config)
	runtimeWG.Add(1)
	go func() {
		defer runtimeWG.Done()
		httpErr := d.discordWebhookServer.Serve(ctx)
		if httpErr != nil && !errors.Is(httpErr, http.ErrServerClosed) {
			d.logger.ErrorContext(ctx, "error serving webhook HTTP", tint.Err(httpErr))
		}
	}()
}

func (d *DisConcierge) catchupAndWatchQueue(ctx context.Context, logger *slog.Logger) {
	logger.InfoContext(ctx, "starting run catchup")
	if catchupErr := d.catchupInterruptedRuns(ctx); catchupErr != nil {
		logger.ErrorContext(
			ctx,
			"error catching up interrupted runs",
			tint.Err(catchupErr),
		)
	}
	logger.InfoContext(ctx, "starting queue watcher")
	d.watchQueue(ctx)
	logger.InfoContext(ctx, "queue watcher done")
}

func (d *DisConcierge) startUserCacheRefresher(ctx context.Context, runtimeWG *sync.WaitGroup) {
	userCacheTTL := d.config.UserCacheTTL

	var lastRefresh time.Time

	if userCacheTTL > 0 {
		ticker := time.NewTicker(d.config.UserCacheTTL)
		defer ticker.Stop()

		runtimeWG.Add(1)
		go func() {
			defer runtimeWG.Done()
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				select {
				case d.triggerUserCacheRefreshCh <- false:
				//
				case <-time.After(15 * time.Second):
					d.logger.Info("timed out sending user cache refresh signal")
				}
			}
		}()
	}

	runtimeWG.Add(1)
	go func() {
		defer runtimeWG.Done()
		for {
			select {
			case <-ctx.Done():
				d.logger.Info("context canceled, stopping user cache refresher")
				return
			case forceRefresh := <-d.triggerUserCacheRefreshCh:
				if forceRefresh || lastRefresh.IsZero() {
					d.logger.Info("force-reloading cache")
					d.refreshUserCache(ctx)
					lastRefresh = time.Now()
					d.logger.Info("finished reloading")
				} else {
					elapsed := time.Since(lastRefresh)
					if elapsed > userCacheTTL {
						d.logger.Info("reloading cache")
						d.refreshUserCache(ctx)
						lastRefresh = time.Now()
						d.logger.Info("finished reloading")
					} else {
						d.logger.Info("recently refreshed, ignoring")
					}
				}
			}
		}
	}()

}

func (d *DisConcierge) startUserUpdatedListener(ctx context.Context, runtimeWG *sync.WaitGroup) {
	runtimeWG.Add(1)
	go func() {
		defer runtimeWG.Done()
		for {
			select {
			case <-ctx.Done():
				d.logger.Info("context canceled, stopping user updated listener")
				return
			case userID := <-d.triggerUserUpdatedRefreshCh:
				if userID == "" {
					d.logger.Warn("empty user ID received, skipping refresh")
					continue
				}
				d.refreshUser(userID)
			}
		}
	}()
}

func (d *DisConcierge) refreshUser(userID string) {
	d.logger.Info("reloading user", "user_id", userID)
	user := d.writeDB.ReloadUser(userID)
	d.logger.Info("reloaded user", "user_id", userID)

	d.userWorkerMu.RLock()
	defer d.userWorkerMu.RUnlock()

	worker := d.userWorkers[user.ID]
	if worker != nil {
		worker.userMu.Lock()
		defer worker.userMu.Unlock()
		worker.user = user
	}
}

// startRuntimeConfigRefresher starts the cache refresher goroutine. This periodically
// refreshes [RuntimeConfig] and the user cache.
func (d *DisConcierge) startRuntimeConfigRefresher(
	ctx context.Context,
	runtimeWG *sync.WaitGroup,
	logger *slog.Logger,
) {
	runtimeConfigTTL := d.config.RuntimeConfigTTL

	if runtimeConfigTTL > 0 {
		runtimeWG.Add(1)
		go func() {
			defer runtimeWG.Done()
			ticker := time.NewTicker(runtimeConfigTTL)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					select {
					case d.triggerRuntimeConfigRefreshCh <- false:
						logger.Info("sent cache refresh signal from ticker")
					case <-time.After(5 * time.Second):
						logger.Warn("timed out sending config refresh signal")
					}
				}
			}
		}()
	}

	runtimeWG.Add(1)
	go func() {
		defer runtimeWG.Done()

		for {
			select {
			case <-ctx.Done():
				return
			case forceRefresh := <-d.triggerRuntimeConfigRefreshCh:
				refreshCh := make(chan struct{}, 1)
				refreshCtx, refreshCancel := context.WithTimeout(ctx, 30*time.Second)
				go func() {
					d.refreshRuntimeConfig(refreshCtx, forceRefresh)
					refreshCh <- struct{}{}
				}()
				select {
				case <-refreshCh:
				//
				case <-refreshCtx.Done():
					d.logger.Warn("refresh runtime config timed out or interrupted")
				}
				refreshCancel()
			}
		}
	}()
}

func (d *DisConcierge) refreshRuntimeConfig(ctx context.Context, force bool) {
	d.cfgMu.Lock()
	defer d.cfgMu.Unlock()

	runtimeConfigTTL := d.config.RuntimeConfigTTL
	rollbackConfig := d.runtimeConfig

	var refreshConfig RuntimeConfig
	if err := d.db.WithContext(ctx).Last(&refreshConfig).Error; err != nil {
		d.logger.Error("error getting runtime config", tint.Err(err))
		return
	}

	lastUpdated := time.Since(time.UnixMilli(refreshConfig.UpdatedAt))
	if force || lastUpdated > runtimeConfigTTL {
		d.logger.Info(
			fmt.Sprintf(
				"runtime config last updated: %s ago, refreshing",
				lastUpdated.String(),
			),
		)
		d.unsafeRefreshRuntimeConfig(rollbackConfig, &refreshConfig)
	} else {
		d.logger.Info("runtime config is up to date, skipping refresh")
	}
}

// unsafeRefreshRuntimeConfig refreshes the runtime configuration without
// locking the config mutex.
func (d *DisConcierge) unsafeRefreshRuntimeConfig(
	rollbackConfig *RuntimeConfig,
	existingConfig *RuntimeConfig,
) {
	d.logger.Info("refreshing runtime configuration and user cache")
	switch {
	case rollbackConfig.DiscordGatewayEnabled && !existingConfig.DiscordGatewayEnabled:
		if discErr := d.discord.session.Close(); discErr != nil {
			d.logger.Error("error closing discord connection", tint.Err(discErr))
		}
	case rollbackConfig.DiscordGatewayEnabled && existingConfig.DiscordGatewayEnabled:
		switch {
		case existingConfig.Paused:
			if !rollbackConfig.Paused {
				if discErr := d.discord.session.UpdateStatusComplex(
					discordgo.UpdateStatusData{
						AFK:    true,
						Status: string(discordgo.StatusDoNotDisturb),
					},
				); discErr != nil {
					d.logger.Error("error updating discord status", tint.Err(discErr))
				}
			}
		case existingConfig.DiscordCustomStatus != rollbackConfig.DiscordCustomStatus:
			if discErr := d.discord.session.UpdateCustomStatus(
				existingConfig.DiscordCustomStatus,
			); discErr != nil {
				d.logger.Error("error updating discord status", tint.Err(discErr))
			}
		}
	case existingConfig.DiscordGatewayEnabled:
		d.discord.session.SetIdentify(
			discordgo.Identify{
				Intents:  d.config.Discord.GatewayIntents,
				Presence: getDiscordPresenceStatusUpdate(*existingConfig),
			},
		)
		if discErr := d.discord.session.Open(); discErr != nil {
			d.logger.Error("error opening discord connection", tint.Err(discErr))
		}
	}

	d.runtimeConfig = existingConfig
	d.setRuntimeLevels(*existingConfig)

	d.logger.Info("refreshed runtime config")
}

func (d *DisConcierge) refreshUserCache(ctx context.Context) {
	d.writeDB.UserCacheLock()
	defer d.writeDB.UserCacheUnlock()
	_ = d.writeDB.LoadUsers()
}

func (d *DisConcierge) shutdown(
	ctx context.Context,
	runtimeWG *sync.WaitGroup,
) error {
	d.logger.WarnContext(ctx, "shutting down")
	defer func() {
		if d.eventShutdown != nil {
			go func() {
				d.eventShutdown <- struct{}{}
			}()
		}
	}()
	shutdownStart := time.Now()
	shutdownTimeout := d.config.ShutdownTimeout
	if shutdownTimeout.Seconds() == 0 {
		d.logger.Warn("immediate shutdown")
		go func() {
			_ = d.api.httpServer.Close()
		}()
		return fmt.Errorf("request worker did not stop in time")
	}
	shutdownDeadline := shutdownStart.Add(shutdownTimeout)

	shutdownAnnouncementInterval := 10 * time.Second

	announcementTicker := time.NewTicker(shutdownAnnouncementInterval)
	defer announcementTicker.Stop()

	d.logger.InfoContext(
		ctx,
		"exiting!",
		"shutdown_timeout", d.config.ShutdownTimeout,
		"shutdown_started", shutdownStart,
		"shutdown_deadline", shutdownDeadline,
	)

	closeCtx, closeCancel := context.WithDeadline(
		context.Background(),
		shutdownDeadline,
	)
	defer closeCancel()

	// Graceful shutdown - at least until closeCtx is closed
	gracefulShutdownCh := make(chan struct{}, 1)
	go func() {
		runtimeWG.Wait() // wait for anything spawned by the main processes
		runtimeStopEnd := time.Now()
		d.logger.InfoContext(
			ctx,
			"finished handling in-flight requests",
			"shutdown_started", shutdownStart,
			"runtime_stopped", runtimeStopEnd,
			"runtime_stop_duration", runtimeStopEnd.Sub(shutdownStart),
		)
		stopWG := &sync.WaitGroup{}

		// flush the queue
		if d.requestQueue != nil {
			stopWG.Add(1)
			go func() {
				defer stopWG.Done()
				queueFlushCt := 0
				for d.requestQueue.Len() > 0 {
					rq := d.requestQueue.Clear(context.Background())
					if rq != nil {
						queueFlushCt++
					} else {
						break
					}
				}
				d.logger.InfoContext(
					ctx,
					"purged request queue",
					"count", queueFlushCt,
				)
			}()
		}

		stopWG.Add(1)
		go func() {
			defer stopWG.Done()

			d.userWorkerMu.Lock()
			defer d.userWorkerMu.Unlock()

			if d.userWorkers != nil {
				for wid, worker := range d.userWorkers {
					stopWG.Add(1)
					go func(workerID string, w *userCommandWorker) {
						defer stopWG.Done()
						d.logger.Info(
							fmt.Sprintf(
								"sending stop signal to worker for user '%s'",
								workerID,
							),
						)
						w.signalStop <- struct{}{}
						d.logger.Info(
							fmt.Sprintf(
								"sent stop signal to user worker '%s' - waiting on confirmation",
								workerID,
							),
						)
						<-w.stopped
						d.logger.Info(
							fmt.Sprintf(
								"confirmed worker '%s' stopped",
								workerID,
							),
						)
					}(wid, worker)
				}
			}
			d.userWorkers = map[string]*userCommandWorker{}
		}()

		if d.api.httpServer != nil {
			stopWG.Add(1)
			go func() {
				defer stopWG.Done()
				d.logger.InfoContext(ctx, "stopping http server")
				_ = d.api.httpServer.Shutdown(closeCtx)
				d.logger.InfoContext(ctx, "http server stopped")
			}()
		}

		if d.discordWebhookServer != nil {
			stopWG.Add(1)
			go func() {
				defer stopWG.Done()
				d.logger.InfoContext(ctx, "stopping webhook http server")
				_ = d.discordWebhookServer.httpServer.Shutdown(closeCtx)
				d.logger.InfoContext(ctx, "webhook http server stopped")
			}()
		}

		if d.discord.session != nil {
			stopWG.Add(1)
			go func() {
				defer stopWG.Done()
				d.logger.InfoContext(ctx, "closing discord session")
				_ = d.discord.session.Close()
				d.logger.InfoContext(ctx, "discord session closed")
				if len(d.discord.discordgoRemoveHandlerFuncs) > 0 {
					d.logger.InfoContext(
						ctx,
						fmt.Sprintf(
							"removing %d discord handlers",
							len(d.discord.discordgoRemoveHandlerFuncs),
						),
					)
					for _, h := range d.discord.discordgoRemoveHandlerFuncs {
						h()
					}
					d.logger.InfoContext(ctx, "finished removing handlers")
				}
			}()
		}

		// wait on the above, then send a signal that we're done
		go func() {
			d.logger.InfoContext(ctx, "waiting graceful shutdown")
			stopWG.Wait()
			gracefulShutdownCh <- struct{}{}
			d.logger.InfoContext(ctx, "stopped http/discord")
		}()
	}()

	// if we get a signal on gracefulShutdownCh, everything stopped and
	// cleaned up normally.
	// otherwise, burn it all down!
	for {
		select {
		case <-gracefulShutdownCh:
			closeCancel()
			shutdownEnded := time.Now()
			d.logger.InfoContext(
				ctx,
				"shutdown complete",
				"shutdown_ended", shutdownEnded,
				"shutdown_duration", shutdownEnded.Sub(shutdownStart),
			)
			return nil
		case <-announcementTicker.C:
			remaining := time.Until(shutdownDeadline)
			d.logger.Warn(
				fmt.Sprintf(
					"time until hard shutdown: %s",
					remaining.String(),
				),
			)
		case <-closeCtx.Done(): // timed out, enqueue closing stuff
			d.logger.Warn("request worker did not stop in time, forcing close")

			go func() {
				_ = d.api.httpServer.Close()
			}()
			if d.discordWebhookServer != nil {
				go func() {
					_ = d.discordWebhookServer.httpServer.Close()
				}()
			}

			return fmt.Errorf("request worker did not stop in time")
		}
	}
}

// setRuntimeLevels sets the logging levels and request limits for various components
// of the DisConcierge bot based on the provided runtime configuration.
//
// Parameters:
//   - state: The [RuntimeConfig] to use to set log levels and/or rate limits
func (d *DisConcierge) setRuntimeLevels(state RuntimeConfig) {
	d.config.LogLevel.Set(state.LogLevel.Level())
	d.config.OpenAI.LogLevel.Set(state.OpenAILogLevel.Level())
	d.config.Discord.LogLevel.Set(state.DiscordLogLevel.Level())
	d.config.API.LogLevel.Set(state.APILogLevel.Level())
	d.config.Discord.WebhookServer.LogLevel.Set(state.DiscordWebhookLogLevel.Level())
	d.config.Discord.DiscordGoLogLevel.Set(state.DiscordGoLogLevel.Level())
	d.config.DatabaseLogLevel.Set(state.DatabaseLogLevel.Level())
	if d.openai.requestLimiter == nil {
		d.openai.requestLimiter = rate.NewLimiter(
			rate.Limit(state.OpenAIMaxRequestsPerSecond),
			1,
		)
	} else {
		d.openai.requestLimiter.SetLimit(rate.Limit(state.OpenAIMaxRequestsPerSecond))
	}
}

func (d *DisConcierge) initRun(startCtx context.Context, ctx context.Context) error {
	d.logger.Debug("initializing DB...")
	if err := d.initDB(startCtx); err != nil {
		return fmt.Errorf("error initializing database: %w", err)
	}
	d.logger.Debug("finished initializing DB")

	// load or create the DB state config - this tells the bot whether
	// it should enqueue in a 'paused' state (to avoid a potential scenario
	// where we want to keep it paused, but it crashes and restarts in
	// an active state)
	var botState RuntimeConfig

	getStateErr := d.db.Last(&botState).Error
	if getStateErr != nil {
		if errors.Is(getStateErr, gorm.ErrRecordNotFound) {
			d.pendingSetup.Store(true)
			botState = DefaultRuntimeConfig()

			if _, err := d.writeDB.Create(&botState); err != nil {
				return fmt.Errorf("error creating config: %w", err)
			}
		} else {
			return fmt.Errorf("error getting config: %w", getStateErr)
		}
	}
	if validationErr := structValidator.Struct(botState); validationErr != nil {
		return fmt.Errorf("invalid runtime config: %w", validationErr)
	}

	if botState.AdminUsername == "" || botState.AdminPassword == "" {
		d.pendingSetup.Store(true)
	}
	d.paused.Store(botState.Paused)
	d.setRuntimeLevels(botState)
	d.runtimeConfig = &botState

	// verify we've configured the correct assistant ID
	if d.openai.assistant == nil {
		assistant, err := d.openai.client.RetrieveAssistant(
			startCtx,
			d.config.OpenAI.AssistantID,
		)
		if err != nil {
			return fmt.Errorf("error retrieving assistant: %w", err)
		}
		d.logger.InfoContext(
			ctx,
			"assistant found",
			"assistant", structToSlogValue(assistant),
		)
		d.openai.assistant = &assistant
	}

	return nil
}

func (d *DisConcierge) initDiscordSession(ctx context.Context, runtimeWG *sync.WaitGroup) error {
	logger := d.logger.With(loggerNameKey, "discord_session")

	if d.discord.session == nil {
		disc, discErr := d.discord.newSession()
		if discErr != nil {
			return fmt.Errorf("error creating discord session: %w", discErr)
		}
		d.discord.session = disc
	}

	ctx = WithLogger(ctx, logger)

	if len(d.discord.discordgoRemoveHandlerFuncs) > 0 {
		for _, h := range d.discord.discordgoRemoveHandlerFuncs {
			h()
		}
	}

	identify := discordgo.Identify{Intents: d.config.Discord.GatewayIntents}
	if d.paused.Load() {
		identify.Presence = discordgo.GatewayStatusUpdate{
			AFK:    true,
			Status: string(discordgo.StatusDoNotDisturb),
		}
	} else {
		identify.Presence = discordgo.GatewayStatusUpdate{
			Status: d.RuntimeConfig().DiscordCustomStatus,
		}
	}
	d.discord.session.SetIdentify(identify)

	d.discord.discordgoRemoveHandlerFuncs = []func(){
		d.discord.session.AddHandler(d.discord.handlerConnect()),
		d.discord.session.AddHandler(d.discord.handlerDisconnect()),
		d.discord.session.AddHandler(d.discord.handlerReady()),
		d.discord.session.AddHandler(
			func(
				_ *discordgo.Session,
				i *discordgo.InteractionCreate,
			) {
				handler := d.getInteractionHandlerFunc(ctx, i)
				runtimeWG.Add(1)
				go func() {
					defer runtimeWG.Done()
					d.handleInteraction(ctx, handler)
				}()
			},
		),
		d.discord.session.AddHandler(
			func(
				_ *discordgo.Session,
				m *discordgo.MessageCreate,
			) {
				runtimeWG.Add(1)
				go func() {
					defer runtimeWG.Done()
					d.handleDiscordMessage(ctx, m)
				}()
			},
		),
	}

	if d.getInteractionHandlerFunc == nil {
		d.getInteractionHandlerFunc = func(
			rctx context.Context,
			i *discordgo.InteractionCreate,
		) InteractionHandler {
			handler := GatewayHandler{
				session:     d.discord.session,
				interaction: i,
				config:      d.RuntimeConfig().CommandOptions,
				mu:          &sync.RWMutex{},
				logger: d.logger.With(
					slog.Group(
						"interaction",
						interactionLogAttrs(*i)...,
					),
				),
			}
			return handler
		}
	}
	return nil
}

// Pause 'pauses' the bot. While paused, ChatCommand nor ClearCommand
// will be queued or executed - unless User.Priority is set. In that case,
// that user's incoming ChatCommand will be queued, though not executed
// until the bot is resumed.
func (d *DisConcierge) Pause(ctx context.Context) bool {
	prev := d.paused.Swap(true)
	if prev {
		return false
	}

	if err := d.discord.updateStatusComplex(
		discordgo.UpdateStatusData{
			AFK:    true,
			Status: string(discordgo.StatusDoNotDisturb),
		},
	); err != nil {
		d.logger.ErrorContext(ctx, "unable to update afk status", tint.Err(err))
	}
	if !d.runtimeConfig.Paused {
		if _, err := d.writeDB.Update(
			d.runtimeConfig,
			"paused",
			true,
		); err != nil {
			d.logger.ErrorContext(ctx, "unable to set paused in db", tint.Err(err))
		}
	}
	return true
}

// Resume resumes command processing. It returns a bool indicating whether
// the bot was paused at the time the function was called.
func (d *DisConcierge) Resume(ctx context.Context) bool {
	prev := d.paused.Swap(false)
	if !prev {
		d.logger.Warn("bot not paused")
		return false
	}
	d.logger.InfoContext(ctx, "bot resumed")

	if err := d.discord.updateCustomStatus(d.runtimeConfig.DiscordCustomStatus); err != nil {
		d.logger.ErrorContext(ctx, "unable to update noline status", tint.Err(err))
	}

	if d.runtimeConfig.Paused {
		if _, err := d.writeDB.Update(
			d.runtimeConfig, columnRuntimeConfigPaused, false,
		); err != nil {
			d.logger.ErrorContext(ctx, "unable to set resumed in db", tint.Err(err))
		}
	}

	return true
}

// watchQueue is the main loop for handling ChatCommand requests.
func (d *DisConcierge) watchQueue(ctx context.Context) {
	defer func() {
		d.logger.InfoContext(
			ctx,
			"queue watcher stopped",
			"queue_size",
			d.requestQueue.Len(),
		)
	}()

	d.requestQueue.requestCh = make(chan *ChatCommand)

	wg := &sync.WaitGroup{}
	defer func() {
		wg.Wait()
	}()

	wg.Add(1)
	go func() {
		swg := &sync.WaitGroup{}
		defer func() {
			close(d.requestQueue.requestCh)
			swg.Wait()
			wg.Done()
		}()

		for ctx.Err() == nil {
			if d.paused.Load() {
				d.logger.DebugContext(ctx, "currently paused, sleeping")
				time.Sleep(d.requestQueue.config.SleepPaused)
				continue
			}

			req := d.requestQueue.Pop(ctx)

			if req == nil {
				d.logger.DebugContext(
					ctx,
					"no pending requests, sleeping",
					"sleep_duration", d.requestQueue.config.SleepEmpty,
				)
				time.Sleep(d.requestQueue.config.SleepEmpty)
				continue
			}

			logger := d.logger.With(
				slog.Group(
					"chat_command",
					chatCommandLogAttrs(*req)...,
				),
			)

			if req.State == ChatCommandStateQueued {
				logger.InfoContext(
					ctx,
					"popped request",
					slog.Group(
						"chat_command",
						columnChatCommandStep, req.Step,
						columnChatCommandState, req.State,
					),
				)
			} else {
				logger.WarnContext(
					ctx,
					fmt.Sprintf(
						"expected state '%s', got: '%s'",
						ChatCommandStateQueued,
						req.State,
					),
					slog.Group(
						"chat_command",
						columnChatCommandStep, req.Step,
						columnChatCommandState, req.State,
					),
				)
			}

			d.requestQueue.requestCh <- req
		}
	}()

	for req := range d.requestQueue.requestCh {
		logger := d.logger.With(
			slog.Group("chat_command", chatCommandLogAttrs(*req)...),
		)

		reqAge := req.Age()
		if d.config.Queue.MaxAge > 0 && reqAge > d.config.Queue.MaxAge {
			req.State = ChatCommandStateExpired
			logger.WarnContext(
				ctx,
				"discarded old request",
				"user_request", req,
			)

			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := d.writeDB.Update(
					req,
					columnChatCommandState,
					ChatCommandStateExpired,
				); err != nil {
					logger.ErrorContext(
						ctx,
						"failed to update expired request",
						tint.Err(err),
					)
				}
			}()
			continue
		}

		if req.User.Ignored {
			logger.WarnContext(
				ctx,
				"ignoring blocked User request",
				slog.Group(
					"chat_command",
					columnChatCommandStep, req.Step,
					columnChatCommandState, req.State,
				),
			)

			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := d.writeDB.Update(
					req,
					columnChatCommandState,
					ChatCommandStateIgnored,
				); err != nil {
					logger.ErrorContext(
						ctx,
						"failed to update expired request",
						tint.Err(err),
					)
				}
			}()

			continue
		}

		startedAt := time.Now()
		req.StartedAt = &startedAt

		userWorker := d.getUserWorker(ctx, req.User)

		sendCtx, sendCancel := context.WithTimeout(ctx, UserWorkerSendTimeout)

		select {
		case userWorker.chatCh <- req:
			sendCancel()
		case <-sendCtx.Done():
			// If we can't immediately send the request to the user
			// worker, it means a request is already in progress.
			// In this case, we send a message to the user that we're
			// still working on the previous request.
			// Then, we delete that semi-temporary message after
			// 20 seconds.
			logger.WarnContext(ctx, "timed out sending user request")
			wg.Add(1)
			go func(r *ChatCommand) {
				reqCtx := ctx
				config := r.handler.Config()
				if config.RecoverPanic {
					defer func() {
						if rc := recover(); rc != nil {
							d.handleRecover(reqCtx, rc)
						}
					}()
				}
				defer wg.Done()

				reqLogger, ok := ContextLogger(reqCtx)
				if reqLogger == nil || !ok {
					reqLogger = slog.Default()
				}
				reqLogger = reqLogger.With(
					slog.Group("chat_command", chatCommandLogAttrs(*r)...),
				)
				reqCtx = WithLogger(reqCtx, reqLogger)

				reqLogger.WarnContext(
					reqCtx,
					"request already in progress for user",
				)
				responseMsg := config.DiscordRateLimitMessage
				finishedAt := time.Now()

				swg := &sync.WaitGroup{}
				swg.Add(1)
				go func() {
					defer swg.Done()
					reqLogger.WarnContext(
						reqCtx,
						"command rate-limited due to worker send timeout",
					)
					if _, err := d.writeDB.ChatCommandUpdates(
						r,
						map[string]any{
							columnChatCommandState:      ChatCommandStateRateLimited,
							columnChatCommandStep:       "",
							columnChatCommandFinishedAt: &finishedAt,
							columnChatCommandStartedAt:  &startedAt,
							columnChatCommandResponse:   &responseMsg,
						},
					); err != nil {
						reqLogger.ErrorContext(
							reqCtx,
							"error saving rate limited request",
							tint.Err(err),
						)
					}
				}()

				swg.Add(1)
				go func() {
					defer swg.Done()
					_, editErr := r.handler.Edit(
						reqCtx,
						&discordgo.WebhookEdit{Content: &responseMsg},
					)
					if editErr != nil {
						reqLogger.WarnContext(
							reqCtx,
							"failed to edit message",
							tint.Err(editErr),
						)
						return
					}
					reqLogger.InfoContext(
						reqCtx,
						fmt.Sprintf(
							"temporary busy message will be deleted in: %s",
							busyInteractionDeleteDelay.String(),
						),
					)
					deleteTimer := time.NewTimer(busyInteractionDeleteDelay)
					d.messageDeleteTimersRunning.Add(1)
					defer func() {
						d.messageDeleteTimersRunning.Add(-1)
						deleteTimer.Stop()
						select {
						case <-deleteTimer.C:
							//
						default:
							//
						}
					}()
					select {
					case <-ctx.Done():
						reqLogger.InfoContext(
							reqCtx,
							"context cancelled, deleting rate-limited interaction response NOW",
						)
						delCtx, delCancel := context.WithTimeout(
							context.Background(),
							5*time.Second,
						)
						defer delCancel()
						r.handler.Delete(
							ctx,
							discordgo.WithRetryOnRatelimit(false),
							discordgo.WithContext(delCtx),
						)
					case <-deleteTimer.C:
						reqLogger.InfoContext(
							reqCtx,
							"deleting rate-limited interaction response",
						)
						r.handler.Delete(ctx)
					}
				}()
				swg.Wait()
			}(req)
		}
		sendCancel()
	}
}

func notifyDiscordUserReachedRateLimit(
	ctx context.Context,
	logger *slog.Logger,
	d *Discord,
	user *User,
	usage ChatCommandUsage,
	prompt string,
	notificationChannelID string,
) {
	if usage.Billable6h < usage.Limit6h {
		return
	}

	if notificationChannelID == "" {
		logger.Info("no discord notification channel set, skipping")
		return
	}

	if sendErr := d.channelMessageSend(
		notificationChannelID,
		fmt.Sprintf(
			"User `%s` (`%s`) reached their rate limit.\n"+
				"- **6h**: Attempted: %d / Billable: %d / Limit: %d\n"+
				"- Available: %s"+
				"Prompt:\n"+
				"```\n"+
				"%s\n"+
				"```\n",
			user.GlobalName,
			user.ID,
			usage.Attempted6h,
			usage.Billable6h,
			usage.Limit6h,

			usage.CommandsAvailableAt.String(),
			prompt,
		),
		discordgo.WithContext(ctx),
	); sendErr != nil {
		logger.Error("error sending error notification", tint.Err(sendErr))
	}
}

// GetOrCreateUser will retrieve an existing (cached) User to return,
// or will create a new User record if one doesn't already exist for
// the given user's ID.
func (d *DisConcierge) GetOrCreateUser(
	ctx context.Context, u discordgo.User,
) (user *User, isNew bool, err error) {
	user, isNew, err = d.writeDB.GetOrCreateUser(ctx, d, u)
	if isNew {
		go d.discordNotifyNewUserSeen(ctx, user.Username, user.GlobalName, user.ID)
	}
	return user, isNew, err
}

func (d *DisConcierge) discordNotifyNewUserSeen(
	ctx context.Context,
	username string,
	globalName string,
	userID string,
) {
	log, ok := ContextLogger(ctx)
	if !ok || log == nil {
		log = d.logger
	}
	log = log.With(
		slog.Group(
			"new_user",
			"id", userID,
			"username", username,
			"global_name", globalName,
		),
	)
	log.Info("saw new user!")
	channelID := d.RuntimeConfig().DiscordNotificationChannelID
	if channelID == "" {
		log.Debug("no channel id set, not notifying of new user")
		return
	}
	if sendErr := d.discord.channelMessageSend(
		channelID,
		fmt.Sprintf(
			"**New user seen!** GlobalName: `%s` Username: `%s` UserID: `%s`",
			globalName,
			username,
			userID,
		),
		discordgo.WithContext(ctx),
		discordgo.WithRetryOnRatelimit(false),
	); sendErr != nil {
		log.Error("error sending new user notification", tint.Err(sendErr))
	}
}

// initDB initializes the database connection for the DisConcierge bot.
//
// This function sets up the database connection using the provided configuration,
// initializes the GORM logger, and assigns the database connection to the DisConcierge struct.
func (d *DisConcierge) initDB(ctx context.Context) error {
	logger, ok := ContextLogger(ctx)
	if !ok || logger == nil {
		logger = d.logger
	}

	handler := tint.NewHandler(
		defaultLogWriter, &tint.Options{
			Level:     d.config.DatabaseLogLevel,
			AddSource: true,
		},
	)

	gormLogger := newGORMLogger(handler, d.config.DatabaseSlowThreshold)
	db, err := getDB(d.config.DatabaseType, d.config.Database, gormLogger)

	if err != nil {
		return fmt.Errorf("error opening database: %w", err)
	}

	d.db = db

	d.writeDB = NewDatabase(db, nil, d.config.DatabaseType == dbTypePostgres)
	d.requestQueue.db = d.writeDB

	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("error getting database connection: %w", err)
	}

	if d.config.DatabaseType == dbTypeSQLite {
		sqlDB.SetMaxOpenConns(sqliteMaxOpenConns)
		sqlDB.SetMaxIdleConns(sqliteMaxIdleConns)
		sqlDB.SetConnMaxLifetime(sqliteMaxConnLifetime)
		if sqliteExecPragma != nil {
			pragmaErrors := make([]error, 0, len(sqliteExecPragma))
			for _, p := range sqliteExecPragma {
				pragmaErrors = append(
					pragmaErrors,
					db.WithContext(ctx).Exec(p).Error,
				)
			}
			pragmaErr := errors.Join(pragmaErrors...)
			if pragmaErr != nil {
				return pragmaErr
			}
		}
	}

	logger.Debug("migrating database...")
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
		logger.Error("error migrating database", tint.Err(err))
		return fmt.Errorf("error migrating database: %w", err)
	}
	logger.Debug("finished migrating database")

	commitErr := txn.Commit().Error
	if commitErr != nil {
		return fmt.Errorf("error committing transaction: %w", commitErr)
	}
	_ = d.writeDB.LoadUsers()
	return nil
}

// DiscordStatus represents the metrics related to Discord interactions.
//
// Fields:
//   - MessagesHandled: The number of messages handled by the bot.
//   - Connects: The number of times the bot has connected to Discord.
//   - Disconnects: The number of times the bot has disconnected from Discord.
type DiscordStatus struct {
	MessagesHandled int64 `json:"messages_handled"`
	Connects        int64 `json:"connects"`
	Disconnects     int64 `json:"disconnects"`
}

// OpenAIStatus represents the metrics related to OpenAI API usage.
//
// Fields:
//   - CreateMessage: The number of messages created using the OpenAI API.
//   - CreateRun: The number of runs created using the OpenAI API.
//   - CreateThread: The number of threads created using the OpenAI API.
//   - RetrieveRun: The number of runs retrieved using the OpenAI API.
//   - ListMessage: The number of messages listed using the OpenAI API.
//   - RunStatus: A map of run statuses and their counts.
//   - PromptTokens: The number of prompt tokens used.
//   - CompletionTokens: The number of completion tokens used.
//   - TotalTokens: The total number of tokens used.
type OpenAIStatus struct {
	CreateMessage    int64                    `json:"create_message"`
	CreateRun        int64                    `json:"create_run"`
	CreateThread     int64                    `json:"create_thread"`
	RetrieveRun      int64                    `json:"retrieve_run"`
	ListMessage      int64                    `json:"list_message"`
	RunStatus        map[openai.RunStatus]int `json:"run_status"`
	PromptTokens     int                      `json:"prompt_tokens"`
	CompletionTokens int                      `json:"completion_tokens"`
	TotalTokens      int                      `json:"total_tokens"`
}

// interactionResponseToSubmittedModal returns an interaction response, in
// response to the user clicking the 'Submit' button on the modal that's created when
// the user clicks the UserFeedbackOther button component
func (d *DisConcierge) interactionResponseToSubmittedModal(
	ctx context.Context,
	i *discordgo.InteractionCreate,
) *discordgo.InteractionResponse {
	logger, ok := ContextLogger(ctx)
	if logger == nil || !ok {
		logger = d.logger
		ctx = WithLogger(ctx, logger)
	}

	modalData := i.ModalSubmitData()
	logger.InfoContext(
		ctx,
		"got modal data",
		"data", structToSlogValue(modalData),
	)
	reportData, err := getFeedbackTextInput(d.db, modalData)
	if err != nil || reportData == nil {
		logger.ErrorContext(ctx, "error getting report content", tint.Err(err))
		return nil
	}
	logger.InfoContext(
		ctx,
		"got text input feedback",
		"content", reportData.Report,
		"custom_id", reportData.CustomID,
		"chat_command", reportData.ChatCommand,
	)

	chatCommand := reportData.ChatCommand
	logger.InfoContext(
		ctx,
		"creating user feedback",
		"chat_command", structToSlogValue(chatCommand),
		"report", structToSlogValue(reportData),
	)

	if err = d.hydrateChatCommand(ctx, chatCommand); err != nil {
		logger.ErrorContext(ctx, "error hydrating discord message", tint.Err(err))
		return nil
	}

	if chatCommand.hasPrivateFeedback() {
		userReport := UserFeedback{
			ChatCommandID: &chatCommand.ID,
			UserID:        &chatCommand.UserID,
			Description:   feedbackTypeDescription[reportData.CustomID.ReportType],
			Type:          string(reportData.CustomID.ReportType),
			Detail:        reportData.Report,
			CustomID:      reportData.CustomID.ID,
		}
		err = chatCommand.newDMReport(ctx, d.writeDB, &userReport)
		go d.notifyDiscordUserFeedback(context.Background(), *chatCommand, userReport)
		if err != nil {
			logger.ErrorContext(
				ctx,
				"error creating UserFeedback",
				tint.Err(err),
				"user_report", structToSlogValue(userReport),
				"discord_message", structToSlogValue(chatCommand),
			)
		}
		return &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseDeferredMessageUpdate,
		}
	}

	var reportingUser *User

	reportingDiscordUser := getDiscordUser(i)
	if reportingDiscordUser.ID == chatCommand.UserID {
		reportingUser = chatCommand.User
	} else {
		logger.InfoContext(
			ctx,
			"user providing feedback not the same as the user triggering the command",
			"command_user_id", chatCommand.UserID,
			"reporting_user_id", reportingDiscordUser.ID,
			"reporting_username", reportingDiscordUser.Username,
			"reporting_global_name", reportingDiscordUser.GlobalName,
		)
		reportingUser, _, err = d.GetOrCreateUser(ctx, *reportingDiscordUser)
		if err != nil {
			logger.ErrorContext(ctx, "error getting reporting user", tint.Err(err))
			return nil
		}
	}

	userReport := UserFeedback{
		ChatCommandID: &chatCommand.ID,
		UserID:        &reportingUser.ID,
		Description:   feedbackTypeDescription[reportData.CustomID.ReportType],
		Type:          string(reportData.CustomID.ReportType),
		Detail:        reportData.Report,
		CustomID:      reportData.CustomID.ID,
	}
	if _, err = d.writeDB.Create(&userReport); err != nil {
		logger.ErrorContext(ctx, "error creating user feedback", tint.Err(err))
		go d.notifyDiscordUserFeedback(context.Background(), *chatCommand, userReport)
		return nil
	}

	go d.notifyDiscordUserFeedback(context.Background(), *chatCommand, userReport)
	return &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseDeferredMessageUpdate,
	}
}

// interactionResponseToMessageComponent processes an interaction that's the result of
// a user clicking one of the FeedbackButtonType component buttons,
// and returns an interaction to respond with
func (d *DisConcierge) interactionResponseToMessageComponent(
	ctx context.Context,
	i *discordgo.InteractionCreate,
) (*discordgo.InteractionResponse, error) {
	logger, ok := ContextLogger(ctx)
	if logger == nil || !ok {
		logger = d.logger
		ctx = WithLogger(ctx, logger)
	}

	componentData := i.MessageComponentData()
	customID, err := decodeCustomID(componentData.CustomID)
	if err != nil {
		logger.ErrorContext(ctx, "error decoding custom_id", tint.Err(err))
		return nil, fmt.Errorf("error decoding custom_id: %w", err)
	}

	cdata, _ := json.Marshal(componentData)
	logger.InfoContext(
		ctx,
		"received button component interaction",
		"custom_id", customID,
		"component_data", string(cdata),
	)

	logger = logger.With("custom_id", customID)
	ctx = WithLogger(ctx, logger)

	logger.InfoContext(ctx, "received discord button push", "custom_id", customID)

	var chatCmd ChatCommand
	rv := d.db.Where("custom_id = ?", customID.ID).Omit("User").First(&chatCmd)
	if rv.Error != nil {
		logger.ErrorContext(
			ctx,
			"error finding chat_command for the given custom_id",
			tint.Err(rv.Error),
			"custom_id", customID.ID,
		)
		return nil, fmt.Errorf(
			"error finding chat_command for custom_id '%s': %w",
			customID.ID, rv.Error,
		)
	}
	chatCommand := &chatCmd

	if err = d.hydrateChatCommand(ctx, chatCommand); err != nil {
		logger.ErrorContext(ctx, "hydration error", tint.Err(err))
		return nil, fmt.Errorf("error hydrating chat_command: %w", err)
	}
	config := d.RuntimeConfig()
	logger.InfoContext(ctx, fmt.Sprintf("custom ID: %#v", customID))

	// Clicking the "Other" button responds to the interaction with a text
	// input modal, which creates a UserFeedback entry on submission,
	// whereas the other buttons create a UserFeedback record immediately
	if customID.ReportType == UserFeedbackOther {
		modalLabel := truncate(
			config.FeedbackModalInputLabel,
			discordModalInputLabelMaxLength,
		)
		modalResponse := discordModalResponse(
			componentData.CustomID,
			config.FeedbackModalTitle,
			modalLabel,
			config.FeedbackModalPlaceholder,
			config.FeedbackModalMinLength,
			config.FeedbackModalMaxLength,
		)
		logger.DebugContext(
			ctx,
			"modal response",
			"modal_response", modalResponse,
		)
		return modalResponse, nil
	}

	if chatCommand.hasPrivateFeedback() {
		userReport := UserFeedback{
			ChatCommandID: &chatCommand.ID,
			UserID:        &chatCommand.UserID,
			Type:          string(customID.ReportType),
			Description:   feedbackTypeDescription[customID.ReportType],
			CustomID:      customID.ID,
		}
		logger.Info(fmt.Sprintf("created new feedback: %#v", userReport))
		err = chatCommand.newDMReport(
			ctx,
			d.writeDB,
			&userReport,
		)
		go d.notifyDiscordUserFeedback(context.Background(), *chatCommand, userReport)
		if err != nil {
			logger.ErrorContext(
				ctx,
				"error creating user report",
				tint.Err(err),
				"user_report", structToSlogValue(userReport),
				"discord_message", structToSlogValue(chatCommand),
			)
			return nil, nil
		}
		return &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseDeferredMessageUpdate,
		}, nil
	}

	var reportingUser *User

	reportingDiscordUser := getDiscordUser(i)

	if reportingDiscordUser.ID == chatCommand.UserID {
		logger.InfoContext(
			ctx,
			"reporting user is the same user that triggered the command",
		)
		reportingUser = chatCommand.User
	} else {
		logger.WarnContext(
			ctx,
			"different user reporting feedback",
			"command_user_id", chatCommand.UserID,
			"reporting_user_id", reportingDiscordUser.ID,
			"reporting_username", reportingDiscordUser.Username,
			"reporting_global_name", reportingDiscordUser.GlobalName,
		)
		reportingUser, _, err = d.GetOrCreateUser(ctx, *reportingDiscordUser)
		if err != nil {
			logger.ErrorContext(
				ctx,
				"error getting reporting user",
				tint.Err(err),
			)
			return nil, fmt.Errorf("error getting reporting user: %w", err)
		}
	}

	previousFeedback, err := chatCommand.userReportExists(
		ctx,
		d.db,
		reportingUser.ID,
		customID.ReportType,
	)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		logger.ErrorContext(ctx, "error getting previous feedback", tint.Err(err))
		return nil, fmt.Errorf("error getting previous feedback: %w", err)
	}
	if previousFeedback > 0 {
		logger.WarnContext(ctx, "duplicate feedback, ignoring")
		return &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseDeferredMessageUpdate,
		}, nil
	}
	userReport := UserFeedback{
		ChatCommandID: &chatCommand.ID,
		UserID:        &reportingUser.ID,
		Type:          string(customID.ReportType),
		Description:   feedbackTypeDescription[customID.ReportType],
		CustomID:      customID.ID,
	}
	if _, err = d.writeDB.Create(&userReport); err != nil {
		logger.ErrorContext(ctx, "error creating user feedback", tint.Err(err))
		return nil, fmt.Errorf("error creating user feedback: %w", err)
	}
	logger.InfoContext(ctx, "responding to button interaction")
	go d.notifyDiscordUserFeedback(context.Background(), *chatCommand, userReport)
	return &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseDeferredMessageUpdate,
	}, nil
}

func (d *DisConcierge) notifyDiscordUserFeedback(
	ctx context.Context,
	c ChatCommand,
	report UserFeedback,
) {
	logger, ok := ContextLogger(ctx)
	if !ok || logger == nil {
		logger = d.logger.With("chat_command", c, "user_feedback", report)
		ctx = WithLogger(ctx, logger)
	}

	config := c.handler.Config()

	channelID := config.DiscordNotificationChannelID
	if channelID == "" {
		logger.Warn("discord notification channel not enabled, will not send feedback to channel")
		return
	}

	if !d.RuntimeConfig().DiscordGatewayEnabled {
		logger.Warn("discord gateway enabled, will not send feedback to channel")
	}
	feedbackType := FeedbackButtonType(report.Type)
	if feedbackType == UserFeedbackReset {
		return
	}
	sb := strings.Builder{}

	switch feedbackType {
	case UserFeedbackGood:
		sb.WriteString(
			fmt.Sprintf("# Received feedback: **%s**\n", report.Description),
		)
	default:
		sb.WriteString(
			fmt.Sprintf("# :warning: Received feedback: **%s**\n", report.Description),
		)
	}

	if feedbackType == UserFeedbackOther {
		sb.WriteString("\n## User Input\n")
		sb.WriteString("```\n")
		sb.WriteString(strings.ReplaceAll(report.Detail, "`", " "))
		sb.WriteString("\n```\n")
	}
	sb.WriteString("## User\n")
	sb.WriteString(fmt.Sprintf("- global_name: `%s`\n", c.User.GlobalName))
	sb.WriteString(fmt.Sprintf("- username: `%s`\n", c.User.Username))
	sb.WriteString(fmt.Sprintf("- id: `%s`\n", c.User.ID))

	sb.WriteString("## ChatCommand\n")
	sb.WriteString(fmt.Sprintf("- id: `%d`\n", c.ID))
	sb.WriteString(fmt.Sprintf("- interaction_id: `%s`\n", c.InteractionID))
	sb.WriteString(fmt.Sprintf("- custom_id: `%s`\n", c.CustomID))
	sb.WriteString(fmt.Sprintf("- context: `%s`\n", c.CommandContext))
	sb.WriteString(
		fmt.Sprintf(
			"- completion tokens: `%d`\n",
			c.UsageCompletionTokens,
		),
	)
	sb.WriteString(fmt.Sprintf("- prompt tokens: `%d`\n", c.UsagePromptTokens))
	sb.WriteString(fmt.Sprintf("- total tokens: `%d`\n", c.UsageTotalTokens))

	sb.WriteString("### Prompt\n")
	sb.WriteString("```\n")
	sb.WriteString(strings.ReplaceAll(c.Prompt, "`", " "))
	sb.WriteString("\n```\n")

	sb.WriteString("### Response\n")
	var promptResponse string
	if c.Response != nil {
		promptResponse = *c.Response
	}
	if promptResponse == "" {
		sb.WriteString("(no response)")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(strings.ReplaceAll(promptResponse, "`", " "))
		sb.WriteString("\n```\n")
	}

	sendCtx, sendCancel := context.WithTimeout(
		ctx,
		30*time.Second,
	)
	defer sendCancel()

	err := d.discord.channelMessageSend(
		channelID,
		sb.String(),
		discordgo.WithContext(sendCtx),
		discordgo.WithRetryOnRatelimit(false),
		discordgo.WithRestRetries(2),
	)
	if err != nil {
		logger.Error("error sending feedback to discord", tint.Err(err))
	} else {
		logger.Info("send channel notification")
	}
}

// runClearCommand executes a ClearCommand (`/clear` slash command) for a user.
//
// This clears `User.ThreadID` so that a new OpenAI thread is created on
// the user's next `/chat` (or `/private`) command.
//
// The method performs the following steps:
//  1. Checks if the user is allowed to execute the command based on priority
//     status and rate limiting.
//  2. If rate limited, responds with a rate limit message and updates the command record.
//  3. If allowed, executes the clear command.
//  4. Updates the last execution time for rate limiting purposes.
//  5. Handles any errors that occur during command execution.
//
// This method is typically called as part of a userCommandWorker runloop
func (d *DisConcierge) runClearCommand(
	ctx context.Context,
	handler InteractionHandler,
	clearRec *ClearCommand,
) {
	wg := &sync.WaitGroup{}
	defer func() {
		wg.Wait()
	}()

	if ctx.Err() != nil {
		return
	}
	logger, ok := ContextLogger(ctx)
	if !ok || logger == nil {
		logger = handler.Logger()
	}

	started := time.Now()
	clearRec.StartedAt = &started
	config := handler.Config()
	if _, dbErr := d.writeDB.Create(clearRec); dbErr != nil {
		logger.ErrorContext(ctx, "error creating clear command", tint.Err(dbErr))
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = handler.Edit(
				ctx,
				&discordgo.WebhookEdit{Content: &config.DiscordErrorMessage},
			)
		}()
		return
	}
	logger.InfoContext(
		ctx,
		"created new clear command",
		"chat_command", clearRec,
	)

	userWorker := d.getUserWorker(ctx, clearRec.User)
	startCtx, startCancel := context.WithTimeout(ctx, UserWorkerSendTimeout)
	defer startCancel()
	select {
	case userWorker.clearCh <- clearRec:
		//
	case <-startCtx.Done():
		go func() {
			logger.Warn(
				"request already in progress for user",
				"user_request", clearRec,
			)
			responseMsg := config.DiscordRateLimitMessage
			finishedAt := time.Now()
			// TODO add a test to make sure finished_at gets set in this scenario
			if _, err := d.writeDB.Updates(
				clearRec,
				map[string]any{
					columnClearCommandResponse:   &responseMsg,
					columnClearCommandFinishedAt: &finishedAt,
				},
			); err != nil {
				logger.ErrorContext(
					ctx,
					"error saving rate limited request",
					tint.Err(err),
				)
			}
			if responseMsg == "" {
				logger.Debug("rate limit message not set, deleting interaction response")
				handler.Delete(ctx)
			} else {
				_, _ = handler.Edit(
					ctx,
					&discordgo.WebhookEdit{Content: &responseMsg},
				)
			}
		}()
	}
}

// handleRecover handles the recovery from a panic in a goroutine. This is
// intended to be used when executing slash commands, and should only
// be used when [RuntimeConfig.RecoverPanic] is enabled.
func (*DisConcierge) handleRecover(ctx context.Context, rc any) {
	logger, ok := ContextLogger(ctx)
	if logger == nil || !ok {
		logger = slog.Default()
	}
	stackTrace := string(debug.Stack())
	fmt.Println("stack trace:", stackTrace)
	if nerr, ok := rc.(error); ok {
		logger.ErrorContext(
			ctx,
			"recovered from panic",
			tint.Err(nerr),
			"stack_trace", stackTrace,
		)
		return
	}
	if nerr, ok := rc.(string); ok {
		logger.ErrorContext(
			ctx,
			"recovered from panic",
			tint.Err(errors.New(nerr)),
			"stack_trace", stackTrace,
		)
		return
	}
	logger.ErrorContext(
		ctx,
		"recovered from panic",
		"panic_arg", rc,
		"stack_trace", stackTrace,
	)
}

// InteractionHandler defines the interface for handling Discord interactions.
// It provides methods for responding to interactions, retrieving responses,
// editing messages, and managing interaction lifecycle.
//
// Implementations of this interface are responsible for handling different
// types of Discord interactions, such as commands, components, and modals.
type InteractionHandler interface {
	// Respond sends an initial response to a Discord interaction.
	Respond(ctx context.Context, i *discordgo.InteractionResponse) error

	// GetResponse retrieves the current response for an interaction.
	GetResponse(ctx context.Context) (*discordgo.Message, error)

	// Edit modifies an existing interaction response.
	Edit(
		ctx context.Context,
		e *discordgo.WebhookEdit,
		opts ...discordgo.RequestOption,
	) (*discordgo.Message, error)

	// Delete removes an interaction response.
	Delete(ctx context.Context, opts ...discordgo.RequestOption)

	// GetInteraction returns the original InteractionCreate event.
	GetInteraction() *discordgo.InteractionCreate

	// InteractionReceiveMethod returns the method used to receive the
	// interaction (webhook or gateway).
	InteractionReceiveMethod() DiscordInteractionReceiveMethod

	// Logger returns the logger associated with this handler.
	Logger() *slog.Logger

	// Config returns the command options for this handler.
	Config() CommandOptions
}

// GatewayHandler implements [InteractionHandler] when receiving interactions
// via the discord websocket gateway.
type GatewayHandler struct {
	session     DiscordSessionHandler
	interaction *discordgo.InteractionCreate
	logger      *slog.Logger
	config      CommandOptions
	mu          *sync.RWMutex
}

func (GatewayHandler) InteractionReceiveMethod() DiscordInteractionReceiveMethod {
	return discordInteractionReceiveMethodGateway
}

func (w GatewayHandler) Config() CommandOptions {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.config
}

func (w GatewayHandler) ChannelMessageSendReply(
	channelID string,
	content string,
	reference *discordgo.MessageReference,
	options ...discordgo.RequestOption,
) (*discordgo.Message, error) {
	msg, err := w.session.ChannelMessageSendReply(
		channelID, content, reference, options...,
	)
	if err != nil {
		w.logger.Error(
			"error sending message reply",
			tint.Err(err),
			"channel_id", channelID,
			"content", content,
			"reference", reference,
		)
	} else {
		w.logger.Error(
			"sent message reply",
			"channel_id", channelID,
			"content", content,
			"reference", reference,
			"msg", msg,
		)
	}
	return msg, err
}

func (w GatewayHandler) Respond(
	ctx context.Context,
	response *discordgo.InteractionResponse,
) error {
	err := w.session.InteractionRespond(w.interaction.Interaction, response)
	if err != nil {
		w.logger.ErrorContext(ctx, "error responding to interaction", tint.Err(err))
	} else {
		w.logger.InfoContext(ctx, "responded to interaction")
	}
	return err
}

func (w GatewayHandler) GetResponse(ctx context.Context) (
	*discordgo.Message,
	error,
) {
	msg, err := w.session.InteractionResponse(
		w.interaction.Interaction,
	)
	if err != nil {
		w.logger.ErrorContext(ctx, "error getting interaction", tint.Err(err))
	} else {
		w.logger.InfoContext(ctx, "got interaction response", "message", msg)
	}
	return msg, err
}

func (w GatewayHandler) GetInteraction() *discordgo.InteractionCreate {
	return w.interaction
}

func (w GatewayHandler) Edit(
	ctx context.Context,
	wh *discordgo.WebhookEdit,
	opts ...discordgo.RequestOption,
) (*discordgo.Message, error) {
	msg, err := w.session.InteractionResponseEdit(
		w.interaction.Interaction,
		wh,
		opts...,
	)
	if err != nil {
		w.logger.ErrorContext(ctx, "error editing interaction response", tint.Err(err))
	} else {
		w.logger.InfoContext(ctx, "edited interaction")
	}
	return msg, err
}

func (w GatewayHandler) Delete(ctx context.Context, opts ...discordgo.RequestOption) {
	err := w.session.InteractionResponseDelete(
		w.interaction.Interaction,
		opts...,
	)
	if err != nil {
		w.logger.ErrorContext(ctx, "error deleting interaction response", tint.Err(err))
	}
}

func (w GatewayHandler) Logger() *slog.Logger {
	return w.logger
}

func newInteractionLog(
	i *discordgo.InteractionCreate,
	u *discordgo.User,
	handler InteractionHandler,
) (*InteractionLog, error) {
	p, err := json.Marshal(i)
	if err != nil {
		return nil, fmt.Errorf("error marshaling interaction: %w", err)
	}

	interactionLog := &InteractionLog{
		InteractionID: i.ID,
		Type:          i.Type.String(),
		UserID:        u.ID,
		Username:      u.String(),
		GuildID:       i.GuildID,
		ChannelID:     i.ChannelID,
		Context:       i.Context.String(),
		Payload:       string(p),
		Method:        handler.InteractionReceiveMethod(),
	}
	return interactionLog, nil
}

// handleInteraction processes incoming Discord interactions for the DisConcierge bot.
//
// This function is responsible for handling various types of Discord interactions,
// including application commands (slash commands), message components, and modal submits.
// It manages the flow of interaction processing, from initial reception to final response.
//
// Parameters:
//   - ctx: A context.Context for managing the lifecycle of the interaction handling.
//   - handler: An InteractionHandler interface that provides methods for
//     responding to the interaction.
//
// The function performs the following main tasks:
//  1. Logs the incoming interaction details.
//  2. Creates an InteractionLog record in the database.
//  3. Handles different interaction types:
//     - InteractionPing: Responds with a pong.
//     - InteractionModalSubmit: Processes modal submissions (e.g., feedback forms).
//     - InteractionMessageComponent: Handles button clicks and other component interactions.
//     - InteractionApplicationCommand: Processes slash commands like /chat, /private, /clear, etc.
//  4. For application commands, it:
//     - Acknowledges the interaction if necessary.
//     - Retrieves or creates a User record associated with the interaction.
//     - Processes specific commands (/chat, /private, /clear).
//     - Manages command queuing and execution.
//  5. Handles errors and updates interaction states accordingly.
//
// The function uses goroutines for concurrent processing of certain tasks,
// such as database operations and long-running command executions.
//
// Note: This function is central to the bot's operation and integrates various
// components like user management, command processing, and Discord API interactions.
func (d *DisConcierge) handleInteraction(
	ctx context.Context,
	handler InteractionHandler,
) {
	interaction := handler.GetInteraction()
	logger := handler.Logger()

	i := handler.GetInteraction()
	discordUser := getDiscordUser(i)
	if discordUser == nil {
		logger.ErrorContext(
			ctx,
			"no user found in interaction",
			"interaction", structToSlogValue(i),
		)
		return
	}

	logger = logger.With(slog.Group("interaction", interactionLogAttrs(*i)...))
	ctx = WithLogger(ctx, logger)
	logger.InfoContext(ctx, "received new interaction", "user", structToSlogValue(discordUser))

	interactionLog, err := newInteractionLog(i, discordUser, handler)
	if err != nil {
		logger.ErrorContext(ctx, "error marshaling interaction", tint.Err(err))
	}

	wg := &sync.WaitGroup{}
	defer wg.Wait()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, createErr := d.writeDB.Create(interactionLog); createErr != nil {
			logger.ErrorContext(ctx, "error logging interaction", tint.Err(createErr))
		}
	}()

	if discordUser.Bot {
		logger.WarnContext(ctx, "user is bot, ignoring", "user", discordUser)
		return
	}

	switch interaction.Type {
	case discordgo.InteractionPing:
		_ = handler.Respond(
			ctx, &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponsePong,
			},
		)
	case discordgo.InteractionModalSubmit:
		if rv := d.interactionResponseToSubmittedModal(ctx, i); rv != nil {
			_ = handler.Respond(ctx, rv)
		}
	case discordgo.InteractionMessageComponent:
		rv, e := d.interactionResponseToMessageComponent(ctx, i)
		if e != nil {
			logger.ErrorContext(ctx, "error with component response", tint.Err(e))
		}
		if rv != nil {
			if responseErr := handler.Respond(ctx, rv); responseErr != nil {
				logger.ErrorContext(
					ctx,
					"error responding to component interaction",
					tint.Err(responseErr),
				)
			}
		}
	case discordgo.InteractionApplicationCommand:
		commandName := i.ApplicationCommandData().Name

		u, _, e := d.GetOrCreateUser(ctx, *discordUser)

		if e != nil {
			logger.ErrorContext(ctx, "error getting user", tint.Err(e))

			wg.Add(1)
			go func() {
				defer wg.Done()
				handler.Delete(ctx)
			}()

			return
		}

		logger = logger.With(slog.Group("user", userLogAttrs(*u)...))

		// ignore any interactions from ignored users, or from
		// non-priority users while the bot is paused
		if u.Ignored || (d.paused.Load() && !u.Priority) {
			wg.Add(1)
			go func() {
				defer wg.Done()
				d.handleIgnoredUserCommand(ctx, handler, u, i)
			}()

			return
		}

		switch commandName {
		case DiscordSlashCommandChat, DiscordSlashCommandPrivate:
			if ackErr := handler.Respond(ctx, d.discord.ackResponse(commandName)); ackErr != nil {
				logger.ErrorContext(ctx, "error acknowledging interaction", tint.Err(ackErr))
				return
			}

			chatCommand, cmdErr := NewChatCommand(u, i)
			if cmdErr != nil {
				logger.ErrorContext(ctx, "error creating chat_command", tint.Err(cmdErr))
			}
			if chatCommand == nil {
				logger.Warn("unexpected nil command")
				return
			}

			chatCommand.handler = handler
			if i.ApplicationCommandData().Name == DiscordSlashCommandPrivate {
				chatCommand.Private = true
			}
			if _, createErr := d.writeDB.Create(chatCommand); createErr != nil {
				chatCommand.finalizeWithError(ctx, d, createErr)
				return
			}

			msg, respErr := handler.GetResponse(ctx)
			if respErr != nil {
				logger.Error("error getting interaction response", tint.Err(respErr))
				chatCommand.finalizeWithError(ctx, d, respErr)
				return
			}

			chatCommand.Acknowledged = true
			if chatCommand.DiscordMessageID == "" && msg != nil {
				chatCommand.DiscordMessageID = msg.ID
			}

			if _, updErr := d.writeDB.Updates(
				chatCommand,
				map[string]any{
					columnChatCommandAcknowledged:     chatCommand.Acknowledged,
					columnChatCommandDiscordMessageID: chatCommand.DiscordMessageID,
				},
			); updErr != nil {
				logger.ErrorContext(ctx, "error updating chat_command", tint.Err(updErr))
				chatCommand.finalizeWithError(ctx, d, updErr)
				return
			}

			logger = logger.With(
				slog.Group("chat_command", chatCommandLogAttrs(*chatCommand)...),
			)
			ctx = WithLogger(ctx, logger)

			chatCommand.enqueue(ctx, d)
		case DiscordSlashCommandClear:
			clearRec := NewUserClearCommand(d, u, i)
			clearRec.handler = handler
			if ackErr := handler.Respond(ctx, d.discord.ackResponse(commandName)); ackErr != nil {
				logger.ErrorContext(ctx, "error acknowledging interaction", tint.Err(ackErr))
				clearRec.State = ClearCommandStateFailed
				if _, dbErr := d.writeDB.Create(clearRec); dbErr != nil {
					logger.Error("error saving clear command", tint.Err(dbErr))
				}
				return
			}
			clearRec.Acknowledged = true
			d.runClearCommand(ctx, handler, clearRec)
		}
	}
}

// handleIgnoredUserCommand processes commands from users who are
// marked as ignored.
//
// It sets [ChatCommandStateIgnored] on the command and saves it to the
// database.
func (d *DisConcierge) handleIgnoredUserCommand(
	ctx context.Context,
	handler InteractionHandler,
	u *User,
	i *discordgo.InteractionCreate,
) {
	logger := handler.Logger()
	commandName := i.ApplicationCommandData().Name
	logger.InfoContext(
		ctx,
		"handling ignored user interaction",
		"command_name", commandName,
	)
	switch commandName {
	case DiscordSlashCommandChat, DiscordSlashCommandPrivate:
		chatCommand, err := NewChatCommand(u, i)
		if err != nil {
			logger.ErrorContext(ctx, "error creating ChatCommand", tint.Err(err))
			return
		}
		chatCommand.handler = handler
		chatCommand.State = ChatCommandStateIgnored
		if i.ApplicationCommandData().Name == DiscordSlashCommandPrivate {
			chatCommand.Private = true
		}

		if _, e := d.writeDB.Create(chatCommand); e != nil {
			logger.ErrorContext(ctx, "error saving chat_command record", tint.Err(e))
		} else {
			logger.InfoContext(
				ctx,
				"created new (ignored) chat command",
				"chat_command", chatCommand,
			)
		}
	case DiscordSlashCommandClear:
		clearCmd := NewUserClearCommand(d, u, i)
		clearCmd.handler = handler

		clearCmd.State = ClearCommandStateIgnored
		if _, e := d.writeDB.Create(clearCmd); e != nil {
			logger.ErrorContext(ctx, "error saving clear command", tint.Err(e))
		} else {
			logger.InfoContext(
				ctx,
				"created new (ignored) clear command",
				"clear_command", clearCmd,
			)
		}
	}
}

// waitForPause blocks until the bot is in an "unpaused" state.
// A bool is returned indicating whether the bot was paused at the
// time the function was called.
func (d *DisConcierge) waitForPause(ctx context.Context) bool {
	if !d.paused.Load() {
		return false
	}

	logger, ok := ContextLogger(ctx)
	if !ok || logger == nil {
		logger = d.logger
	}

	logger.Info("bot is paused, waiting for resume")
	for ctx.Err() == nil {
		if !d.paused.Load() {
			logger.Debug("bot resumed")
			break
		}
		time.Sleep(WaitForResumeCheckInterval)
	}
	logger.Debug("context canceled before bot resumed")
	return true
}

// resumeChatCommand attempts to resume the command from the last known state,
// if in a state that is eligible to be resumed.
// States that indicate we shouldn't process the command at all will
// return immediately. (Ex: Rate limited/aborted/ignored/expired/failed).
//
// If ChatCommand.RunStatus is openai.RunStatusInProgress or openai.RunStatusQueued,
// execution will be resumed - even if the Discord interaction token is expired.
// That way, we at least get the prompt response on the backend, even if it
// can't be edited into the interaction. (important for token usage tracking).
//
// If the command is in a state prior to an OpenAI run being created, and the
// Discord interaction token is expired, execution is not resumed - we wouldn't
// want to push an OpenAI run for an interaction that can't be updated anymore.
//
// If the command state is ChatCommandStepFeedbackOpen, we launch the
// button timer again, as it would've been interrupted during a restart.
// If the token's already expired at this point, we just update the record
// to reflect the buttons don't work anymore (even if they may still be visible
// to the user).
func (d *DisConcierge) resumeChatCommand(
	ctx context.Context,
	c *ChatCommand,
) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	logger := c.handler.Logger()

	logger = logger.With(
		slog.Group("chat_command", chatCommandLogAttrs(*c)...),
	)
	if c.User != nil {
		logger = logger.With(slog.Group("user", userLogAttrs(*c.User)...))
	}
	ctx = WithLogger(ctx, logger)
	if d.waitForPause(ctx) {
		// we may have updated the runtime config while the bot was paused
		c.handler = d.getInteractionHandlerFunc(
			ctx,
			&discordgo.InteractionCreate{
				Interaction: &discordgo.Interaction{
					AppID: c.AppID,
					ID:    c.InteractionID,
					Token: c.Token,
				},
			},
		)
	}

	maxAttempts := c.handler.Config().ChatCommandMaxAttempts
	if maxAttempts > 0 && c.Attempts >= maxAttempts {
		c.setAbandoned(ctx, logger, d)
		return nil
	}

	triggerResume := false

	defer func() {
		if triggerResume {
			if _, updErr := d.writeDB.UpdatesWhere(
				&ChatCommand{},
				map[string]any{columnChatCommandAttempts: c.Attempts + 1},
				"id = ?",
				c.ID,
			); updErr != nil {
				logger.ErrorContext(ctx, "error updating attempts", tint.Err(updErr))
			}
		} else {
			logger.InfoContext(
				ctx,
				fmt.Sprintf("resume command execution: %v", triggerResume),
			)
		}
	}()

	if c.State.StopProcessing() {
		logger.InfoContext(ctx, "final state seen")
		return nil
	}

	now := time.Now().UTC()

	tokenExpired := c.TokenExpires <= now.UnixMilli()

	switch c.State {
	case ChatCommandStateReceived, ChatCommandStateQueued:
		if tokenExpired {
			logger.Warn("token expired on resume")
			if _, updErr := d.writeDB.Update(
				c,
				columnChatCommandState,
				ChatCommandStateExpired,
			); updErr != nil {
				logger.ErrorContext(ctx, "error updating state", tint.Err(updErr))
			}
		} else {
			triggerResume = true
			logger.Info(fmt.Sprintf("resuming from state: %s", c.State))
			c.enqueue(ctx, d)
		}
		return nil
	}

	switch c.RunStatus {
	case openai.RunStatusInProgress:
		triggerResume = true
		logger.Info(fmt.Sprintf("resuming from run_status: %s", c.RunStatus))
		c.enqueue(ctx, d)
		return nil
	case openai.RunStatusQueued:
		triggerResume = true
		c.enqueue(ctx, d)
		return nil
	}

	switch c.Step {
	case ChatCommandStepCreatingMessage, ChatCommandStepCreatingThread:
		if !tokenExpired {
			triggerResume = true
			logger.Info(fmt.Sprintf("resuming step: %s", c.Step))
			c.enqueue(ctx, d)
		}
	case ChatCommandStepCreatingRun:
		if c.RunID != "" || !tokenExpired {
			triggerResume = true
			logger.Info(fmt.Sprintf("resuming step: %s", c.Step))
			c.enqueue(ctx, d)
		}
	case ChatCommandStepPollingRun:
		triggerResume = true
		logger.Info(fmt.Sprintf("resuming step: %s", c.Step))
		c.enqueue(ctx, d)
	case ChatCommandStepListMessage:
		triggerResume = true
		logger.Info(fmt.Sprintf("resuming step: %s", c.Step))
		go c.finalizeCompletedRun(ctx, d)
	case ChatCommandStepFeedbackOpen:
		if tokenExpired {
			d.logger.InfoContext(
				ctx,
				"interaction expired, setting feedback as closed",
				"chat_command", c,
			)
			c.finalizeExpiredButtons(ctx, d.writeDB)
			return nil
		}
		logger.InfoContext(ctx, "starting button timer")

		go d.chatCommandUnselectedButtonTimer(ctx, c)
		return nil
	}

	return nil
}

// hydrateChatCommand loads/sets Interaction data from the database and current
// process, and sets button components
func (d *DisConcierge) hydrateChatCommand(
	ctx context.Context,
	c *ChatCommand,
) error {
	logger, ok := ContextLogger(ctx)
	if logger == nil || !ok {
		logger = slog.Default()
		ctx = WithLogger(ctx, logger)
	}
	logger.Info("hydrating!", "chat_command_id", c.ID)
	if c.mu == nil {
		c.mu = &sync.RWMutex{}
	}

	if c.handler == nil {
		c.handler = d.getInteractionHandlerFunc(
			ctx,
			&discordgo.InteractionCreate{
				Interaction: &discordgo.Interaction{
					AppID: c.AppID,
					ID:    c.InteractionID,
					Token: c.Token,
				},
			},
		)
	}

	u := d.writeDB.GetUser(c.UserID)
	c.User = u

	err := d.db.First(c).Error
	if err != nil {
		logger.ErrorContext(ctx, "error hydrating ChatCommand", tint.Err(err))
	}
	return err
}

// chatCommandUnselectedButtonTimer waits until a minute before the Interaction's
// token expires, and then removes any buttons from the interaction that
// haven't been selected (selected buttons should already be disabled, but
// should remain visible)
func (d *DisConcierge) chatCommandUnselectedButtonTimer(
	ctx context.Context,
	c *ChatCommand,
) {
	d.buttonTimersRunning.Add(1)
	defer d.buttonTimersRunning.Add(-1)

	logger, ok := ContextLogger(ctx)
	if logger == nil || !ok {
		logger = slog.Default()
		ctx = WithLogger(ctx, logger)
	}
	tokenExpires := time.UnixMilli(c.TokenExpires).UTC()
	now := time.Now().UTC()

	ctx, cancel := context.WithDeadline(ctx, tokenExpires)
	defer cancel()

	removeAt := c.removeButtonsAt()

	ds := removeAt.Sub(now)

	if ds <= 0 {
		c.mu.Lock()
		defer c.mu.Unlock()

		c.finalizeExpiredButtons(ctx, d.writeDB)
		return
	}

	if ds > 0 && ds < time.Minute {
		c.mu.Lock()
		defer c.mu.Unlock()
		if err := c.removeUnusedFeedbackButtons(
			ctx,
			d.writeDB,
		); err != nil {
			logger.ErrorContext(ctx, "error removing unselected buttons", tint.Err(err))
		}
		return
	}

	logger.InfoContext(
		ctx,
		fmt.Sprintf(
			"scheduling buttons to be disabled at: %s",
			removeAt.String(),
		),
		"remove_at", removeAt,
		"remove_in", ds,
	)
	timer := time.NewTimer(ds)
	defer func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
				//
			default:
				//
			}
		}
	}()

	// periodically emit a countdown log
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.InfoContext(ctx, "context canceled, stopping timer to remove buttons")
			return
		case <-ticker.C:
			timeRemaining := time.Until(removeAt)
			logger.DebugContext(
				ctx,
				fmt.Sprintf("%s remaining until buttons disabled", timeRemaining),
			)
		case <-timer.C:
			if err := c.removeUnusedFeedbackButtons(
				ctx,
				d.writeDB,
			); err != nil {
				logger.ErrorContext(ctx, "error removing unselected buttons", tint.Err(err))
			}
			return
		}
	}
}

//
// func (d *DisConcierge) listenForUserCacheRefresh(ctx context.Context) {
// 	if d.config.DatabaseType != dbTypePostgres {
// 		return
// 	}
//
// 	logger := d.logger.With(loggerNameKey, "user_cache_listener")
//
// 	config, err := pgxpool.ParseConfig(d.config.Database)
// 	if err != nil {
// 		logger.ErrorContext(ctx, "Error parsing database config", tint.Err(err))
// 		return
// 	}
//
// 	pool, err := pgxpool.NewWithConfig(ctx, config)
//
// 	defer pool.Close()
//
// 	// Start listening for notifications
// 	conn, err := pool.Acquire(ctx)
// 	if err != nil {
// 		logger.ErrorContext(ctx, "Error acquiring connection", tint.Err(err))
// 		return
// 	}
// 	defer conn.Release()
//
// 	_, err = conn.Exec(ctx, "LISTEN ?", d.dbNotifier.UserCacheChannelName())
// 	if err != nil {
// 		logger.ErrorContext(ctx, "Error setting up listener", tint.Err(err))
// 		return
// 	}
//
// 	logger.InfoContext(ctx, "Started listening for user cache reload signals")
//
// 	for ctx.Err() == nil {
// 		notification, e := conn.Conn().WaitForNotification(ctx)
// 		if e != nil {
// 			logger.ErrorContext(ctx, "Error waiting for notification", tint.Err(err))
// 			time.Sleep(5 * time.Second) // Wait before retrying
// 			continue
// 		}
//
// 		if notification.Channel == d.dbNotifier.UserCacheChannelName() {
// 			if notification.Payload == d.dbNotifier.ID() {
// 				logger.InfoContext(ctx, "received NOTIFY from self, ignoring")
// 				continue
// 			}
// 			logger.InfoContext(ctx, "Received notification to reload user cache")
// 			select {
// 			case d.triggerUserCacheRefreshCh <- true:
// 				logger.Info("sent cache refresh signal from postgres listener")
// 			case <-time.After(5 * time.Second):
// 				logger.Warn("timed out sending config refresh signal")
// 			}
// 		}
// 	}
// }
//
// func (d *DisConcierge) listenForRuntimeConfigUpdates(ctx context.Context) {
// 	if d.config.DatabaseType != dbTypePostgres {
// 		return
// 	}
//
// 	logger := d.logger.With(loggerNameKey, "runtime_config_listener")
//
// 	config, err := pgxpool.ParseConfig(d.config.Database)
// 	if err != nil {
// 		logger.ErrorContext(ctx, "Error parsing database config", tint.Err(err))
// 		return
// 	}
//
// 	pool, err := pgxpool.NewWithConfig(ctx, config)
//
// 	defer pool.Close()
//
// 	// Start listening for notifications
// 	conn, err := pool.Acquire(ctx)
// 	if err != nil {
// 		logger.ErrorContext(ctx, "Error acquiring connection", tint.Err(err))
// 		return
// 	}
// 	defer conn.Release()
//
// 	_, err = conn.Exec(
// 		ctx,
// 		"LISTEN ?",
// 		d.dbNotifier.RuntimeConfigChannelName(),
// 	)
// 	if err != nil {
// 		logger.ErrorContext(ctx, "Error setting up listener", tint.Err(err))
// 		return
// 	}
//
// 	logger.InfoContext(ctx, "Started listening for runtime config updates")
//
// 	for ctx.Err() == nil {
// 		notification, e := conn.Conn().WaitForNotification(ctx)
// 		if e != nil {
// 			logger.ErrorContext(ctx, "Error waiting for notification", tint.Err(err))
// 			time.Sleep(5 * time.Second) // Wait before retrying
// 			continue
// 		}
//
// 		if notification.Channel == d.dbNotifier.RuntimeConfigChannelName() {
// 			if notification.Payload == d.dbNotifier.ID() {
// 				logger.InfoContext(ctx, "received NOTIFY from self, ignoring")
// 				continue
// 			}
// 			logger.InfoContext(ctx, "Received notification for runtime config update")
// 			select {
// 			case d.triggerRuntimeConfigRefreshCh <- true:
// 				logger.Info("sent runtime config refresh signal from postgres listener")
// 			case <-time.After(5 * time.Second):
// 				logger.Warn("timed out sending config refresh signal")
// 			}
// 		}
// 	}
// }
