package disconcierge

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"github.com/bwmarrin/discordgo"
	"github.com/gin-gonic/gin"
	"github.com/lmittmann/tint"
	openai "github.com/sashabaranov/go-openai"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
	"gorm.io/gorm"
	"io"
	"log/slog"
	"net/http"
	"os"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"
)

var (
	// When building, set these like:
	// -ldflags "-X github.com/arcward/disconcierge/disconcierge.Version=$$(date +'%Y%m%d')"

	Version   = "dev"
	CommitSHA = "unknown"
	BuildTime = "unknown"

	// WaitForResumeCheckInterval is the duration to sleep between checking
	// whether the bot has been un-paused/resumed (when [RuntimeConfig.Paused is
	// no longer true).
	// For example, if [OpenAI.CreateRun] is called while the bot is paused,
	// it will only actually execute the API call once the bot is unpaused.
	// Until then, it will check every [WaitForResumeCheckInterval] to see if
	// it's been un-paused/resumed.
	WaitForResumeCheckInterval = 5 * time.Second

	// UserWorkerSendTimeout is the amount of time to wait when sending
	// a ChatCommand or ClearCommand to userCommandWorker.clearCh or
	// userCommandWorker.chatCh before abandoning the request. This is
	// intended to prevent users from running multiple commands concurrently,
	// which still allowing some wiggle room for a slow receiver. Set this
	// too low, and the user receives false-positive rate limits... set it too
	// high, the user will be able to 'queue' multiple commands.
	UserWorkerSendTimeout = time.Second

	// busyInteractionDeleteDelay is the amount of time to wait
	// before deleting a 'busy' interaction that was sent to
	// the user (ex: when they use /chat while their previous
	// /chat hasn't finished yet)
	busyInteractionDeleteDelay = 20 * time.Second

	// ShutdownAnnouncementInterval logs a message at this interval when
	// a graceful shutdown is initiated, providing a countdown to the
	// time a forced shutdown would take place if the shutdown is taking
	// too long
	ShutdownAnnouncementInterval = 10 * time.Second

	UpdateExpiredRunCheckInterval           = 30 * time.Minute
	ErrChatCommandTooOld                    = errors.New("request too old")
	defaultLogWriter              io.Writer = os.Stdout
)

type ShutdownError struct {
	message string
	cause   error
}

func (e *ShutdownError) Error() string {
	return e.message
}

func (e *ShutdownError) Unwrap() error {
	return e.cause
}

func NewShutdownError(msg string) *ShutdownError {
	return &ShutdownError{
		message: msg,
		cause:   context.Canceled,
	}
}

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
		return nil, errors.Join(errs...)
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

	d.requestQueue = NewChatCommandMemoryQueue(
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
func (d *DisConcierge) Run(parentCtx context.Context) error {
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

	parentCtx = WithLogger(parentCtx, logger)

	// this is the 'runtime' context, which triggers a graceful shutdown
	// when canceled
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)

	d.webhookInteractionHandler = webhookReceiveHandler(ctx, d)

	logger.LogAttrs(ctx, slog.LevelInfo, "starting", slog.Any("config", d.config))
	if d.signalReady == nil {
		d.signalReady = make(chan struct{}, 1)
	}

	go func() {
		select {
		case <-parentCtx.Done():
			d.logger.Warn("parent context canceled, canceling runtime context")
			cancel(NewShutdownError("received shutdown signal"))
		case <-d.signalStop:
			d.logger.Warn("got stop signal, canceling")
			cancel(NewShutdownError("received shutdown signal"))
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
	case e := <-initErr:
		if e != nil {
			logger.ErrorContext(ctx, "init error", tint.Err(e))
			_ = d.api.httpServer.Close()
			if d.discordWebhookServer != nil {
				_ = d.discordWebhookServer.httpServer.Close()
			}
			return e
		} else {
			logger.Info("init complete")
		}
	}

	// primary application functions - broadcasting events to
	// websocket subscribers, and monitoring/handling the ChatCommand queue
	runtimeWG := &sync.WaitGroup{}

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

	runtimeWG.Add(1)
	go func() {
		defer runtimeWG.Done()
		_ = d.populateExpiredInteractionRunStatus(
			ctx,
			30*time.Second,
			2*time.Minute,
			2,
		)
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

	d.startRuntimeConfigRefresher(ctx, runtimeWG, logger)
	d.startUserCacheRefresher(ctx, runtimeWG)
	d.startUserUpdatedListener(ctx, runtimeWG)
	d.startDBNotifiers(ctx, runtimeWG)

	if e := d.discordInit(ctx, runtimeCfg, logger); e != nil {
		return e
	}

	d.signalReady <- struct{}{}
	d.logger.InfoContext(ctx, "sent ready signal")

	// block until something cancels the main runtime context - generally
	// from an interrupt, or the `/api/quit` endpoint
	stopCh := make(chan struct{}, 1)
	go func() {
		<-ctx.Done()
		stopCh <- struct{}{}
	}()
	<-stopCh

	shutdownCtx, shutdownCancel := d.shutdownContext()
	defer shutdownCancel()
	deadline, _ := shutdownCtx.Deadline()
	d.logger.InfoContext(
		ctx,
		"exiting!",
		"shutdown_timeout", d.config.ShutdownTimeout,
		"shutdown_deadline", deadline,
	)

	runtimeFinished := make(chan struct{}, 1)
	go func() {
		runtimeWG.Wait()
		runtimeFinished <- struct{}{}
	}()
	select {
	case <-runtimeFinished:
		return d.shutdown(shutdownCtx)
	case <-shutdownCtx.Done():
		d.logger.Warn("timed out waiting for runtime processes")
		return shutdownCtx.Err()
	}
}

// RuntimeConfig returns a copy of the current runtime configuration
func (d *DisConcierge) RuntimeConfig() RuntimeConfig {
	d.cfgMu.RLock()
	defer d.cfgMu.RUnlock()
	return *d.runtimeConfig
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
			context.TODO(),
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
			context.TODO(),
			d.runtimeConfig,
			columnRuntimeConfigPaused,
			false,
		); err != nil {
			d.logger.ErrorContext(ctx, "unable to set resumed in db", tint.Err(err))
		}
	}

	return true
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
		if _, createErr := d.writeDB.Create(context.TODO(), interactionLog); createErr != nil {
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
		if modalErr := d.interactionResponseToSubmittedModal(ctx, i, handler); modalErr != nil {
			logger.Error("error with modal response", tint.Err(modalErr))
		}
	case discordgo.InteractionMessageComponent:
		e := d.interactionResponseToMessageComponent(ctx, i, handler)
		if e != nil {
			logger.ErrorContext(ctx, "error with component response", tint.Err(e))
		}
	case discordgo.InteractionApplicationCommand:
		commandName := i.ApplicationCommandData().Name

		ackCtx, ackCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer ackCancel()
		ackCtx = WithLogger(ackCtx, logger)

		u, _, e := d.GetOrCreateUser(ackCtx, *discordUser)

		if e != nil {
			logger.ErrorContext(ackCtx, "error getting user", tint.Err(e))
			return
		}

		logger = logger.With(slog.Group("user", userLogAttrs(*u)...))

		// ignore any interactions from ignored users, or from
		// non-priority users while the bot is paused
		if u.Ignored || (d.paused.Load() && !u.Priority) {
			d.handleIgnoredUserCommand(ctx, handler, u, i)
			return
		}

		switch commandName {
		case DiscordSlashCommandChat, DiscordSlashCommandPrivate:
			ackErr := handler.Respond(
				ackCtx,
				d.discord.ackResponse(commandName),
			)
			if ackErr != nil {
				logger.ErrorContext(ackCtx, "error acknowledging interaction", tint.Err(ackErr))
			}

			chatCommand, cmdErr := NewChatCommand(u, i)
			if cmdErr != nil {
				logger.ErrorContext(ctx, "error creating chat_command", tint.Err(cmdErr))
				return
			}

			if i.ApplicationCommandData().Name == DiscordSlashCommandPrivate {
				chatCommand.Private = true
			}
			chatCommand.handler = handler

			if ackErr != nil {
				// abort any command that can't be acknowledged in time.
				// since it's not acked, we can't respond with an error message,
				// so just save the record and return
				chatCommand.Error = NullableString(ackErr.Error())
				chatCommand.State = ChatCommandStateAborted
				if _, createErr := d.writeDB.Create(
					context.TODO(),
					chatCommand,
				); createErr != nil {
					logger.Error("error saving chat command", tint.Err(createErr))
				}
				return
			}

			chatCommand.Acknowledged = true

			followupCtx, followupCancel := context.WithTimeout(
				context.Background(),
				d.config.Queue.MaxAge,
			)
			defer followupCancel()

			if _, createErr := d.writeDB.Create(followupCtx, chatCommand); createErr != nil {
				chatCommand.finalizeWithError(ctx, d, createErr)
				return
			}

			msg, respErr := handler.GetResponse(followupCtx)
			if respErr != nil {
				chatCommand.Acknowledged = false
				logger.Error("error getting interaction response", tint.Err(respErr))
				chatCommand.finalizeWithError(ctx, d, respErr)
				return
			}

			if chatCommand.DiscordMessageID == "" && msg != nil {
				chatCommand.DiscordMessageID = msg.ID
			}

			if _, updErr := d.writeDB.Updates(
				followupCtx, chatCommand, map[string]any{
					columnChatCommandDiscordMessageID: chatCommand.DiscordMessageID,
				},
			); updErr != nil {
				logger.ErrorContext(ctx, "error updating chat_command", tint.Err(updErr))
				chatCommand.finalizeWithError(followupCtx, d, updErr)
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
			ackErr := handler.Respond(ackCtx, d.discord.ackResponse(commandName))
			if ackErr != nil {
				logger.ErrorContext(ctx, "error acknowledging interaction", tint.Err(ackErr))
				clearRec.State = ClearCommandStateFailed
				if _, dbErr := d.writeDB.Create(context.TODO(), clearRec); dbErr != nil {
					logger.Error("error saving clear command", tint.Err(dbErr))
				}
				return
			}
			clearRec.Acknowledged = true
			d.runClearCommand(ctx, handler, clearRec)
		}
	}
}

func (d *DisConcierge) shutdownAPIServer(ctx context.Context) error {
	d.logger.InfoContext(ctx, "stopping http server")
	err := d.api.httpServer.Shutdown(ctx)
	d.logger.InfoContext(ctx, "http server stopped")
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			d.logger.Warn("shutdown timeout exceeded, closing all api connections")
			return d.api.httpServer.Close()
		} else if !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("error shutting down webhook server: %w", err)
		}
	}
	d.logger.InfoContext(ctx, "api server stopped")
	return nil
}

func (d *DisConcierge) shutdownWebhookServer(ctx context.Context) error {
	d.logger.InfoContext(ctx, "stopping webhook http server")
	err := d.discordWebhookServer.httpServer.Shutdown(ctx)

	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			d.logger.Warn("shutdown timeout exceeded, closing all webhook connections")
			return d.discordWebhookServer.httpServer.Close()
		} else if !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("error shutting down webhook server: %w", err)
		}
	}
	d.logger.InfoContext(ctx, "webhook http server stopped")
	return nil
}

// shutdownDiscordSession closes the discord gateway connection and removes
// all registered discord event handlers.
func (d *DisConcierge) shutdownDiscordSession(ctx context.Context) error {
	if d.discord.session == nil {
		return nil
	}
	d.logger.InfoContext(ctx, "closing discord session")
	errs := make([]error, 0, 2)
	errs = append(errs, d.discord.session.Close())
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
			if ctx.Err() != nil {
				errs = append(errs, ctx.Err())
				break
			}
			h()
		}
		d.logger.InfoContext(ctx, "finished removing handlers")
	}
	return errors.Join(errs...)
}

// stopUserWorkers sends a shutdown signal to each userCommandWorker, and
// for each, waits on the return signal
func (d *DisConcierge) stopUserWorkers(ctx context.Context) error {
	d.userWorkerMu.Lock()
	defer d.userWorkerMu.Unlock()

	g := new(errgroup.Group)

	for wid, worker := range d.userWorkers {
		g.Go(
			func() error {
				d.logger.Info("sending stop signal to worker", "worker", worker)
				select {
				case worker.signalStop <- struct{}{}:
					d.logger.Info("sent stop signal, waiting on confirmation", "worker", worker)
				case <-ctx.Done():
					d.logger.Info("graceful shutdown cancelled, aborting", "worker", worker)
					return fmt.Errorf("worker %q shutdown timed out: %w", wid, ctx.Err())
				}

				select {
				case <-worker.stopped:
					d.logger.Info("worker stopped", "worker", worker)
				case <-ctx.Done():
					d.logger.Info("graceful shutdown cancelled, aborting", "worker", worker)
					return fmt.Errorf("worker %q shutdown timed out: %w", wid, ctx.Err())
				}
				return nil
			},
		)
	}

	err := g.Wait()
	d.userWorkers = map[string]*userCommandWorker{}
	return err
}

// flushRequestQueue clears the request queue and logs the number of
// requests purged
func (d *DisConcierge) flushRequestQueue(ctx context.Context) error {
	queueFlushCt := 0
	for ctx.Err() == nil && d.requestQueue.Len() > 0 {
		rq := d.requestQueue.Clear(ctx)
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
	if ctx.Err() != nil {
		return fmt.Errorf("request queue flush interrupted: %w", ctx.Err())
	}
	return nil
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

		// run the worker - when the function exits (worker stopped),
		// we can delete it from the map
		userWorker.Run(ctx, startSignal)

		d.userWorkerMu.Lock()
		defer d.userWorkerMu.Unlock()

		w, ok := d.userWorkers[u.ID]
		if ok && w == userWorker {
			// only delete if it's actually the same struct, on the off chance
			// that another worker for the same user has been created in the meantime
			delete(d.userWorkers, u.ID)
		}
	}()

	d.userWorkers[u.ID] = userWorker
	<-startSignal
	return userWorker
}

func (d *DisConcierge) startDBNotifiers(ctx context.Context, runtimeWG *sync.WaitGroup) {
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
		"(state IN ? OR run_status IN ?) "+
			"AND token_expires is not null "+
			"AND token_expires >= ?",
		[]string{
			ChatCommandStateReceived.String(),
			ChatCommandStateInProgress.String(),
			ChatCommandStateQueued.String(),
		},
		[]string{
			string(openai.RunStatusInProgress),
			string(openai.RunStatusQueued),
		},
		time.Now().UnixMilli(),
	)

	if rv.Error != nil {
		logger.ErrorContext(ctx, "error performing catchup query", tint.Err(rv.Error))
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

// shutdownContext returns a context with a deadline of the current time,
// plus the configured shutdown timeout. This is used to set a limit on
// how long the graceful shutdown process can take.
func (d *DisConcierge) shutdownContext() (context.Context, context.CancelFunc) {
	shutdownStart := time.Now()
	shutdownDeadline := shutdownStart.Add(d.config.ShutdownTimeout)
	shutdownCtx, shutdownCancel := context.WithDeadline(
		context.Background(),
		shutdownDeadline,
	)
	return shutdownCtx, shutdownCancel
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

		if statusErr := d.discord.session.UpdateCustomStatus(
			runtimeCfg.DiscordCustomStatus,
		); statusErr != nil {
			logger.Error("error updating discord status", tint.Err(statusErr))
		}

	}
	return nil
}

// startWebhookServer starts the Discord webhook server in a separate
// goroutine. The webhook server, when enabled, is used to receive
// Discord interactions via webhook, rather than gateway connection.
func (d *DisConcierge) startWebhookServer(ctx context.Context, runtimeWG *sync.WaitGroup) {
	runtimeWG.Add(1)
	go func() {
		defer runtimeWG.Done()
		httpErr := d.discordWebhookServer.Serve(ctx)
		if httpErr != nil && !errors.Is(httpErr, http.ErrServerClosed) {
			d.logger.ErrorContext(ctx, "error serving webhook HTTP", tint.Err(httpErr))
		}
	}()
}

// expiredInteractionRunUpdater, every UpdateExpiredRunCheckInterval,
// checks for ChatCommand interactions with expired tokens, with in-progress
// or queued OpenAI runs, and attempts to back-populate the result of those
// runs, without attempting to update the discord interaction.
func (d *DisConcierge) expiredInteractionRunUpdater(ctx context.Context) {
	ticker := time.NewTicker(UpdateExpiredRunCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			d.logger.Info("stopping run updater")
			return
		case <-ticker.C:
			_ = d.populateExpiredInteractionRunStatus(
				ctx,
				15*time.Second,
				time.Minute,
				2,
			)
		}
	}
}

// catchupAndWatchQueue first sets any ChatCommand without an in-progress or
// queued run as 'expired' if the interaction token has expired.
// Next, it attempts to finish any in-progress commands.
// Finally, it starts watching the queue for new commands.
func (d *DisConcierge) catchupAndWatchQueue(ctx context.Context, logger *slog.Logger) {
	logger.InfoContext(ctx, "starting run catchup")

	affected, updateErr := d.writeDB.UpdatesWhere(
		ctx,
		ChatCommand{},
		map[string]any{
			columnChatCommandState: ChatCommandStateExpired,
		},
		"token_expires is not null AND token_expires < ? AND state IN ? AND run_status NOT IN ?",
		time.Now().UnixMilli(),
		[]ChatCommandState{
			ChatCommandStateInProgress,
			ChatCommandStateQueued,
		},
		[]openai.RunStatus{
			openai.RunStatusQueued,
			openai.RunStatusInProgress,
		},
	)
	if updateErr != nil {
		logger.Error("error updating old commands", tint.Err(updateErr))
	} else {
		logger.Info(fmt.Sprintf("set %d records as expired", affected))
	}
	if catchupErr := d.catchupInterruptedRuns(ctx); catchupErr != nil {
		logger.ErrorContext(
			ctx,
			"error catching up interrupted runs",
			tint.Err(catchupErr),
		)
	}

	logger.InfoContext(ctx, "starting queue watcher")
	d.watchQueue(ctx, nil)
	logger.InfoContext(ctx, "queue watcher done")
}

// startUserCacheRefresher starts a goroutine that watches the channel for signals
// to reload the entire user cache
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

// startUserUpdatedListener starts a goroutine that watches the channel for
// signals to refresh specific users
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

// refreshUser reloads the user for given user ID from the database
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

// refreshRuntimeConfig replaces the current RuntimeConfig with the given
// RuntimeConfig. It also updates the current logging levels.
func (d *DisConcierge) refreshRuntimeConfig(ctx context.Context, force bool) {
	// TODO this is outdated, no longer serves its original purpose
	d.cfgMu.Lock()
	defer d.cfgMu.Unlock()

	runtimeConfigTTL := d.config.RuntimeConfigTTL

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
		d.runtimeConfig = &refreshConfig
		d.setRuntimeLevels(refreshConfig)
	} else {
		d.logger.Info("runtime config is up to date, skipping refresh")
	}
}

func (d *DisConcierge) refreshUserCache(_ context.Context) {
	d.writeDB.UserCacheLock()
	defer d.writeDB.UserCacheUnlock()
	_ = d.writeDB.LoadUsers()
}

// shutdown attempts to gracefully shut down the bot, close HTTP servers, etc.
func (d *DisConcierge) shutdown(ctx context.Context) error {
	d.logger.InfoContext(ctx, "shutting down")
	defer func() {
		if d.eventShutdown != nil {
			select {
			case d.eventShutdown <- struct{}{}:
			//
			case <-time.After(10 * time.Second):
				d.logger.Warn("timed out sending shutdown signal")
			}
		}
	}()

	runtimeStopEnd := time.Now()
	d.logger.InfoContext(
		ctx,
		"finished handling in-flight requests",
		"runtime_stopped", runtimeStopEnd,
	)
	g := new(errgroup.Group)

	// flush the queue
	g.Go(
		func() error {
			return d.flushRequestQueue(ctx)
		},
	)

	g.Go(
		func() error {
			return d.stopUserWorkers(ctx)
		},
	)

	g.Go(
		func() error {
			return d.shutdownAPIServer(ctx)
		},
	)

	if d.discordWebhookServer != nil {
		g.Go(
			func() error {
				return d.shutdownWebhookServer(ctx)
			},
		)
	}

	if d.discordWebhookServer != nil {
		g.Go(
			func() error {
				return d.shutdownDiscordSession(ctx)
			},
		)
	}

	// wait on the above, then send a signal that we're done

	// Graceful shutdown - at least until ctx is closed
	gracefulShutdownCh := make(chan struct{}, 1)
	go func() {
		d.logger.InfoContext(ctx, "waiting graceful shutdown")
		err := g.Wait()
		if err != nil {
			d.logger.Error("error(s) during shutdown", tint.Err(err))
		}

		if ctx.Err() == nil {
			gracefulShutdownCh <- struct{}{}
			d.logger.InfoContext(ctx, "all processes gracefully stopped")
			close(gracefulShutdownCh)
		}
	}()

	var tickerCh <-chan time.Time
	if ShutdownAnnouncementInterval > 0 {
		announcementTicker := time.NewTicker(ShutdownAnnouncementInterval)
		defer announcementTicker.Stop()
		tickerCh = announcementTicker.C
	}

	// if we get a signal on gracefulShutdownCh, everything stopped and
	// cleaned up normally.
	// otherwise, burn it all down!
	for {
		select {
		case <-gracefulShutdownCh:
			shutdownEnded := time.Now()
			d.logger.InfoContext(
				ctx,
				"shutdown complete",
				"shutdown_ended", shutdownEnded,
			)
			return nil
		case <-tickerCh:
			deadline, ok := ctx.Deadline()
			if ok {
				d.logger.Warn(
					fmt.Sprintf(
						"time until hard shutdown: %s",
						time.Until(deadline).String(),
					),
				)
			}
		case <-ctx.Done(): // timed out, enqueue closing stuff
			d.logger.Warn("did not stop in time, forcing close")
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
			botState = DefaultRuntimeConfig()

			if _, err := d.writeDB.Create(context.TODO(), &botState); err != nil {
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
		d.logger.Warn("admin credentials not set")
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

// initDiscordSession creates and opens a discord gateway websocket connection.
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
			func(_ *discordgo.Session, i *discordgo.InteractionCreate) {
				handler := d.getInteractionHandlerFunc(ctx, i)
				runtimeWG.Add(1)
				recoverPanic := handler.Config().RecoverPanic
				go func() {
					d.logger.Error("recover panic", tint.Err(fmt.Errorf("%v", recoverPanic)))
					if recoverPanic {
						defer func() {
							if rc := recover(); rc != nil {
								d.handleRecover(ctx, rc)
							}
							runtimeWG.Done()
						}()
					} else {
						runtimeWG.Done()
					}
					d.handleInteraction(ctx, handler)
				}()
			},
		),
		d.discord.session.AddHandler(
			func(_ *discordgo.Session, m *discordgo.MessageCreate) {
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
					slog.Group("interaction", interactionLogAttrs(*i)...),
				),
			}
			return handler
		}
	}
	return nil
}

// watchQueue is the main loop for handling ChatCommand requests.
func (d *DisConcierge) watchQueue(ctx context.Context, requestCh chan *ChatCommand) {
	defer func() {
		d.logger.InfoContext(
			ctx,
			"queue watcher stopped",
			"queue_size", d.requestQueue.Len(),
		)
	}()
	if requestCh == nil {
		requestCh = make(chan *ChatCommand)
	}
	d.requestQueue.requestCh = requestCh

	wg := &sync.WaitGroup{}
	defer wg.Wait()

	wg.Add(1)
	go func() {
		// Until the context is cancelled, continuously pops ChatCommand
		// instances off the queue

		defer func() {
			close(requestCh)
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

			logger.Info(
				"popped request",
				slog.Group(
					"chat_command",
					columnChatCommandStep, req.Step,
					columnChatCommandState, req.State,
				),
			)
			d.requestQueue.requestCh <- req
		}
	}()

	for req := range requestCh {
		logger := d.logger.With(
			slog.Group("chat_command", chatCommandLogAttrs(*req)...),
		)

		reqAge := req.Age()
		if (d.config.Queue.MaxAge > 0 && reqAge > d.config.Queue.MaxAge) && !req.OpenAIRunInProgress() {
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
					context.TODO(),
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
				"ignoring blocked user request",
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
					context.TODO(),
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

		if ctx.Err() != nil {
			// if we're stopping, instead of returning, update as many records
			// as we can with the above checks
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
			go func() {
				defer wg.Done()

				d.handleWorkerSendTimeout(ctx, wg, startedAt, req)
			}()
		}
		sendCancel()
	}
}

// handleWorkerSendTimeout handles the case where a request is already in
// progress for a user, so sending to the userCommandWorker channel times
// out. The request should be updated with a state to prevent it from
// being resumed/executed, and the user should get a message indicating
// why the bot isn't responding normally. The message, by default,
// should be deleted after a short delay, to avoid cluttering the chat.
func (d *DisConcierge) handleWorkerSendTimeout(
	ctx context.Context,
	wg *sync.WaitGroup,
	startedAt time.Time,
	r *ChatCommand,
) {
	config := r.handler.Config()

	reqLogger, ok := ContextLogger(ctx)
	if reqLogger == nil || !ok {
		reqLogger = slog.Default()
	}
	reqLogger = reqLogger.With(
		slog.Group("chat_command", chatCommandLogAttrs(*r)...),
	)
	ctx = WithLogger(ctx, reqLogger)

	reqLogger.WarnContext(ctx, "request already in progress for user")
	responseMsg := config.DiscordRateLimitMessage
	if responseMsg == "" {
		responseMsg = DefaultDiscordRateLimitMessage
		reqLogger.Warn(
			fmt.Sprintf(
				"Discord rate limit message not configured, using default: %q",
				responseMsg,
			),
		)
	}
	finishedAt := time.Now()

	reqLogger.Warn("command rate-limited due to worker send timeout")

	if _, err := d.writeDB.ChatCommandUpdates(
		context.TODO(), r, map[string]any{
			columnChatCommandState:      ChatCommandStateRateLimited,
			columnChatCommandStep:       "",
			columnChatCommandFinishedAt: &finishedAt,
			columnChatCommandStartedAt:  &startedAt,
			columnChatCommandResponse:   &responseMsg,
		},
	); err != nil {
		reqLogger.Error("error saving rate limited request", tint.Err(err))
	}

	if _, e := r.handler.Edit(ctx, &discordgo.WebhookEdit{Content: &responseMsg}); e != nil {
		return
	}
	reqLogger.InfoContext(
		ctx,
		fmt.Sprintf(
			"temporary busy message will be deleted in: %s",
			busyInteractionDeleteDelay.String(),
		),
	)

	wg.Add(1)
	go func() {
		defer wg.Done()

		deleteTimer := time.NewTimer(busyInteractionDeleteDelay)
		d.messageDeleteTimersRunning.Add(1)
		defer func() {
			deleteTimer.Stop()
			select {
			case <-deleteTimer.C:
			default:
			}
			d.messageDeleteTimersRunning.Add(-1)
		}()

		select {
		case <-ctx.Done():
			reqLogger.Info(
				"context cancelled, deleting rate-limited interaction response NOW",
			)
			delCtx, delCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer delCancel()
			r.handler.Delete(
				ctx,
				discordgo.WithRetryOnRatelimit(false),
				discordgo.WithContext(delCtx),
			)
		case <-deleteTimer.C:
			reqLogger.Info("deleting rate-limited interaction response")
			r.handler.Delete(ctx)
		}
	}()
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

	_ = d.writeDB.LoadUsers()
	return nil
}

// interactionResponseToSubmittedModal returns an interaction response, in
// response to the user clicking the 'Submit' button on the modal that's created when
// the user clicks the UserFeedbackOther button component
func (d *DisConcierge) interactionResponseToSubmittedModal(
	ctx context.Context,
	i *discordgo.InteractionCreate,
	handler InteractionHandler,
) error {
	logger, ok := ContextLogger(ctx)
	if logger == nil || !ok {
		logger = d.logger
		ctx = WithLogger(ctx, logger)
	}

	ackCtx, ackCancel := context.WithTimeout(ctx, discordAckTimeout)
	defer ackCancel()

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

	reportingDiscordUser := getDiscordUser(i)

	user, _, err := d.GetOrCreateUser(ctx, *reportingDiscordUser)
	if err != nil {
		logger.ErrorContext(ctx, "error getting reporting user", tint.Err(err))
		return fmt.Errorf("error getting reporting user: %w", err)
	}

	logger = logger.With("user", user)
	ctx = WithLogger(ctx, logger)

	chatCommand := reportData.ChatCommand

	userReport := UserFeedback{
		ChatCommandID: &chatCommand.ID,
		UserID:        &user.ID,
		Description:   feedbackTypeDescription[reportData.CustomID.ReportType],
		Type:          string(reportData.CustomID.ReportType),
		Detail:        reportData.Report,
		CustomID:      reportData.CustomID.ID,
	}

	defer func() {
		nctx, ncancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer ncancel()
		d.notifyDiscordUserFeedback(nctx, *chatCommand, userReport, *user)
	}()

	if _, err = d.writeDB.Create(context.TODO(), &userReport); err != nil {
		logger.ErrorContext(ctx, "error creating user feedback", tint.Err(err))
		return fmt.Errorf("error creating user feedback: %w", err)
	}

	// if for whatever reason we can't get the original content of the message,
	// we'll just update the interaction with the default response - otherwise,
	// we'd end up wiping out the message content with the update
	var content string
	if i.Message != nil {
		content = i.Message.Content
	}
	if content == "" && chatCommand.Response != nil {
		content = *chatCommand.Response
	}

	if content == "" {
		logger.Warn("no content to update")
		err = handler.Respond(
			ackCtx,
			&discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseDeferredMessageUpdate,
			},
			discordgo.WithContext(ackCtx),
		)
		if err != nil {
			logger.ErrorContext(ctx, "error editing interaction", tint.Err(err))
		}
		return err
	}

	feedbackCounts, err := GetFeedbackCounts(ctx, d.db, chatCommand.ID)
	if err != nil {
		logger.Error("error getting feedback counts", tint.Err(err))
		return err
	}
	buttonComponents := chatCommand.discordUserFeedbackComponents(feedbackCounts)

	err = handler.Respond(
		ackCtx,
		&discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseUpdateMessage,
			Data: &discordgo.InteractionResponseData{
				Content:    content,
				Components: buttonComponents,
			},
		},
		discordgo.WithContext(ackCtx),
	)

	if err != nil {
		logger.ErrorContext(ctx, "error editing interaction", tint.Err(err))
		return err
	}

	return nil
}

// interactionResponseToMessageComponent processes an interaction that's the result of
// a user clicking one of the FeedbackButtonType component buttons,
// and returns an interaction to respond with
func (d *DisConcierge) interactionResponseToMessageComponent(
	ctx context.Context,
	i *discordgo.InteractionCreate,
	handler InteractionHandler,
) error {
	logger, ok := ContextLogger(ctx)
	if logger == nil || !ok {
		logger = d.logger
		ctx = WithLogger(ctx, logger)
	}

	componentData := i.MessageComponentData()
	customID, err := decodeCustomID(componentData.CustomID)
	if err != nil {
		logger.ErrorContext(ctx, "error decoding custom_id", tint.Err(err))
		return fmt.Errorf("error decoding custom_id: %w", err)
	}

	logger = logger.With("custom_id", customID)
	ctx = WithLogger(ctx, logger)

	logger.InfoContext(ctx, "received discord button push")

	ackCtx, ackCancel := context.WithTimeout(ctx, discordAckTimeout)
	defer ackCancel()

	reportingDiscordUser := getDiscordUser(i)

	user, _, err := d.GetOrCreateUser(ctx, *reportingDiscordUser)
	if err != nil {
		logger.ErrorContext(ctx, "error getting reporting user", tint.Err(err))
		return fmt.Errorf("error getting reporting user: %w", err)
	}
	logger = logger.With("user", user)
	ctx = WithLogger(ctx, logger)

	if user.Ignored {
		logger.Warn("ignoring feedback from blocked user")
		return nil
	}

	config := d.RuntimeConfig()

	// Clicking the "Other" button responds to the interaction with a text
	// input modal, which creates a UserFeedback entry on submission,
	// whereas the other buttons create a UserFeedback record immediately
	if customID.ReportType == UserFeedbackOther {
		if !config.FeedbackEnabled {
			logger.Warn("feedback currently disabled, skipping modal")
			return nil
		}
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
		return handler.Respond(ackCtx, modalResponse, discordgo.WithContext(ackCtx))
	}

	var chatCommand ChatCommand
	rv := d.db.Where("custom_id = ?", customID.ID).Omit("User").Last(&chatCommand)
	if rv.Error != nil {
		logger.ErrorContext(
			ctx,
			"error finding chat_command for the given custom_id",
			tint.Err(rv.Error),
			"custom_id", customID.ID,
		)
		return fmt.Errorf(
			"error finding chat_command for custom_id '%s': %w",
			customID.ID, rv.Error,
		)
	}

	userReport := UserFeedback{
		ChatCommandID: &chatCommand.ID,
		UserID:        &user.ID,
		Type:          string(customID.ReportType),
		Description:   feedbackTypeDescription[customID.ReportType],
		CustomID:      customID.ID,
	}

	if !config.FeedbackEnabled {
		logger.Warn("feedback currently disabled, saving report but will not update the interaction")
		if _, err = d.writeDB.Create(context.TODO(), &userReport); err != nil {
			logger.ErrorContext(ctx, "error creating user feedback", tint.Err(err))
			return fmt.Errorf("error creating user feedback: %w", err)
		}
		return nil
	}

	userPreviouslySubmitted, err := UserPreviouslySubmittedFeedback(
		ctx,
		d.db,
		user.ID,
		chatCommand.ID,
		customID.ReportType,
	)

	if err != nil {
		logger.ErrorContext(ctx, "error getting user feedback info", tint.Err(err))
		return fmt.Errorf("error getting user feedback info: %w", err)
	}

	if userPreviouslySubmitted {
		logger.Warn("user already used this feedback button, ignoring")
		return handler.Respond(
			ackCtx,
			&discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseDeferredMessageUpdate,
			},
			discordgo.WithContext(ackCtx),
		)
	}

	if _, err = d.writeDB.Create(context.TODO(), &userReport); err != nil {
		logger.ErrorContext(ctx, "error creating user feedback", tint.Err(err))
		return fmt.Errorf("error creating user feedback: %w", err)
	}
	logger.InfoContext(ctx, "responding to button interaction")

	// if for whatever reason we can't get the original content of the message,
	// we'll just update the interaction with the default response - otherwise,
	// we'd end up wiping out the message content with the update
	var content string
	if i.Message != nil {
		content = i.Message.Content
	}
	if content == "" && chatCommand.Response != nil {
		content = *chatCommand.Response
	}
	defer func() {
		nctx, ncancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer ncancel()
		d.notifyDiscordUserFeedback(nctx, chatCommand, userReport, *user)
	}()

	if content == "" {
		logger.Error("no content to update")
		err = handler.Respond(
			ackCtx,
			&discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseDeferredMessageUpdate,
			},
			discordgo.WithContext(ackCtx),
		)
		if err != nil {
			logger.ErrorContext(ctx, "error editing interaction", tint.Err(err))
		}

		return err
	}

	feedbackCounts, err := GetFeedbackCounts(ctx, d.db, chatCommand.ID)
	if err != nil {
		logger.Error("error getting feedback counts", tint.Err(err))
		return err
	}

	buttonComponents := chatCommand.discordUserFeedbackComponents(feedbackCounts)

	err = handler.Respond(
		ctx,
		&discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseUpdateMessage,
			Data: &discordgo.InteractionResponseData{
				Content:    content,
				Components: buttonComponents,
			},
		},
	)
	if err != nil {
		logger.ErrorContext(ctx, "error editing interaction", tint.Err(err))
		return err
	}

	return nil
}

// notifyDiscordUserFeedback sends a discord message to the configured
// notification channel, reporting the given user feedback, with links to
// the UserFeedback and ChatCommand entries in the admin interface.
// Has no effect if [RuntimeConfig.DiscordNotificationChannelID] is not
// set, or if `RuntimeConfig.DiscordGatewayEnabled` is false.
func (d *DisConcierge) notifyDiscordUserFeedback(
	ctx context.Context,
	c ChatCommand,
	report UserFeedback,
	user User,
) {
	logger, ok := ContextLogger(ctx)
	if !ok || logger == nil {
		logger = d.logger.With("chat_command", c, "user_feedback", report)
		ctx = WithLogger(ctx, logger)
	}

	config := d.RuntimeConfig()

	channelID := config.DiscordNotificationChannelID
	if channelID == "" {
		logger.Warn("discord notification channel not enabled, will not send feedback to channel")
		return
	}

	if !config.DiscordGatewayEnabled {
		logger.Warn("discord gateway enabled, will not send feedback to channel")
	}
	feedbackType := FeedbackButtonType(report.Type)

	feedbackURL := fmt.Sprintf(
		"%s%s%d",
		d.config.API.ExternalURL,
		adminPathUserFeedback,
		report.ID,
	)
	chatCommandURL := fmt.Sprintf(
		"%s%s%d",
		d.config.API.ExternalURL,
		adminPathChatCommand,
		*report.ChatCommandID,
	)

	var notificationMessage string
	switch feedbackType {
	case UserFeedbackGood:
		notificationMessage = fmt.Sprintf(
			":thumbsup: `%s` reported [feedback: **%s**](%s) for [ChatCommand %d](%s)",
			user.GlobalName,
			report.Description,
			feedbackURL,
			*report.ChatCommandID,
			chatCommandURL,
		)

	default:
		notificationMessage = fmt.Sprintf(
			":thumbsdown: `%s` reported [feedback: **%s**](%s) for [ChatCommand %d](%s)\n",
			user.GlobalName,
			report.Description,
			feedbackURL,
			*report.ChatCommandID,
			chatCommandURL,
		)

	}

	sendCtx, sendCancel := context.WithTimeout(
		ctx,
		30*time.Second,
	)
	defer sendCancel()

	err := d.discord.channelMessageSend(
		channelID,
		notificationMessage,
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
	if _, dbErr := d.writeDB.Create(context.TODO(), clearRec); dbErr != nil {
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
				context.TODO(), clearRec, map[string]any{
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
func (d *DisConcierge) handleDiscordMessage(ctx context.Context, m *discordgo.MessageCreate) {
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
			if _, err := d.writeDB.Create(context.TODO(), &dm); err != nil {
				logger.ErrorContext(
					ctx,
					"error creating discord message log",
					tint.Err(err),
					"discord_message", dm,
				)
			} else {
				logger.InfoContext(
					ctx,
					"created new discord_message mentioning bot",
					"discord_message", dm,
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
			"interaction_id = ?", dm.InteractionID,
		).Error
		if err != nil {
			switch {
			case errors.Is(err, gorm.ErrRecordNotFound):
				logger.InfoContext(
					ctx,
					"no ChatCommand found for interaction",
					"interaction_id", dm.InteractionID,
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
					context.TODO(),
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

		if _, e := d.writeDB.Create(context.TODO(), chatCommand); e != nil {
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
		if _, e := d.writeDB.Create(context.TODO(), clearCmd); e != nil {
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
				context.TODO(),
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
				context.TODO(),
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
		logger.Info("resuming from queued", "chat_command", c)
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
		c.finalizeCompletedRun(ctx, d)
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
	logger.Debug("hydrating chat_command", "chat_command_id", c.ID)

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

// populateExpiredInteractionRunStatus attempts to retrieve the OpenAI
// run results for any ChatCommand from the past 24 hours with an expired
// discord interaction token (15 minutes), and updates the ChatCommand
// with the result.
// This is necessary to accurately track user token usage, because we may
// incur cost from a ChatCommand that was interrupted for some reason,
// and never had its OpenAI run status updated.
func (d *DisConcierge) populateExpiredInteractionRunStatus(
	ctx context.Context,
	pollInterval time.Duration,
	maxInterval time.Duration,
	maxErrors int,
) error {
	log, ok := ContextLogger(ctx)
	if !ok || log == nil {
		log = d.logger
		ctx = WithLogger(ctx, log)
	}
	var chatCommands []ChatCommand

	rv := d.db.WithContext(ctx).Where(
		"run_id is not null "+
			"AND run_id != ''"+
			"AND run_status IN ? "+
			"AND token_expires is not null "+
			"AND token_expires > ? "+
			"AND token_expires < ?",
		[]openai.RunStatus{
			openai.RunStatusInProgress,
			openai.RunStatusQueued,
			openai.RunStatus(""),
		},
		time.Now().Add(-24*time.Hour).UnixMilli(),
		time.Now().Add(-15*time.Minute).UnixMilli(),
	).Find(&chatCommands)

	if rv.Error != nil {
		log.Error("error getting pending runs", tint.Err(rv.Error))
		return rv.Error
	}
	if len(chatCommands) == 0 {
		log.Info("no chat command runs to update")
		return nil
	}
	log.InfoContext(ctx, fmt.Sprintf("found %d records to catch up", len(chatCommands)))

	g := new(errgroup.Group)
	for _, c := range chatCommands {
		g.Go(
			func() error {
				cmdCtx := WithLogger(ctx, log.With("chat_command", c))
				updateErr := d.openai.pollUpdateRunStatus(
					cmdCtx,
					d.writeDB,
					&c,
					pollInterval,
					maxInterval,
					maxErrors,
				)
				if updateErr != nil {
					return fmt.Errorf("error updating chat_command %d: %w", c.ID, updateErr)
				}
				return nil
			},
		)
	}

	if err := g.Wait(); g != nil {
		log.Error("error updating chat command runs", tint.Err(err))
		return err
	}
	return nil
}

// isShutdownErr takes the given error and context, and returns a boolean
// indicating whether the given error is ShutdownError, or whether the
// provided context has been cancelled with ShutdownError.
// This is to differentiate actual runtime errors (like a request timing out),
// from context errors resulting from a shutdown signal being sent (in which
// case we'd want to resume execution if we restart quickly enough)
func isShutdownErr(ctx context.Context, err error) bool {
	if err == nil {
		return false
	}
	var shutdownErr *ShutdownError
	if errors.As(err, &shutdownErr) {
		return true
	}
	if ctx.Err() != nil {
		causeErr := context.Cause(ctx)
		if causeErr != nil && errors.As(causeErr, &shutdownErr) {
			return true
		}
	}
	return false
}
