package disconcierge

import (
	"context"
	"errors"
	"fmt"
	"github.com/bwmarrin/discordgo"
	"github.com/lmittmann/tint"
	"github.com/sashabaranov/go-openai"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

var (
	clearCommandTimeout = 30 * time.Second
	workerIdleTimeout   = 2 * time.Minute
)

var (
	discordTokenDeadlineOffset = -3 * time.Minute
)

// workerLimiter manages rate limiting and idle timeout for user command workers.
//
// It keeps track of the last usage time for different types of commands and
// provides methods to check if a command is allowed based on cooldown periods.
// It also manages an idle timeout to determine when a worker should be stopped
// due to inactivity.
//
// Fields:
//   - LastClearTime: The timestamp of the last clear command.
//   - ClearCooldown: The cooldown period for clear commands.
//   - IdleTimeout: The duration after which a worker is considered idle.
//   - LastCommandAt: The timestamp of the last command of any type.
//   - mu: Mutex for ensuring thread-safe access to the struct's fields.
type workerLimiter struct {
	// LastClearTime is the timestamp of the most recent `/clear` command
	// for the lifetime of the worker
	LastClearTime time.Time

	// ClearCooldown is the duration after which a new `/clear` command
	// can be processed after the last one
	ClearCooldown time.Duration

	// IdleTimeout is the duration after which a worker is considered 'idle'
	IdleTimeout time.Duration

	// LastCommandAt is the last time any slash command was used for the
	// lifetime of this worker. If LastCommandAt+IdleTimeout is in the past,
	// the worker is considered idle and can be stopped.
	LastCommandAt time.Time

	mu sync.Mutex
}

// newWorkerLimiter creates a new workerLimiter with default values.
func newWorkerLimiter() *workerLimiter {
	return &workerLimiter{
		ClearCooldown: clearCommandTimeout,
		IdleTimeout:   workerIdleTimeout,
	}
}

// Expired checks if the worker has been idle for longer than the IdleTimeout.
//
// This method locks the workerLimiter to ensure thread-safe access to the LastCommandAt field,
// calculates the expiration time, and returns whether the current time is after
// the expiration time.
//
// Returns:
//   - time.Time: The calculated expiration time.
//   - bool: True if the current time is after the expiration time, indicating the
//     worker has expired.
func (w *workerLimiter) Expired() (time.Time, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := time.Now()

	expiresAt := w.LastCommandAt.Add(w.IdleTimeout)

	return expiresAt, now.After(expiresAt)
}

// AllowClear checks if a new `/clear` command can be processed based on the cooldown period.
//
// This method locks the workerLimiter to ensure thread-safe access to the LastClearTime field,
// and returns true if the cooldown period has passed since the last `/clear` command.
//
// Returns:
//   - bool: True if a new `/clear` command can be processed, false otherwise.
func (w *workerLimiter) AllowClear() bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.LastClearTime.IsZero() {
		return true
	}
	if time.Since(w.LastClearTime) >= w.ClearCooldown {
		return true
	}
	return false
}

// UsedClear should be called when the user successfully uses a `/clear` command.
// This updates the LastClearTime and LastCommandAt fields to the current time.
func (w *workerLimiter) UsedClear() {
	w.mu.Lock()
	defer w.mu.Unlock()

	now := time.Now()
	w.LastClearTime = now
	w.LastCommandAt = now
}

// SetLastCommand updates the LastCommandAt field to the provided timestamp.
func (w *workerLimiter) SetLastCommand(ts time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.LastCommandAt = ts
}

// TimeSinceLastCommand returns the duration since the last command was used.
func (w *workerLimiter) TimeSinceLastCommand() time.Duration {
	w.mu.Lock()
	defer w.mu.Unlock()
	return time.Since(w.LastCommandAt)
}

// userCommandWorker represents a worker dedicated to handling commands for a specific user.
// It ensures that only one command is processed at a time for each user, preventing
// concurrent execution of multiple commands from the same user.
//
// The worker listens on various channels for different types of commands (chat, clear)
// and processes them accordingly. It also handles message replies and run step logging.
type userCommandWorker struct {
	// user associated with this worker
	user   *User
	userMu *sync.Mutex

	// chatCh is the channel for receiving /chat and /private commands
	chatCh chan *ChatCommand

	// clearCh is the channel for receiving /clear commands
	clearCh chan *ClearCommand

	// lastCommandAt is the timestamp of the last command processed by this worker
	lastCommandAt atomic.Int64

	// signalStop is a channel for sending a stop signal to the worker
	signalStop chan struct{}

	// stopped is a channel for receiving a notification when the worker has stopped,
	// and the time it stopped
	stopped chan time.Time

	// limiter manages rate limiting and idle timeout for the worker
	limiter *workerLimiter

	// idleTimeoutCheckInterval is the interval at which the worker checks
	// whether it has been idle for longer than the idle timeout
	idleTimeoutCheckInterval time.Duration

	// dc is the DisConcierge instance associated with this worker
	dc *DisConcierge
}

func (w *userCommandWorker) User() User {
	w.userMu.Lock()
	defer w.userMu.Unlock()
	return *w.user
}

func (w *userCommandWorker) SetUser(u *User) {
	w.userMu.Lock()
	defer w.userMu.Unlock()
	w.user = u
}

// newUserWorker creates a new userCommandWorker with the provided DisConcierge and User.
func newUserWorker(dc *DisConcierge, u *User) *userCommandWorker {
	return &userCommandWorker{
		user:                     u,
		userMu:                   &sync.Mutex{},
		chatCh:                   make(chan *ChatCommand),
		clearCh:                  make(chan *ClearCommand),
		dc:                       dc,
		signalStop:               make(chan struct{}, 1),
		stopped:                  make(chan time.Time, 1),
		limiter:                  newWorkerLimiter(),
		idleTimeoutCheckInterval: time.Minute,
	}
}

// getRunSteps retrieves the run steps for a given ChatCommand and logs them.
//
// Parameters:
//   - ctx: The context for the operation, used for logging and cancellation.
//   - req: The ChatCommand for which to retrieve the run steps.
//
// Returns:
//   - error: An error if the run steps could not be retrieved or saved.
func (u *userCommandWorker) getRunSteps(
	ctx context.Context,
	req *ChatCommand,
) error {
	logger, ok := ContextLogger(ctx)
	if logger == nil || !ok {
		logger = slog.Default()
		ctx = WithLogger(ctx, logger)
	}

	runSteps, err := u.dc.openai.listRunSteps(ctx, req)
	if err != nil {
		logger.Error("error listing run steps", tint.Err(err))
	}
	if len(runSteps) > 0 {
		affected, insErr := u.dc.writeDB.Create(&runSteps)
		if insErr != nil {
			logger.Error("error saving run steps", tint.Err(err))
			return errors.Join(err, insErr)
		}
		logger.Info("saved run steps", "affected", affected)
	}
	return nil
}

// Run starts the worker, where it starts listening on the chatCh and
// clearCh channels for ChatCommand and ClearCommand requests, respectively.
// Completed ChatCommand requests are also forwarded to runStepCh to log
// openai.RunStep data to the database.
// To stop the run, cancel the provided context or send a signal
// on userCommandWorker.signalStop.
// If none of these events are seen, the function will automatically
// exit after the duration specified on userWorkerExpiry (default 2 minutes)
func (u *userCommandWorker) Run(
	ctx context.Context,
	startCh chan struct{},
) {
	log, ok := ContextLogger(ctx)
	if log == nil || !ok {
		log = slog.Default()
	}
	log = log.With(
		slog.Group("user", userLogAttrs(u.User())...),
	)
	ctx = WithLogger(ctx, log)

	defer func() {
		stopSignalCtx, stopSignalCancel := context.WithTimeout(
			context.Background(),
			5*time.Second,
		)
		select {
		case u.stopped <- time.Now():
			log.Info("sent stop notification")
		case <-stopSignalCtx.Done():
			log.Warn("timed out sending stop signal")
		}
		stopSignalCancel()
	}()

	log.InfoContext(ctx, "starting user worker")
	startedAt := time.Now()
	ticker := time.NewTicker(u.idleTimeoutCheckInterval)

	defer func() {
		log.InfoContext(
			ctx,
			"stopping user worker",
			"started_at", startedAt,
		)
		ticker.Stop()

		endedAt := time.Now()
		log.InfoContext(
			ctx,
			"stopped user worker",
			"stopped_at", endedAt,
			"runtime", endedAt.Sub(startedAt),
		)
	}()

	startCh <- struct{}{}
	close(startCh)
	wg := &sync.WaitGroup{}
	defer func() {
		log.InfoContext(ctx, "waiting on goroutines")
		wg.Wait()
	}()

	u.limiter.SetLastCommand(time.Now())
	for {
		select {
		case <-ctx.Done():
			log.WarnContext(ctx, "context canceled")
			return
		case <-u.signalStop:
			log.WarnContext(ctx, "got stop signal")
			return
		case <-ticker.C:
			expiresAt, isExpired := u.limiter.Expired()
			if isExpired {
				log.InfoContext(
					ctx,
					"no commands seen in 2 minutes, stopping worker",
					"last_command_at", u.limiter.LastCommandAt,
					"worker_expired", expiresAt,
				)
				return
			}
			user := u.User()
			log.InfoContext(
				ctx,
				fmt.Sprintf(
					"%q (%q): worker expires in: %s",
					user.GlobalName,
					user.Username,
					expiresAt.Round(time.Second).Sub(time.Now().Round(time.Second)).String(),
				),
			)
		case req := <-u.chatCh:
			u.handleChatCommand(ctx, log, req, ticker)
		case req := <-u.clearCh:
			u.handleClearCommand(ctx, log, req, ticker)
		}
	}
}

func (u *userCommandWorker) handleClearCommand(
	ctx context.Context,
	log *slog.Logger,
	req *ClearCommand,
	ticker *time.Ticker,
) {
	log.InfoContext(ctx, "got clear command", "clear_command", req)

	var allowClear bool
	user := u.User()
	if user.Priority {
		allowClear = true
	} else {
		allowClear = u.limiter.AllowClear()
	}

	if !allowClear {
		u.dc.logger.WarnContext(ctx, "clear command rate limited", columnUserID, user.ID)
		responseMsg := clearCommandResponseTooSoon
		started := time.Now()
		swg := &sync.WaitGroup{}

		swg.Add(1)
		go func() {
			defer swg.Done()
			if _, err := u.dc.writeDB.Updates(
				req,
				map[string]any{
					columnClearCommandStartedAt:  &started,
					columnClearCommandResponse:   &responseMsg,
					columnClearCommandFinishedAt: &started,
					columnClearCommandState:      ClearCommandStateIgnored,
				},
			); err != nil {
				u.dc.logger.Error("error saving rate limited request", tint.Err(err))
			}
		}()

		swg.Add(1)
		go func() {
			defer swg.Done()
			_, _ = req.handler.Edit(
				ctx,
				&discordgo.WebhookEdit{Content: &responseMsg},
			)
		}()

		swg.Wait()

		return
	}
	u.limiter.UsedClear()
	clearCtx, clearCancel := context.WithTimeout(ctx, clearCommandTimeout)
	clearDoneCh := make(chan struct{}, 1)

	go func() {
		if err := req.execute(clearCtx, u.dc); err != nil {
			u.dc.logger.ErrorContext(ctx, "error executing clear command", tint.Err(err))
		}
		clearDoneCh <- struct{}{}
	}()

	select {
	case <-clearDoneCh:
	//
	case <-clearCtx.Done():
		log.WarnContext(ctx, "clear command timed out")
	}
	clearCancel()

	ticker.Reset(u.limiter.IdleTimeout)
}

// handleChatCommand processes a ChatCommand request.
//
// This updates the workerLimiter with the current time, resetting its
// idle timeout.
func (u *userCommandWorker) handleChatCommand(
	ctx context.Context,
	log *slog.Logger,
	req *ChatCommand,
	ticker *time.Ticker,
) {
	log.InfoContext(ctx, "got chat command", "chat_command", req)
	u.limiter.SetLastCommand(time.Now())
	deadline := req.Deadline()

	log.InfoContext(ctx, "token expires", "at", deadline)
	reqPanicked := make(chan bool, 1)
	go func() {
		switch {
		case req.handler.Config().RecoverPanic:
			defer func() {
				if r := recover(); r != nil {
					log.ErrorContext(
						ctx,
						"panic in chat command",
						tint.Err(fmt.Errorf("%v", r)),
					)
					reqPanicked <- true
					return
				}
				reqPanicked <- false
			}()
		default:
			defer func() {
				reqPanicked <- false
			}()
		}
		u.runChatCommand(ctx, req)
	}()
	panicked := <-reqPanicked
	if panicked {
		go discordNotifyCommandPanicked(ctx, log, req, u.dc.discord)
		return
	}
	switch req.RunStatus {
	case openai.RunStatusCompleted, openai.RunStatusIncomplete, openai.RunStatusFailed, openai.RunStatusCancelled, openai.RunStatusRequiresAction, openai.RunStatusExpired:
		go func() {
			log.InfoContext(ctx, "getting run steps in background for chat command")
			if stepErr := u.getRunSteps(ctx, req); stepErr != nil {
				log.ErrorContext(ctx, "error getting run steps", tint.Err(stepErr))
			}
		}()
	}

	u.lastCommandAt.Store(time.Now().UnixMilli())
	ticker.Reset(u.limiter.IdleTimeout)
}

// runChatCommand (potentially) moves ChatCommand processing along, either directly or
// after being popped from ChatCommandMemoryQueue. Some additional checks are done
// (such as checking if User.Ignored has been set since the request was
// queued). Deadline is a time by which the processing must finish.
func (u *userCommandWorker) runChatCommand(
	ctx context.Context,
	c *ChatCommand,
) {
	d := u.dc
	d.chatCommandsInProgress.Add(1)
	defer d.chatCommandsInProgress.Add(-1)

	if c.mu == nil {
		c.mu = &sync.RWMutex{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	logger, ok := ContextLogger(ctx)
	if logger == nil || !ok {
		logger = d.logger
	}
	logger = logger.With(
		slog.Group("chat_command", chatCommandLogAttrs(*c)...),
	)
	if c.User != nil {
		logger = logger.With(slog.Group("user", userLogAttrs(*c.User)...))
	}
	ctx = WithLogger(ctx, logger)

	if c.User.Ignored {
		logger.WarnContext(ctx, "user is ignored, ignoring command")
		if c.State != ChatCommandStateIgnored {
			updateChatCommandStateAndDeleteInteraction(
				ctx, logger, d.writeDB, c, ChatCommandStateIgnored,
			)
		}
		return
	}

	deadline := c.Deadline()
	startDeadline := deadline.Add(discordTokenDeadlineOffset)
	afterDeadline := time.Now().UTC().After(startDeadline)

	if afterDeadline {
		logger.WarnContext(ctx, "command expired")
		updateChatCommandStateAndDeleteInteraction(
			ctx, logger, d.writeDB, c, ChatCommandStateExpired,
		)

		return
	}

	if ctx.Err() != nil {
		logger.WarnContext(ctx, "context canceled, stopping command")
		return
	}

	startedAt := time.Now()
	if _, err := d.writeDB.Updates(
		c, map[string]any{
			columnChatCommandState:     ChatCommandStateInProgress,
			columnChatCommandStartedAt: &startedAt,
			columnChatCommandAttempts:  c.Attempts + 1,
		},
	); err != nil {
		logger.ErrorContext(ctx, "error updating command state", tint.Err(err))
		config := c.handler.Config()
		_, _ = c.handler.Edit(ctx, &discordgo.WebhookEdit{Content: &config.DiscordErrorMessage})
		return
	}
	c.Answer(ctx, d)
}

func updateChatCommandStateAndDeleteInteraction(
	ctx context.Context,
	logger *slog.Logger,
	db DBI,
	c *ChatCommand,
	newState ChatCommandState,
) {
	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := db.Update(
			c, columnChatCommandState, newState,
		); err != nil {
			logger.ErrorContext(ctx, "error updating command state", tint.Err(err))
		}
	}()

	if c.Acknowledged && time.Now().UTC().Before(c.Deadline()) {
		logger.InfoContext(
			ctx,
			"command acknowledged and token still valid, deleting acknowledgment",
		)

		wg.Add(1)
		go func() {
			defer wg.Done()
			c.handler.Delete(ctx)
		}()
	}

	wg.Wait()
}
