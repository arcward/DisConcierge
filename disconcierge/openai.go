package disconcierge

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lmittmann/tint"
	"github.com/sashabaranov/go-openai"
	"golang.org/x/time/rate"
	"log/slog"
	"net/http"
	"slices"
	"sync"
	"time"
)

const (
	assistantVersion = "v2"
	openaiUserRole   = "user"
)

var (
	openaiListMessageOrderAscending  = "asc"
	openaiListRunStepsOrderAscending = "asc"
	openaiListRunStepsLimit          = 100
	openaiListMessageLimit           = 1
	openaiAssistantRoleUser          = "user"
	openaiAssistantRoleAssistant     = "assistant"
)

// OpenAI represents the OpenAI integration for DisConcierge.
//
// It manages the OpenAI client, handles API requests, and provides methods for
// interacting with OpenAI services such as creating threads, messages, and runs.
//
// Fields:
//   - client: The OpenAI client for making API requests.
//   - config: Configuration for OpenAI integration.
//   - logger: Logger for OpenAI-related events.
//   - requestLimiter: Rate limiter for OpenAI API requests.
//   - assistant: Cached OpenAI assistant information.
//   - dc: Reference to the parent DisConcierge instance.
//
// The OpenAI struct is responsible for managing all interactions with the OpenAI API,
// including creating and managing threads, messages, and runs. It also handles
// rate limiting and logging of OpenAI-related operations.
type OpenAI struct {
	client         OpenAIClient
	config         *OpenAIConfig
	logger         *slog.Logger
	requestLimiter *rate.Limiter

	// assistant is loaded on startup - it's not really used, other
	// than to verify the configured assistant exists. It's only
	// saved as a field here for a nil check (so we can just assign it
	// upfront in tests and not attempt an actual check)
	assistant *openai.Assistant
	dc        *DisConcierge

	mu *sync.RWMutex // primarily just protects requestLimiter
}

func newOpenAI(
	d *DisConcierge,
	httpClient *http.Client,
) *OpenAI {
	config := d.config.OpenAI
	o := &OpenAI{
		config: config,
		dc:     d,
		mu:     &sync.RWMutex{},
	}
	o.logger = slog.New(
		tint.NewHandler(
			defaultLogWriter, &tint.Options{
				Level:     config.LogLevel,
				AddSource: true,
			},
		),
	).With(loggerNameKey, "openai")

	clientCfg := openai.DefaultConfig(config.Token)
	clientCfg.AssistantVersion = assistantVersion
	if httpClient != nil {
		clientCfg.HTTPClient = httpClient
	}

	o.client = openai.NewClientWithConfig(clientCfg)

	return o
}

func (d *OpenAI) CreateThread(
	ctx context.Context,
	db DBI,
	req *ChatCommand,
) (string, error) {
	cmdLogger, ok := ContextLogger(ctx)
	if cmdLogger == nil || !ok {
		cmdLogger = d.logger
		if cmdLogger == nil {
			cmdLogger = slog.Default()
		}
		ctx = WithLogger(ctx, cmdLogger)
	}

	if _, err := db.Update(
		context.TODO(),
		req,
		columnChatCommandStep,
		ChatCommandStepCreatingThread,
	); err != nil {
		cmdLogger.ErrorContext(ctx, "error updating command state", tint.Err(err))
		return "", err
	}

	thread := &OpenAICreateThread{
		OpenAIAPILog{
			ChatCommandID:  &req.ID,
			RequestStarted: time.Now().UnixMilli(),
		},
	}
	threadPayload := openai.ThreadRequest{}
	data, _ := json.Marshal(threadPayload)
	thread.RequestBody = string(data)

	trv, err := d.client.CreateThread(ctx, threadPayload)
	thread.RequestEnded = time.Now().UnixMilli()
	if err != nil {
		thread.Error = err.Error()
		if _, e := db.Create(context.TODO(), thread); e != nil {
			cmdLogger.ErrorContext(ctx, "error adding record", tint.Err(e))
		}
		return "", err
	}
	data, err = json.Marshal(trv)
	if err != nil {
		cmdLogger.ErrorContext(ctx, "error marshaling json", tint.Err(err))
	}
	thread.ResponseBody = string(data)
	thread.ResponseHeaders = d.dumpHeaders(trv.Header())
	if _, err = db.Create(context.TODO(), thread); err != nil {
		cmdLogger.ErrorContext(ctx, "error adding record", tint.Err(err))
	}
	return trv.ID, nil
}

// CreateRun initiates a new run for the given ChatCommand.
//
// [ChatCommand.Step] is updated to [ChatCommandStepCreatingRun] before the run
// is created. This allows the ChatCommand to be resumed from this step if
// it's interrupted for some reason (e.g., a crash or restart).
//
// The run will only be created if the discord interaction token isn't going
// to expire for at least 2 minutes
// The function performs the following steps:
// 1. Updates the ChatCommand's step to ChatCommandStepCreatingRun.
// 2. Constructs the run request with the ChatCommand's parameters.
// 3. Calls the OpenAI API to create the run.
// 4. Records the API response and any errors.
// 5. Logs the operation details.
//
// If an error occurs at any step, it is logged and returned. The function
// ensures that all API interactions and database operations are properly recorded.

func (d *OpenAI) CreateRun(ctx context.Context, db DBI, req *ChatCommand) (*openai.Run, error) {
	cmdLogger, ok := ContextLogger(ctx)
	if cmdLogger == nil || !ok {
		cmdLogger = d.logger
		ctx = WithLogger(ctx, cmdLogger)
	}

	if _, e := db.Update(
		context.TODO(),
		req,
		columnChatCommandStep,
		ChatCommandStepCreatingRun,
	); e != nil {
		cmdLogger.ErrorContext(ctx, "error updating state", tint.Err(e))
		return nil, e
	}

	requestTokenExpires := time.UnixMilli(req.TokenExpires).UTC()
	// use to ensure some extra time to update the discord interaction
	beforeRequestTokenExpires := requestTokenExpires.Add(-2 * time.Minute)
	tokenCtx, cancel := context.WithDeadline(ctx, beforeRequestTokenExpires)
	defer cancel()

	if d.dc != nil {
		_ = d.dc.waitForPause(tokenCtx)
	}
	if tokenCtx.Err() != nil {
		return nil, tokenCtx.Err()
	}
	strategy := &openai.ThreadTruncationStrategy{
		Type: req.User.OpenAITruncationStrategyType,
	}
	if strategy.Type == openai.TruncationStrategyLastMessages {
		strategy.LastMessages = &req.User.OpenAITruncationStrategyLastMessages
	}

	additionalInstructions := req.User.AssistantAdditionalInstructions
	runRequest := openai.RunRequest{
		AssistantID:            d.config.AssistantID,
		MaxCompletionTokens:    req.User.OpenAIMaxCompletionTokens,
		MaxPromptTokens:        req.User.OpenAIMaxPromptTokens,
		TruncationStrategy:     strategy,
		Instructions:           req.User.AssistantInstructions,
		Temperature:            &req.User.AssistantTemperature,
		AdditionalInstructions: additionalInstructions,
	}

	runRec := &OpenAICreateRun{
		OpenAIAPILog{
			ChatCommandID:  &req.ID,
			RequestStarted: time.Now().UnixMilli(),
		},
	}
	data, err := json.Marshal(runRequest)
	if err != nil {
		return nil, err
	}
	runRec.RequestBody = string(data)

	err = d.waitOnRequestLimiter(tokenCtx)
	if err != nil {
		runRec.Error = err.Error()
		if _, e := db.Create(context.TODO(), runRec); e != nil {
			cmdLogger.ErrorContext(tokenCtx, "error adding record", tint.Err(e))
		}
		return nil, err
	}

	runRec.RequestStarted = time.Now().UnixMilli()

	runResponse, createRunErr := d.client.CreateRun(
		context.Background(),
		req.ThreadID,
		runRequest,
	)
	if createRunErr != nil {
		cmdLogger.ErrorContext(
			ctx,
			"error creating run",
			tint.Err(createRunErr),
		)
		runRec.Error = createRunErr.Error()
	}
	runRec.RequestEnded = time.Now().UnixMilli()
	runRec.ResponseHeaders = d.dumpHeaders(runResponse.Header())

	responseBody, err := json.Marshal(runResponse)
	if err != nil {
		cmdLogger.ErrorContext(tokenCtx, "error marshaling json", tint.Err(err))
	}
	runRec.ResponseBody = string(responseBody)

	if _, err = db.Create(context.TODO(), runRec); err != nil {
		cmdLogger.ErrorContext(tokenCtx, "error adding record", tint.Err(err))
	}

	return &runResponse, createRunErr
}

// CreateMessage creates a new message in an OpenAI thread for a given ChatCommand.
//
// This method handles the creation of a new message in the specified OpenAI thread,
// updates the ChatCommand's state, and logs the operation.
//
// Parameters:
//   - ctx: A context.Context for managing the request lifecycle.
//   - db: A DBI interface for database operations.
//   - req: A pointer to the ChatCommand for which the message is being created.
//
// Returns:
//   - string: The ID of the created message.
//   - error: An error if any occurred during the process, nil otherwise.
//
// The function performs the following steps:
// 1. Updates the ChatCommand's step to ChatCommandStepCreatingMessage.
// 2. Creates an OpenAICreateMessage record for logging.
// 3. Constructs the message request with the ChatCommand's prompt.
// 4. Calls the OpenAI API to create the message.
// 5. Records the API response and any errors.
// 6. Logs the operation details.
//
// If an error occurs at any step, it is logged and returned. The function
// ensures that all API interactions and database operations are properly recorded.
func (d *OpenAI) CreateMessage(
	ctx context.Context,
	db DBI,
	req *ChatCommand,
) (string, error) {
	cmdLogger, ok := ContextLogger(ctx)
	if cmdLogger == nil || !ok {
		cmdLogger = slog.Default()
		ctx = WithLogger(ctx, cmdLogger)
	}
	if _, e := db.Update(
		context.TODO(),
		req,
		columnChatCommandStep,
		ChatCommandStepCreatingMessage,
	); e != nil {
		cmdLogger.ErrorContext(ctx, "error updating state", tint.Err(e))
		return "", e
	}

	msgRec := &OpenAICreateMessage{
		OpenAIAPILog{
			ChatCommandID:  &req.ID,
			RequestStarted: time.Now().UnixMilli(),
		},
	}

	msgRequest := openai.MessageRequest{
		Role:     openaiUserRole,
		Content:  req.Prompt,
		Metadata: map[string]any{"interaction_id": req.InteractionID},
	}
	data, err := json.Marshal(msgRequest)
	if err != nil {
		cmdLogger.ErrorContext(ctx, "error adding record", tint.Err(err))
	} else {
		msgRec.RequestBody = string(data)
	}

	msg, createMsgErr := d.client.CreateMessage(ctx, req.ThreadID, msgRequest)
	msgRec.RequestEnded = time.Now().UnixMilli()
	//goland:noinspection GoDfaErrorMayBeNotNil
	msgRec.ResponseHeaders = d.dumpHeaders(msg.Header())

	if createMsgErr != nil {
		cmdLogger.ErrorContext(
			ctx,
			"error creating message",
			tint.Err(createMsgErr),
		)
		msgRec.Error = createMsgErr.Error()
	}

	data, err = json.Marshal(msg)
	if err != nil {
		cmdLogger.ErrorContext(ctx, "error adding record", tint.Err(err))
	}
	msgRec.ResponseBody = string(data)

	if _, err = db.Create(context.TODO(), msgRec); err != nil {
		cmdLogger.ErrorContext(ctx, "error adding record", tint.Err(err))
	}
	return msg.ID, createMsgErr
}

func (d *OpenAI) dumpHeaders(headers http.Header) string {
	if headers == nil {
		return ""
	}
	data, err := json.Marshal(headers)
	if err != nil {
		d.logger.Warn("error dumping headers", tint.Err(err))
		return ""
	}
	return string(data)
}

// pollUpdateRunStatus polls the OpenAI API for updates on a run's status and
// updates the ChatCommand accordingly.
//
// This function continually checks the status of an OpenAI run associated
// with a ChatCommand, updating the command's state and run status as it changes.
// It implements a backoff strategy for polling and handles various run status outcomes.
//
// Parameters:
//   - ctx: A context.Context for managing the request lifecycle and cancellation.
//   - db: A DBI interface for database operations.
//   - req: A pointer to the ChatCommand associated with the run being polled.
//   - interval: The initial interval between poll attempts.
//   - maxInterval: The maximum interval between poll attempts.
//   - maxErrors: The maximum number of consecutive errors allowed before giving up.
//
// Returns:
//   - error: An error if the polling was interrupted or max errors were exceeded, nil otherwise.
//
// The function performs the following main operations:
// 1. Updates the ChatCommand's step to ChatCommandStepPollingRun.
// 2. Repeatedly polls the OpenAI API for the run status, with a backoff strategy.
// 3. Updates the ChatCommand's run status and other relevant fields in the database.
// 4. Handles different run statuses (completed, failed, expired, etc.).
// 5. Continues polling until the run is complete, an error occurs, or the context is cancelled.
//
// If the maximum number of errors is reached, it returns ErrPollRunMaxErrorsExceeded.
// If the polling is interrupted (e.g., by context cancellation), it returns ErrPollRunInterrupted.
//
// The polling interval increases after errors, up to the specified maxInterval.
func (d *OpenAI) pollUpdateRunStatus(
	ctx context.Context,
	db DBI,
	req *ChatCommand,
	interval time.Duration,
	maxInterval time.Duration,
	maxErrors int,
) error {
	started := time.Now()
	logger, ok := ContextLogger(ctx)
	if logger == nil || !ok {
		logger = slog.Default()
		ctx = WithLogger(ctx, logger)
	}
	if req.Step != ChatCommandStepPollingRun {
		if _, err := db.Update(
			context.TODO(),
			req,
			columnChatCommandStep,
			ChatCommandStepPollingRun,
		); err != nil {
			return err
		}
	}
	logger.InfoContext(
		ctx,
		fmt.Sprintf(
			"Polling run status (interval: %s max errors: %d)",
			interval,
			maxErrors,
		),
		slog.Group(
			"chat_command",
			columnChatCommandStep, req.Step,
			columnChatCommandState, req.State,
		),
	)

	ct := 0
	var errs []error

	defer func() {
		logger.InfoContext(
			ctx,
			fmt.Sprintf("Polled %d times (total: %s)", ct, time.Since(started).String()),
			slog.Group(
				"chat_command",
				columnChatCommandState, req.State,
				columnChatCommandStep, req.Step,
				columnChatCommandRunStatus, req.RunStatus,
			),
		)
	}()

	// normal ticker process
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	initialTick := make(chan struct{}, 1)
	initialTick <- struct{}{}
	defer close(initialTick)

	for len(errs) <= maxErrors {
		ct++
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-initialTick:
			isDone, pollErr := d.executePoll(ctx, db, logger, req)
			interval = updateInterval(logger, interval, maxInterval, pollErr)
			if pollErr != nil {
				if isShutdownErr(ctx, pollErr) {
					return pollErr
				} else if errors.Is(pollErr, context.DeadlineExceeded) {
					return pollErr
				}
				errs = append(errs, pollErr)

			}
			if isDone {
				return nil
			}
			ticker.Reset(interval)
		case <-ticker.C:
			isDone, pollErr := d.executePoll(ctx, db, logger, req)
			interval = updateInterval(logger, interval, maxInterval, pollErr)
			if pollErr != nil {
				if isShutdownErr(ctx, pollErr) {
					return pollErr
				} else if errors.Is(pollErr, context.DeadlineExceeded) {
					return pollErr
				}
				errs = append(errs, pollErr)

			}
			if isDone {
				return nil
			}
			ticker.Reset(interval)
		}
	}
	if len(errs) > 0 {
		allErrors := errors.Join(errs...)
		if allErrors != nil {
			logger.ErrorContext(
				ctx,
				fmt.Sprintf("polling errors: %d", len(errs)),
				tint.Err(allErrors),
			)
		}
		return allErrors
	}
	return nil
}

// listRunSteps retrieves all run steps for a given ChatCommand from the OpenAI API.
//
// This function fetches the run steps associated with a specific run in an OpenAI thread,
// potentially making multiple API calls to retrieve all steps if pagination is required.
//
// Parameters:
//   - ctx: A context.Context for managing the request lifecycle and cancellation.
//   - req: A pointer to the ChatCommand for which run steps are being retrieved.
//
// Returns:
//   - []OpenAIListRunSteps: A slice of OpenAIListRunSteps, each representing a batch of run steps.
//   - error: An error if any occurred during the process, nil otherwise.
//
// The function performs the following operations:
// 1. Initializes pagination parameters (limit of 100 steps per request, ascending order).
// 2. Repeatedly calls the OpenAI API to list run steps, handling pagination if necessary.
// 3. For each API call, creates an OpenAIListRunSteps record with request and response details.
// 4. Continues fetching pages of run steps until all steps are retrieved or an error occurs.
// 5. Respects the context cancellation, allowing for graceful termination of the process.
//
// If the DisConcierge instance is paused, the function waits for it to resume before proceeding.
//
// Each OpenAIListRunSteps record in the returned slice contains:
//   - Request details (start time, ChatCommand ID)
//   - Response details (end time, response headers, response body)
//   - Any error information if an API call failed
//
// This function is useful for detailed analysis and logging of the steps
// taken during an OpenAI run.
func (d *OpenAI) listRunSteps(ctx context.Context, req *ChatCommand) (
	[]OpenAIListRunSteps,
	error,
) {
	p := openai.Pagination{
		Limit: &openaiListRunStepsLimit,
		Order: &openaiListRunStepsOrderAscending,
	}
	var runSteps []OpenAIListRunSteps

	runLogger, ok := ContextLogger(ctx)
	if runLogger == nil || !ok {
		runLogger = slog.Default()
		ctx = WithLogger(ctx, runLogger)
	}

	if d.dc != nil {
		_ = d.dc.waitForPause(ctx)
	}

	seen := map[string]bool{}

	for ctx.Err() == nil {
		runStep := OpenAIListRunSteps{
			OpenAIAPILog{
				ChatCommandID:  &req.ID,
				RequestStarted: time.Now().UnixMilli(),
			},
		}
		rv, err := d.client.ListRunSteps(ctx, req.ThreadID, req.RunID, p)
		runStep.ResponseHeaders = d.dumpHeaders(rv.Header())
		runStep.RequestEnded = time.Now().UnixMilli()
		if err != nil {
			runStep.Error = err.Error()
			return runSteps, err
		}

		data, err := json.Marshal(rv)
		if err != nil {
			runLogger.ErrorContext(ctx, "error marshaling run steps", tint.Err(err))
		}
		runStep.ResponseBody = string(data)
		if len(rv.RunSteps) == 0 {
			break
		}
		runSteps = append(runSteps, runStep)

		if !rv.HasMore {
			break
		}
		p.After = &rv.LastID
		if seen[rv.LastID] {
			break
		} else {
			seen[rv.LastID] = true
		}
	}
	return runSteps, nil
}

// executePoll performs a single poll operation to retrieve and update the status of an OpenAI run.
//
// This function is typically called repeatedly by pollUpdateRunStatus to
// check the progress of a run. It retrieves the current state of the run from
// the OpenAI API, updates the local ChatCommand record, and determines whether
// the run has reached a terminal state.
//
// Parameters:
//   - ctx: A context.Context for managing the request lifecycle and cancellation.
//   - db: A DBI interface for database operations.
//   - logger: A slog.Logger for logging the poll operation details.
//   - req: A pointer to the ChatCommand associated with the run being polled.
//
// Returns:
//   - bool: isDone indicates whether the run has reached a terminal state
//     (completed, failed, etc.).
//   - error: An error if any occurred during the polling process, nil otherwise.
//
// The function performs the following main operations:
// 1. Retrieves the current run status from the OpenAI API.
// 2. Updates the ChatCommand's run status and usage statistics in the database.
// 3. Logs the current run status and any relevant details.
// 4. Determines if the run has reached a terminal state based on its status.
//
// Terminal states include:
//   - RunStatusIncomplete: Logs the reason if available.
//   - RunStatusCancelling, RunStatusCancelled, RunStatusExpired,
//     RunStatusFailed: Considered as error states.
//   - RunStatusCompleted: Logs completion time if available.
//
// This function is crucial for tracking the progress of OpenAI runs and updating the ChatCommand
// state accordingly. It handles various run statuses and ensures that the local state is
// synchronized with the OpenAI API's state.
func (d *OpenAI) executePoll(
	ctx context.Context,
	db DBI,
	logger *slog.Logger,
	req *ChatCommand,
) (isDone bool, err error) {
	polledAt := time.Now()
	run, err := d.RetrieveRun(ctx, db, req)

	if err != nil {
		logger.ErrorContext(ctx, "error retrieving run, updating interval", tint.Err(err))
		return false, err
	}

	logger.InfoContext(
		ctx,
		fmt.Sprintf("run status: %s", run.Status),
		slog.Group(
			"chat_command",
			columnChatCommandStep, req.Step,
			columnChatCommandState, req.State,
			columnChatCommandRunStatus, run.Status,
		),
	)
	err = d.updateRunStatus(ctx, db, req, run)
	if err != nil {
		logger.ErrorContext(
			ctx,
			"error updating run status",
			tint.Err(err),
		)
	}

	switch run.Status {
	case openai.RunStatusIncomplete:
		if run.IncompleteDetails == nil {
			logger.WarnContext(ctx, "run status incomplete, no reason given")
		} else {
			logger.WarnContext(
				ctx,
				"run status incomplete",
				"reason", run.IncompleteDetails.Reason,
			)
		}
		isDone = true
	case openai.RunStatusCancelling, openai.RunStatusCancelled, openai.RunStatusExpired, openai.RunStatusFailed:
		logger.ErrorContext(
			ctx,
			"bad run status",
			columnChatCommandRunStatus, run.Status,
		)
		isDone = true
	case openai.RunStatusCompleted:
		if run.CompletedAt != nil {
			completeAt := time.Unix(*run.CompletedAt, 0)
			logger.InfoContext(
				ctx,
				fmt.Sprintf(
					"Polled at: %s Real completion at: %s",
					polledAt,
					completeAt,
				),
			)
		}
		logger.InfoContext(ctx, "run completed")
		isDone = true
	default:
		isDone = false
	}

	return isDone, err
}

// updateInterval adjusts the polling interval based on the presence of an error.
//
// This doubles the interval if an error occurred, up to a specified maximum interval.
// If no error occurred, the interval remains unchanged.
func updateInterval(
	logger *slog.Logger,
	interval time.Duration,
	maxInterval time.Duration,
	err error,
) time.Duration {
	if err == nil {
		return interval
	}
	interval *= 2
	if interval > maxInterval {
		interval = maxInterval
	} else {
		logger.Error(
			"error retrieving run, updating interval",
			tint.Err(err),
			"new_interval", interval,
		)
	}
	return interval
}

// getMessageResponse retrieves the response message for a
// completed ChatCommand from OpenAI.
//
// This function is typically called after an OpenAI run has completed
// successfully. It updates the ChatCommand's step to indicate that message
// retrieval is in progress, then fetches the latest message from
// the OpenAI thread associated with the ChatCommand.
//
// Parameters:
//   - ctx: A context.Context for managing the request lifecycle and cancellation.
//   - db: A DBI interface for database operations.
//   - req: A pointer to the ChatCommand for which the response message is being retrieved.
//
// Returns:
//   - string: The content of the response message from OpenAI.
//   - error: An error if any occurred during the process, nil otherwise.
//
// The function performs the following main operations:
// 1. Updates the ChatCommand's step to ChatCommandStepListMessage in the database.
// 2. Calls the ListMessage method to retrieve the latest message from the OpenAI thread.
//
// If an error occurs while updating the ChatCommand's step, it is logged and
// returned immediately.
// The actual message retrieval is delegated to the ListMessage method,
// which handles the API call to OpenAI and any necessary logging or error handling.
//
// This function is crucial for obtaining the final response from OpenAI
// after a run has completed, allowing the bot to provide the answer back to
// the user who initiated the ChatCommand.
func (d *OpenAI) getMessageResponse(
	ctx context.Context,
	db DBI,
	req *ChatCommand,
) (string, error) {
	if _, err := db.Update(
		context.TODO(),
		req,
		columnChatCommandStep,
		ChatCommandStepListMessage,
	); err != nil {
		d.logger.ErrorContext(ctx, "error updating state", tint.Err(err))
		return "", err
	}
	return d.ListMessage(ctx, db, req)
}

// RetrieveRun fetches the current state of an OpenAI run associated with a ChatCommand.
//
// This function retrieves the latest information about a specific run from
// the OpenAI API, logs the request and response details, and returns the
// run data. It's typically used to check the status and details of an ongoing
// or completed run.
//
// Parameters:
//   - ctx: A context.Context for managing the request lifecycle and cancellation.
//   - db: A DBI interface for database operations.
//   - req: A pointer to the ChatCommand associated with the run being retrieved.
//
// Returns:
//   - *openai.Run: A pointer to an openai.Run struct containing the retrieved
//     run information.
//   - error: An error if any occurred during the process, nil otherwise.
//
// The function performs the following main operations:
// 1. Checks if DisConcierge is paused and waits if necessary.
// 2. Creates an OpenAIRetrieveRun record to log the API request and response.
// 3. Calls the OpenAI API to retrieve the run information.
// 4. Records the API response time and any error encountered.
// 5. Logs the full API response body and headers.
// 6. Saves the OpenAIRetrieveRun record to the database.
//
// If an error occurs during the API call, it is logged and returned, but the function
// still attempts to save the OpenAIRetrieveRun record with the error information.
//
// This function is crucial for monitoring the progress of OpenAI runs and obtaining
// detailed information about their current state, which can be used for status updates,
// error handling, and decision-making in the ChatCommand processing flow.
func (d *OpenAI) RetrieveRun(
	ctx context.Context,
	db DBI,
	req *ChatCommand,
) (*openai.Run, error) {
	runLogger, ok := ContextLogger(ctx)
	if runLogger == nil || !ok {
		runLogger = slog.Default()
		ctx = WithLogger(ctx, runLogger)
	}
	if d.dc != nil {
		_ = d.dc.waitForPause(ctx)
	}

	runRec := &OpenAIRetrieveRun{
		OpenAIAPILog{
			ChatCommandID:  &req.ID,
			RequestStarted: time.Now().UnixMilli(),
		},
	}

	run, retrieveRunErr := d.client.RetrieveRun(ctx, req.ThreadID, req.RunID)
	runRec.RequestEnded = time.Now().UnixMilli()
	if retrieveRunErr != nil {
		runLogger.ErrorContext(ctx, "error retrieving run", tint.Err(retrieveRunErr))
		runRec.Error = retrieveRunErr.Error()
	}
	runRec.ResponseHeaders = d.dumpHeaders(run.Header())
	data, err := json.Marshal(run)
	if err != nil {
		runLogger.ErrorContext(ctx, "error marshaling run", tint.Err(err))
	}
	runRec.ResponseBody = string(data)
	if _, err = db.Create(context.TODO(), runRec); err != nil {
		runLogger.ErrorContext(ctx, "error adding record", tint.Err(err))
	}
	return &run, retrieveRunErr
}

// ListMessage retrieves the latest message from an OpenAI thread associated
// with a ChatCommand.
//
// This function fetches the most recent message from the specified OpenAI thread,
// typically used to get the assistant's response after a run has completed.
//
// Parameters:
//   - ctx: A context.Context for managing the request lifecycle and cancellation.
//   - db: A DBI interface for database operations.
//   - req: A pointer to the ChatCommand for which the message is being retrieved.
//
// Returns:
//   - string: The content of the latest message from the assistant.
//   - error: An error if any occurred during the process, nil otherwise.
//
// The function performs the following main operations:
//  1. Checks if DisConcierge is paused and waits if necessary.
//  2. Creates an OpenAIListMessages record to log the API request and response.
//  3. Calls the OpenAI API to list messages, with parameters set to retrieve
//     only the latest message.
//  4. Records the API response time, headers, and body.
//  5. Processes the response to extract the assistant's message content.
//  6. Saves the OpenAIListMessages record to the database.
//
// The function uses the following parameters for the API call:
//   - Limit: 1 (to retrieve only the latest message)
//   - Order: "asc" (ascending order, which combined with limit 1, gives the latest message)
//   - After: The ID of the user's message, to ensure we get the assistant's response
//
// If an error occurs at any stage, it is logged and returned. The function attempts to
// save the OpenAIListMessages record even if an error occurs during message processing.
//
// This function is crucial for obtaining the final response from the OpenAI assistant,
// which can then be sent back to the user as the answer to their query.
func (d *OpenAI) ListMessage(
	ctx context.Context,
	db DBI,
	req *ChatCommand,
) (string, error) {
	logger, ok := ContextLogger(ctx)
	if logger == nil || !ok {
		logger = slog.Default()
		ctx = WithLogger(ctx, logger)
	}

	if d.dc != nil {
		_ = d.dc.waitForPause(ctx)
	}

	apiReq := OpenAIListMessages{
		OpenAIAPILog{
			ChatCommandID:  &req.ID,
			RequestStarted: time.Now().UnixMilli(),
		},
	}
	trv, listMsgErr := d.client.ListMessage(
		ctx,
		req.ThreadID,
		&openaiListMessageLimit,
		&openaiListMessageOrderAscending,
		&req.MessageID,
		nil,
	)
	apiReq.RequestEnded = time.Now().UnixMilli()
	apiReq.ResponseHeaders = d.dumpHeaders(trv.Header())

	if listMsgErr != nil {
		apiReq.Error = listMsgErr.Error()
		logger.ErrorContext(ctx, "error listing messages", tint.Err(listMsgErr))
	}
	data, err := json.Marshal(trv)
	if err != nil {
		logger.ErrorContext(ctx, "error marshaling messages", tint.Err(err))
	}
	apiReq.ResponseBody = string(data)

	if _, err = db.Create(context.TODO(), &apiReq); err != nil {
		logger.ErrorContext(ctx, "error adding record", tint.Err(err))
	}

	var messageContents string
	if listMsgErr == nil {
		messageContents, err = getAssistantMessageContent(trv.Messages)
		if err != nil {
			logger.ErrorContext(
				ctx,
				"error getting message content",
				tint.Err(err),
				"response_body", string(data),
			)
			listMsgErr = errors.Join(listMsgErr, err)
		}
	}

	return messageContents, listMsgErr
}

// updateRunStatus updates the status and token usage of a ChatCommand based on
// the provided OpenAI run, and returns any errors encountered.
func (*OpenAI) updateRunStatus(
	_ context.Context,
	db DBI,
	req *ChatCommand,
	run *openai.Run,
) error {
	if run.Status == "" {
		return nil
	}

	if _, updErr := db.Updates(
		context.TODO(), req, map[string]any{
			columnChatCommandRunStatus:             run.Status,
			columnChatCommandUsagePromptTokens:     run.Usage.PromptTokens,
			columnChatCommandUsageCompletionTokens: run.Usage.CompletionTokens,
			columnChatCommandUsageTotalTokens:      run.Usage.TotalTokens,
		},
	); updErr != nil {
		return updErr
	}
	return nil
}

// waitOnRequestLimiter waits for the request limiter to allow the next request,
// returning any error from the limiter itself
func (d *OpenAI) waitOnRequestLimiter(ctx context.Context) error {
	// RUnlock isn't deferred here- if we try to update the limiter via
	// API, it'd end up waiting on the current limiter to be released,
	// which isn't great under high load.
	// `rate.Limiter` does not specify that it's safe to concurrently call
	// `Wait` and `SetLimit`.
	d.mu.RLock()
	requestLimiter := d.requestLimiter
	d.mu.RUnlock()
	return requestLimiter.Wait(ctx)
}

// OpenAIClient defines the interface for interacting with the OpenAI API.
// It abstracts the core functionalities needed for managing threads, messages,
// runs, and files in the context of the DisConcierge application.
//
// This interface allows for easier testing and potential future implementations
// with different OpenAI client libraries or mock clients for testing.
type OpenAIClient interface {
	// CreateMessage creates a new message in a specified thread.
	CreateMessage(
		ctx context.Context,
		threadID string,
		request openai.MessageRequest,
	) (msg openai.Message, err error)

	// CreateRun initiates a new run for a specified thread.
	CreateRun(
		ctx context.Context,
		threadID string,
		request openai.RunRequest,
	) (response openai.Run, err error)

	// CreateThread creates a new thread.
	CreateThread(
		ctx context.Context,
		request openai.ThreadRequest,
	) (response openai.Thread, err error)

	// ListMessage retrieves messages from a specified thread.
	ListMessage(
		ctx context.Context, threadID string,
		limit *int,
		order *string,
		after *string,
		before *string,
	) (messages openai.MessagesList, err error)

	// ListRunSteps retrieves the steps of a specific run in a thread.
	ListRunSteps(
		ctx context.Context,
		threadID string,
		runID string,
		pagination openai.Pagination,
	) (response openai.RunStepList, err error)

	// RetrieveRun gets the details of a specific run in a thread.
	RetrieveRun(
		ctx context.Context,
		threadID string,
		runID string,
	) (response openai.Run, err error)

	// RetrieveAssistant fetches the details of a specific assistant.
	RetrieveAssistant(ctx context.Context, assistantID string) (
		response openai.Assistant,
		err error,
	)
}

// getAssistantMessageContent extracts the content of the most recent
// assistant message from a list of OpenAI messages.
//
// This function processes a slice of openai.Message objects, typically
// obtained from an API response, to find and return the text content of
// the most recent message from the assistant.
//
// Parameters:
//   - messageList: A slice of openai.Message objects representing a
//     conversation thread.
//
// Returns:
//   - string: The text content of the most recent assistant message.
//   - error: An error if no suitable message is found or if there's an
//     issue processing the messages.
//
// The function performs the following operations:
// 1. Filters the messageList to include only messages with the role "assistant".
// 2. Sorts the filtered messages by creation time, with the most recent first.
// 3. Iterates through the content of the most recent assistant message to find text content.
// 4. Returns the first non-empty text content found.
//
// If no assistant messages are found in the list, it returns an error.
// If no text content is found in the most recent assistant message, it returns an error.
//
// This function is crucial for extracting the relevant response from
// the OpenAI API's message format, ensuring that only the assistant's latest
// textual response is returned for further processing or to be sent back to the user.
func getAssistantMessageContent(messageList []openai.Message) (string, error) {
	if len(messageList) == 0 {
		return "", errors.New("no messages in message list")
	}
	messages := make([]openai.Message, 0, len(messageList))
	for _, m := range messageList {
		if m.Role == openaiAssistantRoleAssistant {
			messages = append(messages, m)
		}
	}
	// newest to oldest
	slices.SortFunc(
		messages, func(x, y openai.Message) int {
			return cmp.Compare(y.CreatedAt, x.CreatedAt)
		},
	)
	if len(messages) == 0 {
		return "", errors.New("no assistant messages in message list")
	}

	for _, content := range messages[0].Content {
		msgText := content.Text
		if msgText != nil {
			if msgText.Value != "" {
				return msgText.Value, nil
			}
		}
	}
	return "", errors.New("no assistant response content found")
}
