package disconcierge

import (
	"cmp"
	"container/heap"
	"context"
	"fmt"
	"github.com/lmittmann/tint"
	"log/slog"
	"slices"
	"sync"
	"time"
)

type ChatCommandQueue interface {
	Pop(context.Context) (*ChatCommand, error)
	Push(context.Context, *ChatCommand) error
	Clear(context.Context) error
}

// ChatCommandMemoryQueue is a priority queue for ChatCommand (slash command) requests
type ChatCommandMemoryQueue struct {
	queue     *PriorityQueue
	config    *QueueConfig
	logger    *slog.Logger
	mu        sync.Mutex
	db        DBI
	requestCh chan *ChatCommand
}

func NewChatCommandQueue(
	config *QueueConfig,
	logger *slog.Logger,
) *ChatCommandMemoryQueue {
	q := &ChatCommandMemoryQueue{
		queue:  &PriorityQueue{},
		logger: logger,
		config: config,
	}
	heap.Init(q.queue)
	return q
}

func (u *ChatCommandMemoryQueue) Clear(_ context.Context) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.queue = &PriorityQueue{}
	heap.Init(u.queue)
	return nil
}

// oldestNonPriority finds the index of the oldest ChatCommand in the
// queue where ChatCommand.Priority is false. If none are
// found, the returned boolean is false.
func (u *ChatCommandMemoryQueue) oldestNonPriority() (int, bool) {
	old := *u.queue
	for i := len(old) - 1; i >= 0; i-- {
		v := old[i]
		if !v.Priority {
			return i, true
		}
	}
	return 0, false
}

func (u *ChatCommandMemoryQueue) popNext() *ChatCommand {
	if u.queue.Len() == 0 {
		return nil
	}
	req := heap.Pop(u.queue).(*ChatCommand)
	return req
}
func (u *ChatCommandMemoryQueue) Pop(ctx context.Context) *ChatCommand {
	u.mu.Lock()
	defer u.mu.Unlock()
	wg := &sync.WaitGroup{}

	chatCommandCh := make(chan *ChatCommand, 1)

	go func() {
		for {
			req := u.popNext()
			if req == nil {
				chatCommandCh <- nil
				return
			}

			var logger *slog.Logger
			if u.logger == nil {
				logger = slog.Default()
			} else {
				logger = u.logger
			}
			logger = logger.With(
				slog.Group(
					"chat_command",
					chatCommandLogAttrs(*req)...,
				),
			)
			ctx = WithLogger(ctx, logger)
			if u.config.MaxAge > 0 {
				reqAge := req.Age()
				logger.InfoContext(
					ctx, "request age",
					"age", reqAge,
					slog.Group(
						"chat_command",
						columnChatCommandStep,
						req.Step,
						columnChatCommandState,
						req.State,
					),
				)
				if reqAge > u.config.MaxAge {
					req.State = ChatCommandStateExpired
					logger.WarnContext(
						ctx,
						"discarded old request",
						"user_request", req,
						"max_age", u.config.MaxAge,
						"request_age", reqAge,
					)
					if u.db != nil {
						wg.Add(1)
						go func() {
							defer wg.Done()
							if _, err := u.db.Update(
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
					}
					continue
				}
			}
			if req.User.Ignored {
				logger.WarnContext(
					ctx,
					"ignoring blocked User request",
					slog.Group(
						"chat_command",
						columnChatCommandStep,
						req.Step,
						columnChatCommandState,
						req.State,
					),
				)
				if u.db != nil {
					wg.Add(1)
					go func() {
						defer wg.Done()
						if _, err := u.db.Update(
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
				}
				continue
			}

			if req.State != ChatCommandStateQueued {
				logger.WarnContext(
					ctx,
					fmt.Sprintf(
						"expected state '%s', got: '%s'",
						ChatCommandStateQueued,
						req.State,
					),
					slog.Group(
						"chat_command",
						columnChatCommandStep,
						req.Step,
						columnChatCommandState,
						req.State,
					),
				)
				continue
			}

			logger.InfoContext(
				ctx,
				"popped request",
				"queue_size", u.queue.Len(),
				slog.Group(
					"chat_command",
					columnChatCommandStep,
					req.Step,
					columnChatCommandState,
					req.State,
				),
			)
			chatCommandCh <- req
			return
		}
	}()

	wg.Wait()
	return <-chatCommandCh
}

func (u *ChatCommandMemoryQueue) Len() int {
	u.mu.Lock()
	defer u.mu.Unlock()

	return u.queue.Len()
}

func (u *ChatCommandMemoryQueue) Push(
	ctx context.Context,
	req *ChatCommand,
	db DBI,
) error {
	u.logger.InfoContext(ctx, "received user request", "user_request", req)
	req.Step = ChatCommandStepEnqueue

	u.mu.Lock()
	defer u.mu.Unlock()

	logger, ok := ContextLogger(ctx)
	if logger == nil || !ok {
		logger = u.logger
		logger = logger.With("user_request", req)
		ctx = WithLogger(ctx, logger)
	}

	if u.config.Size > 0 && u.queue.Len() >= u.config.Size {
		// When the queue is full, we discard the oldest ChatCommand
		// where [ChatCommand.Priority] is not true.
		// If no non-priority commands exist, we discard the oldest
		// priority command.
		var oldestReq *ChatCommand

		oldestInd, found := u.oldestNonPriority()
		switch {
		case found:
			oldestReq = heap.Remove(u.queue, oldestInd).(*ChatCommand)
			logger.WarnContext(
				ctx,
				"removed oldest non-priority request",
				"removed_request",
				oldestReq,
				"removed_index",
				oldestInd,
			)
		default:
			oldestReq = heap.Pop(u.queue).(*ChatCommand)
			logger.WarnContext(
				ctx,
				"no non-priority requests, removing oldest overall request",
				"dropped_request", oldestReq,
				"max_size", u.config.Size,
				"current_size", u.queue.Len(),
			)
		}
		if oldestReq != nil {
			if oldestReq.Priority {
				logger.Warn("discarding/aborting priority chat command", "chat_command", oldestReq)
			} else {
				logger.Info("discarding/aborting chat command", "chat_command", oldestReq)
			}
			if _, err := db.Update(
				oldestReq,
				columnChatCommandState,
				ChatCommandStateAborted,
			); err != nil {
				logger.Error("failed to update request", tint.Err(err))
			}
		}
	}

	// using Save() instead of Update() here because the update will fail
	// in the test suite given a zero value primary key
	req.State = ChatCommandStateQueued
	if _, err := db.Save(req); err != nil {
		logger.Error(
			"failed to update request state to: %q",
			ChatCommandStateQueued.String(),
			tint.Err(err),
		)
		return err
	}

	reqAge := req.Age()
	if u.config.MaxAge > 0 && reqAge > u.config.MaxAge {
		req.State = ChatCommandStateExpired
		logger.Warn(
			"discarding old request",
			"max_age", u.config.MaxAge,
			"request_age", reqAge,
		)
		if _, err := db.Update(req, columnChatCommandState, ChatCommandStateExpired); err != nil {
			logger.Error("failed to update expired request", tint.Err(err))
		}
		return fmt.Errorf("%w: (age: %s)", ErrChatCommandTooOld, reqAge)
	}

	heap.Push(u.queue, req)
	logger.Info(
		"queued user request",
		"user_request", req,
		"prompt", req.Prompt,
	)
	return nil
}

type PriorityQueue []*ChatCommand

func (pq PriorityQueue) Len() int {
	return len(pq)
}

func (pq PriorityQueue) Less(i, j int) bool {
	leftRequest := pq[i]
	rightRequest := pq[j]
	if leftRequest.Priority && !rightRequest.Priority {
		return true
	}

	if rightRequest.Priority && !leftRequest.Priority {
		return false
	}

	return leftRequest.CreatedAt < rightRequest.CreatedAt
}

func (pq PriorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].index = i
	pq[j].index = j
}

func (pq *PriorityQueue) Push(x any) {
	n := len(*pq)
	item := x.(*ChatCommand)
	item.index = n
	*pq = append(*pq, item)
}

func (pq *PriorityQueue) Pop() any {
	old := *pq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil
	item.index = -1
	*pq = old[0 : n-1]
	return item
}

// chatCommandAvailable returns the time when the next ChatCommand is available
// and a bool indicating if it's available immediately, using the given
// ChatCommandSlice. Limit is the maximum number of requests, timespan is
// the duration in which the limit is enforced, and currentTime is the
// time to use as a reference point for the end of the span
func chatCommandAvailable(
	ctx context.Context,
	requests []*ChatCommand,
	limit int,
	timespan time.Duration,
	currentTime time.Time,
) (time.Time, bool) {
	if limit <= 0 {
		panic("limit must be greater than 0")
	}

	requestTimes := make([]time.Time, 0, len(requests))
	for _, r := range requests {
		requestTimes = append(requestTimes, time.UnixMilli(r.CreatedAt).UTC())
	}
	return nextRequestAvailable(ctx, requestTimes, limit, timespan, currentTime)
}

// nextRequestAvailable returns the time when the next ChatCommand is available
// and a bool indicating if it's available immediately, using the given
// time.Time slice (where the times should represent request times).
// Limit is the maximum number of requests, timespan is
// the duration in which the limit is enforced, and currentTime is the
// time to use as a reference point for the end of the span
func nextRequestAvailable(
	ctx context.Context,
	requests []time.Time,
	limit int,
	timespan time.Duration,
	currentTime time.Time,
) (time.Time, bool) {
	if len(requests) == 0 {
		return time.Now().UTC(), true
	}

	startTS := currentTime.Add(-timespan)

	requestsInWindow := make([]time.Time, 0, len(requests))
	for _, r := range requests {
		if r.Before(startTS) {
			continue
		}
		requestsInWindow = append(requestsInWindow, r)
	}
	ct := len(requestsInWindow)
	if ct < limit {
		return time.Now().UTC(), true
	}

	slices.SortFunc(
		requestsInWindow, func(a, b time.Time) int {
			return cmp.Compare(a.UnixMilli(), b.UnixMilli())
		},
	)
	logger, ok := ContextLogger(ctx)
	if logger == nil || !ok {
		logger = slog.Default()
	}
	if ct == limit {
		oldestTS := requestsInWindow[0]
		availableAt := oldestTS.Add(timespan + time.Minute)
		logger.InfoContext(
			ctx,
			fmt.Sprintf(
				"Now: %s / Oldest request: %s / Timespan: %s (from: %s) / Available at: %s",
				time.Now(), oldestTS, timespan, startTS, availableAt,
			),
		)
		return availableAt, false
	}

	return requestsInWindow[ct-limit].Add(time.Minute), false
}
