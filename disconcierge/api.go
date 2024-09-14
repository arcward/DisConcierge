package disconcierge

//goland:noinspection GoLinter
import (
	"context"
	cryprand "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/bwmarrin/discordgo"
	"github.com/gin-contrib/cors"
	ginPprof "github.com/gin-contrib/pprof"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/gorilla/securecookie"
	gsessions "github.com/gorilla/sessions"
	"github.com/lmittmann/tint"
	"github.com/sashabaranov/go-openai"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
	"gorm.io/gorm"
	"io/fs"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	pprofPrefix                = "/debug"
	apiPrefix                  = "/api"
	apiPathPause               = "/pause"
	apiPathResume              = "/resume"
	apiPathQuit                = "/quit"
	apiPathClearThreads        = "/clear_threads"
	apiPathLogin               = "/login"
	apiPathLogout              = "/logout"
	apiPathUpdateUser          = "/user/:id"
	apiPathUserHistory         = "/user/:id/history"
	apiPathUsers               = "/users"
	apiPathReloadUsers         = "/users/reload"
	apiPathRegisterCommands    = "/discord/register_commands"
	apiPathLoggedIn            = "/logged_in"
	apiHealthCheck             = "/healthz"
	apiDiscordInteractions     = "/discord/interactions"
	apiPathConfig              = "/config"
	apiAdminSetup              = "/admin/create"
	apiPathSetup               = "/setup"
	apiPathSetupStatus         = "/setup/status"
	apiListChatCommands        = "/chat_commands"
	apiPathGetChatCommand      = "/chat_command/:id"
	apiPathGetDiscordMessages  = "/discord_messages"
	apiPathOpenAIRetrieveRuns  = "/openai/logs/retrieve_run"
	apiPathOpenAICreateThread  = "/openai/logs/create_thread"
	apiPathOpenAICreateMessage = "/openai/logs/create_message"
	apiPathUserFeedback        = "/user_feedback"

	apiPathOpenAICreateRun = "/openai/logs/create_run"

	apiPathOpenAIListMessages = "/openai/logs/list_messages"
	apiPathOpenAIListRunSteps = "/openai/logs/list_run_steps"

	apiPathDiscordGatewayBot = "/discord/gateway/bot"
)

const (
	xRequestIDHeader = "X-Request-ID"
	sessionVarName   = "user"
	sessionVarField  = "username"
)

var (
	structValidator = validator.New()
)

var (
	Ascending  Sort = "asc"
	Descending Sort = "desc"
)

//go:embed static
var reactUI embed.FS

// API represents the main API server for DisConcierge.
//
// It encapsulates the HTTP server, routing engine, and various components
// necessary for handling API requests, websocket connections, and
// interaction with the DisConcierge bot.
//
// Fields:
//   - config: Configuration for the API server.
//   - httpServer: The underlying HTTP server.
//   - httpServerURL: The URL of the HTTP server.
//   - listener:
//   - engine:
//   - store:
//   - loginRequestLimiter:
//   - requestMetrics: .
//   - requestMetricsMu: .
//   - logger: Logger for API-related events.
//   - handlers: API request handlers.
//
// The API struct is responsible for setting up and managing the HTTP server,
// configuring routes, handling authentication, and coordinating various
// components of the DisConcierge API.
//
// Usage:
//
//	config := &APIConfig{...}
//	api, err := newAPI(disConcierge, config)
//	if err != nil {
//	    // Handle error
//	}
//	err = api.Serve(ctx)
//	if err != nil {
//	    // Handle error
//	}
//
// The API should be initialized using the newAPI function and started
// with the Serve method.
type API struct {
	config              *APIConfig     // Configuration for the API server
	httpServer          *http.Server   // The underlying HTTP server
	listener            net.Listener   // Network listener for the HTTP server.
	engine              *gin.Engine    //  Gin engine for routing HTTP requests
	store               CookieStore    // CookieStore for session management.
	loginRequestLimiter *rate.Limiter  // Rate limiter for login requests
	requestMetrics      map[string]int // Metrics for API requests
	requestMetricsMu    sync.Mutex     // Mutex for synchronizing access to request metrics
	logger              *slog.Logger   // Logger for API-related events

	handlers *APIHandlers // API request handlers
}

// newAPI initializes and returns a new instance of the API struct.
//
// This function sets up the logger, configures the Gin engine, initializes
// the APIHandlers, sets up the session store, configures TLS, and sets up
// various middleware and routes.
//
// Parameters:
//   - d: A pointer to the DisConcierge instance.
//   - config: A pointer to the APIConfig instance containing configuration settings.
//
// Returns:
//   - A pointer to the newly created API instance.
//   - An error if there was an issue during initialization.
func newAPI(d *DisConcierge, config *APIConfig) (*API, error) {
	setupLogger := slog.New(
		tint.NewHandler(
			os.Stdout, &tint.Options{
				Level:     config.LogLevel,
				AddSource: true,
			},
		),
	)

	r := gin.New()

	api := &API{
		config:              config,
		engine:              r,
		requestMetrics:      map[string]int{},
		loginRequestLimiter: rate.NewLimiter(rate.Limit(1), 1),
	}
	apiHandlers := NewAPIHandlers(d)
	api.handlers = apiHandlers
	api.store = apiHandlers.store
	_ = r.Use(sessions.Sessions(sessionVarName, apiHandlers.store))

	tlsCfg, e := tlsConfig(
		config.SSL.Cert,
		config.SSL.Key,
		config.SSL.TLSMinVersion,
	)
	if e != nil {
		return nil, fmt.Errorf("error loading SSL certs: %w", e)
	}

	httpServer := &http.Server{
		Addr:              config.Listen,
		Handler:           r,
		TLSConfig:         tlsCfg,
		WriteTimeout:      config.WriteTimeout,
		IdleTimeout:       config.IdleTimeout,
		ReadTimeout:       config.ReadTimeout,
		ReadHeaderTimeout: config.ReadHeaderTimeout,
	}
	api.httpServer = httpServer
	api.logger = setupLogger.With(loggerNameKey, "api")

	corsConfig := config.CORS.GINConfig()
	if len(corsConfig.AllowOrigins) == 0 && api.config.Development {
		corsConfig.AllowOrigins = []string{"*"}
	}

	if !config.Development {
		r.Use(gin.Recovery())
	}
	r.Use(
		requestIDMiddleware(),
		ginLoggingMiddleware(),
		metricMiddleware(api),
		cors.New(corsConfig),
	)

	r.POST(apiPathLogin, apiHandlers.loginHandler)
	r.GET(apiHealthCheck, apiHandlers.healthCheck)
	r.POST(apiPathLogout, apiHandlers.logoutHandler)

	if config.Development {
		ginPprof.Register(r, pprofPrefix)
	}

	reactFS := getFileSystem()
	r.StaticFS("/admin/", reactFS)
	r.NoRoute(
		func(c *gin.Context) {
			if strings.HasPrefix(c.Request.URL.Path, "/api/") {
				c.AbortWithStatus(http.StatusNotFound)
				return
			}
			c.FileFromFS("/", reactFS)
		},
	)

	r.POST(apiPathSetup, apiHandlers.adminSetup)
	r.GET(apiPathSetupStatus, apiHandlers.setupStatus)

	protected := r.Group(apiPrefix)
	protected.Use(authMiddleware(d))

	protected.GET(apiPathLoggedIn, apiHandlers.loggedIn)
	protected.GET(apiPathGetChatCommand, apiHandlers.getChatCommandDetail)
	protected.GET(apiPathGetDiscordMessages, apiHandlers.getDiscordMessages)
	protected.GET(apiListChatCommands, apiHandlers.getChatCommands)

	protected.POST(apiPathReloadUsers, apiHandlers.reloadUsers)
	protected.GET(apiPathUsers, apiHandlers.getUsers)
	protected.GET(apiPathUserHistory, apiHandlers.getUserHistory)
	protected.PATCH(apiPathUpdateUser, apiHandlers.updateUser)
	protected.GET(apiPathConfig, apiHandlers.getConfig)
	protected.PATCH(apiPathConfig, apiHandlers.updateRuntimeConfig)
	protected.POST(apiPathQuit, apiHandlers.botQuit)
	protected.POST(apiPathClearThreads, apiHandlers.clearThreads)
	protected.POST(
		apiPathRegisterCommands,
		apiHandlers.discordRegisterCommands,
	)
	protected.GET(apiPathOpenAIRetrieveRuns, apiHandlers.getOpenAIRetrieveRunLogs)
	protected.GET(apiPathOpenAICreateThread, apiHandlers.getOpenAICreateThreadLogs)
	protected.GET(apiPathOpenAICreateMessage, apiHandlers.getOpenAICreateMessageLogs)
	protected.GET(apiPathOpenAICreateRun, apiHandlers.getOpenAICreateRunLogs)
	protected.GET(apiPathOpenAIListMessages, apiHandlers.getOpenAIListMessagesLogs)
	protected.GET(apiPathOpenAIListRunSteps, apiHandlers.getOpenAIListRunStepsLogs)
	protected.GET(apiPathUserFeedback, apiHandlers.getUserFeedback)
	protected.GET(apiPathDiscordGatewayBot, apiHandlers.getDiscordGatewayBot)

	runtime.SetMutexProfileFraction(1)
	runtime.SetBlockProfileRate(1)
	return api, nil
}

func (a *API) Serve(ctx context.Context) error {
	if a.listener != nil {
		return a.httpServer.Serve(a.listener)
	}
	listenCfg := &net.ListenConfig{}
	ln, e := listenCfg.Listen(ctx, a.config.ListenNetwork, a.config.Listen)

	if e != nil {
		panic(e)
	}
	ln = tls.NewListener(ln, a.httpServer.TLSConfig)
	a.listener = ln
	return a.httpServer.Serve(a.listener)
}

func (a *API) getSessionUsername(c *gin.Context) (string, error) {
	store := a.store
	session, err := store.Get(c.Request, sessionVarName)
	if err != nil {
		return "", err
	}
	username, ok := session.Values[sessionVarField]
	if !ok {
		return "", errors.New("username not found in session")
	}
	s, e := username.(string)
	if !e {
		return "", errors.New("username not a string")
	}
	return s, nil
}

type CookieStore interface {
	sessions.Store
}

func NewCookieStore(keyPairs ...[]byte) CookieStore {
	return &cookieStore{gsessions.NewCookieStore(keyPairs...)}
}

type cookieStore struct {
	*gsessions.CookieStore
}

func (c *cookieStore) Options(options sessions.Options) {
	c.CookieStore.Options = options.ToGorillaOptions()
}

// APIHandlers contains the handlers for the various API endpoints.
//
// Fields:
//   - d: A pointer to the DisConcierge instance.
//   - logger: Logger for API-related events.
//   - store: CookieStore for session management.
type APIHandlers struct {
	d      *DisConcierge
	logger *slog.Logger
	store  CookieStore
}

// NewAPIHandlers initializes and returns a new instance of APIHandlers.
//
// This function sets up the logger, generates a secret key for session management,
// and configures the session store with appropriate options.
func NewAPIHandlers(d *DisConcierge) *APIHandlers {
	logger := d.logger.With(loggerNameKey, "api")

	var secretKey []byte
	switch sk := d.config.API.Secret; {
	case sk == "":
		logger.Warn(
			"api secret not set, generating random secret " +
				"(sessions will not persist across restarts)",
		)
		secretKey = securecookie.GenerateRandomKey(64)
	default:
		secretKey = derive64ByteKey(sk)
	}

	store := NewCookieStore(secretKey)
	sameSite := http.SameSiteStrictMode
	if d.config.API.Development {
		sameSite = http.SameSiteNoneMode
	}
	store.Options(
		sessions.Options{
			HttpOnly: true,
			Secure:   true,
			MaxAge:   int(d.config.API.SessionMaxAge.Seconds()),
			SameSite: sameSite,
		},
	)
	return &APIHandlers{d: d, logger: logger, store: store}
}

// setupStatus handles the HTTP GET request to check the setup status.
//
// This function checks if the initial admin setup is pending and sends a JSON response
// indicating whether the setup is required.
//
// Parameters:
//   - c: The Gin context for the request.
//
// Responses:
//   - 200 OK: Returns a JSON object with the setup status.
func (h *APIHandlers) setupStatus(c *gin.Context) {
	c.JSON(http.StatusOK, setupResponse{Required: h.d.pendingSetup.Load()})
}

// adminSetup handles the HTTP POST request for the initial admin setup.
//
// This function locks the configuration mutex, validates the setup payload,
// and updates the admin credentials in the database. It ensures that the
// setup is only performed if it is pending.
//
// Parameters:
//   - c: The Gin context for the request.
//
// Responses:
//   - 201 Created: If the admin credentials were successfully set.
//   - 400 Bad Request: If the request payload is invalid.
//   - 403 Forbidden: If the setup is not pending.
//   - 500 Internal Server Error: If there is an error updating the admin credentials.
func (h *APIHandlers) adminSetup(c *gin.Context) {
	h.d.cfgMu.Lock()
	defer h.d.cfgMu.Unlock()

	if !h.d.pendingSetup.Load() {
		c.JSON(http.StatusForbidden, httpError{Error: "Forbidden"})
		return
	}

	logger := ginContextLogger(c)
	logger.Info("first time admin setup")
	var adminSetup adminSetupPayload

	if e := c.ShouldBindJSON(&adminSetup); e != nil {
		logger.Error("bad payload", tint.Err(e))
		c.JSON(http.StatusBadRequest, gin.H{"error": e.Error()})
		return
	}

	currentState := h.d.runtimeConfig

	username := adminSetup.Username

	password, err := hashPassword(adminSetup.Password)
	if err != nil {
		logger.Error("error hashing password", tint.Err(err))
		c.JSON(
			http.StatusInternalServerError,
			gin.H{"error": "error setting admin credentials"},
		)
		return
	}

	if _, err = h.d.writeDB.Updates(
		currentState, map[string]any{
			columnRuntimeConfigAdminUsername: username,
			columnRuntimeConfigAdminPassword: password,
		},
	); err != nil {
		logger.Error("error updating admin credentials", tint.Err(err))
		c.JSON(
			http.StatusInternalServerError,
			gin.H{"error": "error updating admin credentials"},
		)
		return
	}
	h.d.runtimeConfig = currentState
	h.d.pendingSetup.Store(false)
	c.JSON(http.StatusCreated, gin.H{"message": "admin credentials set"})
}

// loginHandler handles the HTTP POST request to log in a user.
//
// This function validates the login request, checks the provided credentials
// against the stored admin credentials, and creates a new session if the login
// is successful. It also enforces rate limiting for login attempts.
//
// Parameters:
//   - c: The Gin context for the request.
//
// Responses:
//   - 200 OK: If the user was successfully logged in.
//   - 400 Bad Request: If the request payload is invalid.
//   - 401 Unauthorized: If the credentials are incorrect or not set.
//   - 429 Too Many Requests: If the login attempts are rate limited.
//   - 500 Internal Server Error: If there is an error processing the login request.
func (h *APIHandlers) loginHandler(c *gin.Context) {
	logger := h.d.logger
	if logger == nil {
		logger = slog.Default()
	}
	if !h.d.api.loginRequestLimiter.Allow() {
		logger.Warn("login rate limited")

		c.AbortWithStatus(http.StatusTooManyRequests)
		return
	}

	var login userLogin
	if err := c.ShouldBindJSON(&login); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	}

	runtimeConfig := h.d.RuntimeConfig()
	if runtimeConfig.AdminUsername == "" || runtimeConfig.AdminPassword == "" {
		logger.Warn("admin username and password not set")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
	}
	if login.Username != runtimeConfig.AdminUsername {
		logger.Warn("admin username incorrect")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
	}
	valid, err := verifyPassword(runtimeConfig.AdminPassword, login.Password)
	if err != nil {
		logger.Error("error verifying password", tint.Err(err))
		c.JSON(
			http.StatusInternalServerError,
			gin.H{"error": "Internal Server Error"},
		)
	}
	if !valid {
		logger.Warn("invalid login attempt", "username", login.Username)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
	}

	session, err := h.d.api.store.New(c.Request, sessionVarName)
	if err != nil {
		logger.Error("error creating session", tint.Err(err))

		sess, _ := h.store.Get(c.Request, sessionVarName)
		if sess != nil {
			sess.Values[sessionVarField] = ""
			_ = sess.Save(c.Request, c.Writer)
		}
		ginReplyError(c, "internal server error")
		return
	}
	if session == nil {
		logger.Error("didn't get session!?")
		ginReplyError(c, "internal server error")
		return
	}
	sameSite := http.SameSiteStrictMode
	if h.d.api.config.Development {
		sameSite = http.SameSiteNoneMode
	}
	logger.Warn(fmt.Sprintf("dev mode: %v", h.d.api.config.Development))
	session.Options = &gsessions.Options{
		MaxAge:   int(h.d.api.config.SessionMaxAge.Seconds()),
		SameSite: sameSite,
		HttpOnly: true,
		Secure:   true,
	}
	session.Values[sessionVarField] = login.Username
	err = session.Save(c.Request, c.Writer)
	if err != nil {
		logger.Error("error saving session", tint.Err(err))
		ginReplyError(c, "internal server error")
		return
	}
	logger.Info("saved user session", "username", login.Username)
	c.JSON(http.StatusOK, loggedInResponse{Username: login.Username})
}

// healthCheck handles the HTTP GET request for a health check.
//
// This function retrieves the current status of the bot, including whether it is paused,
// the size of the request queue, and the connection status of the Discord gateway.
// It sends this information as a JSON response.
//
// Parameters:
//   - c: The Gin context for the request.
//
// Responses:
//   - 200 OK: Returns the health check information in JSON format.
func (h *APIHandlers) healthCheck(c *gin.Context) {
	c.JSON(
		http.StatusOK, healthCheckResponse{
			Paused:                  h.d.paused.Load(),
			QueueSize:               h.d.requestQueue.Len(),
			DiscordGatewayConnected: h.d.discord.connected.Load(),
		},
	)
}

// logoutHandler handles the HTTP POST request to log out a user.
//
// This function retrieves the session, clears the username from the session,
// and saves the session. It sends a response indicating that the user has been logged out.
//
// Parameters:
//   - c: The Gin context for the request.
//
// Responses:
//   - 200 OK: If the user was successfully logged out.
//   - 500 Internal Server Error: If there was an error processing the logout request.
func (h *APIHandlers) logoutHandler(c *gin.Context) {
	logger := ginContextLogger(c)
	session, err := h.store.Get(c.Request, sessionVarName)
	if err != nil {
		logger.Error("error getting session", tint.Err(err))
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	session.Values[sessionVarField] = ""
	err = session.Save(c.Request, c.Writer)
	if err != nil {
		logger.Error("error saving cookie", tint.Err(err))
	}
	ginReplyMessage(c, "logged out")
}

// loggedIn handles the HTTP GET request to check if a user is logged in.
//
// This function retrieves the session username and sends a JSON response
// with the username if the user is authenticated. If the user is not
// authenticated, it responds with a 401 Unauthorized status.
//
// Parameters:
//   - c: The Gin context for the request.
//
// Responses:
//   - 200 OK: Returns the username of the logged-in user.
//   - 401 Unauthorized: If the user is not authenticated.
func (h *APIHandlers) loggedIn(c *gin.Context) {
	username, err := h.d.api.getSessionUsername(c)

	if err != nil {
		ginContextLogger(c).Warn(
			"error getting session username",
			tint.Err(err),
		)
		c.JSON(
			http.StatusUnauthorized,
			httpError{Error: "unauthorized"},
		)
		return
	}
	c.JSON(http.StatusOK, loggedInResponse{Username: username})
}

// discordRegisterCommands handles the HTTP POST request to register Discord commands.
//
// This function registers the commands with the Discord API and sends a response
// indicating whether the registration was successful.
//
// Parameters:
//   - c: The Gin context for the request.
//
// Responses:
//   - 201 Created: If the commands were successfully registered.
//   - 500 Internal Server Error: If there was an error registering the commands.
func (h *APIHandlers) discordRegisterCommands(c *gin.Context) {
	log := ginContextLogger(c)
	log.Info("registering commands")

	createdCommands, err := h.d.discord.registerCommands(h.d.RuntimeConfig())
	if err != nil {
		log.Error("error registering commands", tint.Err(err))
		c.JSON(http.StatusInternalServerError, httpError{Error: "error registering commands"})
		return
	}
	c.JSON(http.StatusCreated, createdCommands)
}

// botPause handles the HTTP POST request to pause the DisConcierge bot.
//
// This function locks the configuration mutex, attempts to pause the bot,
// and sends a response indicating whether the bot was successfully paused.
//
// Parameters:
//   - c: The Gin context for the request.
//
// Responses:
//   - 200 OK: If the bot was successfully paused.
//   - 409 Conflict: If the bot is already paused.
// func (h *APIHandlers) botPause(c *gin.Context) {
// 	log := ginContextLogger(c)
// 	h.d.cfgMu.Lock()
// 	defer h.d.cfgMu.Unlock()
//
// 	if h.d.Pause(context.Background()) {
// 		log.Info("bot paused")
// 		ginReplyMessage(c, "bot paused")
// 		return
// 	}
//
// 	c.AbortWithStatusJSON(
// 		http.StatusConflict,
// 		httpError{Error: "bot already paused"},
// 	)
// }

// reloadUsers handles the HTTP POST request to reload the user cache.
//
// This function reloads the user cache from the database and sends the updated
// user list as a JSON response.
//
// Parameters:
//   - c: The Gin context for the request.
//
// Responses:
//   - 200 OK: Returns the updated list of users.
// func (h *APIHandlers) botResume(c *gin.Context) {
// 	h.d.cfgMu.Lock()
// 	defer h.d.cfgMu.Unlock()
//
// 	ok := h.d.Resume(context.Background())
// 	if ok {
// 		ginReplyMessage(c, "bot resumed")
// 		return
// 	}
// 	c.AbortWithStatusJSON(http.StatusConflict, httpError{Error: "bot not paused"})
// }

// reloadUsers handles the HTTP POST request to reload the user cache.
//
// This function reloads the user cache from the database and sends the updated
// user list as a JSON response.
//
// Parameters:
//   - c: The Gin context for the request.
//
// Responses:
//   - 200 OK: Returns the updated list of users.
func (h *APIHandlers) reloadUsers(c *gin.Context) {
	log := ginContextLogger(c)
	log.Info("sending user cache reload notification")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sent := h.d.dbNotifier.ReloadUserCache(ctx)
	if sent {
		c.JSON(http.StatusAccepted, httpReply{Message: "Notification sent"})
		return
	}
	c.JSON(http.StatusInternalServerError, httpError{Error: "error sending notification"})
}

// getUsers handles the HTTP GET request to retrieve a list of users.
//
// This function supports pagination and sorting of the results. It validates the query parameters,
// retrieves the users from the database, and optionally includes user statistics in the response.
//
// Parameters:
//   - c: The Gin context for the request.
//
// Responses:
//   - 200 OK: Returns the list of users, optionally including statistics.
//   - 400 Bad Request: If the query parameters are invalid.
//   - 500 Internal Server Error: If there is an error retrieving the users.
func (h *APIHandlers) getUsers(c *gin.Context) {
	var pagination GetUsersQuery
	if c.ShouldBindQuery(&pagination) != nil {
		c.JSON(http.StatusBadRequest, httpError{Error: "invalid pagination"})
		return
	}

	if pagination.Order == "" {
		pagination.Order = Ascending
	}
	if pagination.Limit == 0 {
		pagination.Limit = 25
	}

	log := ginContextLogger(c)

	var users []User

	var err error
	switch pagination.Order {
	case Descending:
		err = h.d.db.Limit(pagination.Limit).Offset(pagination.Offset).Order("id desc").Find(&users).Error
	default:
		err = h.d.db.Limit(pagination.Limit).Offset(pagination.Offset).Order("id asc").Find(&users).Error
	}
	if err != nil {
		log.Error("error getting users", tint.Err(err))
		c.JSON(http.StatusInternalServerError, httpError{Error: "error getting users"})
		return
	}

	if !pagination.IncludeStats {
		c.JSON(http.StatusOK, users)
		return
	}

	usersWithStats := make([]userWithStats, len(users))

	// FIXME not very efficient - we should be querying for all necessary
	//   records to compile user stats with `user_id IN (...)` rather than
	//   querying per-user

	g, _ := errgroup.WithContext(context.Background())
	for ind, u := range users {
		g.Go(
			func() error {
				withStats := userWithStats{User: u}
				stats, e := u.getStats(context.Background(), h.d.db)
				withStats.UserStats = &stats
				if e == nil {
					usersWithStats[ind] = withStats
				}
				return e
			},
		)
	}
	if e := g.Wait(); e != nil {
		log.Error("error getting user stats", tint.Err(e))
		c.JSON(
			http.StatusInternalServerError,
			httpError{Error: "error getting user stats"},
		)
		return
	}

	c.JSON(http.StatusOK, usersWithStats)
}

// getUserHistory handles the HTTP GET request to retrieve a user's command history.
//
// This function validates the query parameters, checks for the existence of the user,
// and retrieves the user's command history from the database. It supports pagination
// and sorting of the results.
//
// Parameters:
//   - c: The Gin context for the request.
//
// Responses:
//   - 200 OK: Returns the user's command history.
//   - 400 Bad Request: If the query parameters are invalid.
//   - 404 Not Found: If the user does not exist.
//   - 500 Internal Server Error: If there is an error retrieving the user's history.
func (h *APIHandlers) getUserHistory(c *gin.Context) {
	logger := ginContextLogger(c)
	var queryParams userHistoryQueryParams
	if err := c.ShouldBindQuery(&queryParams); err != nil {
		c.JSON(http.StatusBadRequest, httpError{Error: err.Error()})
		return
	}
	if queryParams.Sort == "" {
		queryParams.Sort = Ascending
	}
	if queryParams.Limit == 0 {
		queryParams.Limit = 20
	}

	// for some reason this operation was occasionally hanging,
	// so i've added a general timeout
	timeoutCtx, cancel := context.WithTimeout(
		context.Background(),
		15*time.Second,
	)
	defer cancel()
	log := ginContextLogger(c)
	userID := c.Param("id")
	var user User

	if err := h.d.db.WithContext(timeoutCtx).First(
		&user,
		"id = ?",
		userID,
	).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			log.Warn("user not found", columnUserID, userID)
			c.JSON(http.StatusNotFound, httpError{Error: "User not found"})
			return
		}
		log.Error("error getting user", tint.Err(err))
		c.JSON(http.StatusInternalServerError, httpError{Error: "error getting user"})
		return
	}

	var chatCommands []ChatCommand

	stmt := h.d.db.WithContext(timeoutCtx).Limit(queryParams.Limit)
	if queryParams.Sort == Descending {
		stmt = stmt.Order("id desc")
	} else {
		stmt = stmt.Order("id asc")
	}
	err := stmt.Select(
		columnChatCommandID,
		columnChatCommandCreatedAt,
		columnChatCommandPrompt,
		columnChatCommandInteractionID,
		columnChatCommandResponse,
		columnChatCommandClear,
		columnChatCommandThreadID,
		columnChatCommandRunID,
		columnChatCommandRunStatus,
		columnChatCommandError,
		columnChatCommandContext,
		columnChatCommandState,
		columnChatCommandStep,
	).Where("user_id = ?", user.ID).Find(&chatCommands).Error
	// TODO add a test for queries on multiple users
	if err != nil {
		log.Error("error getting user history", tint.Err(err))
		c.JSON(
			http.StatusInternalServerError,
			httpError{Error: "error getting user history"},
		)
		return
	}
	history := make([]userHistoryItem, len(chatCommands))

	logger.Info(fmt.Sprintf("found %d records", len(history)))

	g, _ := errgroup.WithContext(context.Background())
	for ind, ac := range chatCommands {
		g.Go(
			func() error {
				hist := userHistoryItem{
					Username:      user.Username,
					GlobalName:    user.GlobalName,
					UserID:        user.ID,
					Prompt:        ac.Prompt,
					State:         ac.State,
					Step:          ac.Step,
					Response:      ac.Response,
					CreatedAt:     time.UnixMilli(ac.CreatedAt).UTC(),
					RunID:         ac.RunID,
					ThreadID:      ac.ThreadID,
					RunStatus:     ac.RunStatus,
					ChatCommandID: ac.ID,
					InteractionID: ac.InteractionID,
					Context:       ac.CommandContext,
					Private:       ac.Private,
					Error:         string(ac.Error),
				}
				if queryParams.IncludeReports {
					var reportVals []string
					reports, e := ac.getReports(timeoutCtx, h.d.db)
					if e != nil {
						return e
					}
					for _, rp := range reports {
						if rp.Type == string(UserFeedbackReset) {
							continue
						}
						if rp.Type == string(UserFeedbackOther) {
							reportVals = append(reportVals, rp.Detail)
						} else {
							reportVals = append(reportVals, rp.Description)
						}
					}
					hist.Feedback = strings.Join(reportVals, " / ")
				}

				history[ind] = hist
				return nil
			},
		)
	}

	if e := g.Wait(); e != nil {
		log.Error("error getting reports", tint.Err(e))
		c.JSON(
			http.StatusInternalServerError,
			httpError{Error: "error getting reports"},
		)
		return
	}

	logger.Info(fmt.Sprintf("found %d records", len(history)))
	c.JSON(http.StatusOK, history)
}

// getConfig handles the HTTP GET request to retrieve the bot's runtime configuration.
//
// This function fetches the current runtime configuration of the bot and
// sends it as a JSON response.
//
// Parameters:
//   - c: The Gin context for the request.
//
// Responses:
//   - 200 OK: Returns the current runtime configuration in JSON format.
func (h *APIHandlers) getConfig(c *gin.Context) {
	botState := h.d.RuntimeConfig()
	c.JSON(http.StatusOK, botState)
}

// updateRuntimeConfig handles the HTTP PATCH request to update the bot's runtime configuration.
//
// This function validates the request payload, applies the updates to the runtime configuration,
// and persists the changes to the database. It also ensures that the new configuration is valid
// and updates the bot's state accordingly.
//
// Parameters:
//   - c: The Gin context for the request.
//
// Responses:
//   - 200 OK: Returns the updated runtime configuration.
//   - 400 Bad Request: If the request payload is invalid.
//   - 500 Internal Server Error: If there is an error updating the configuration.
func (h *APIHandlers) updateRuntimeConfig(c *gin.Context) {
	d := h.d
	d.cfgMu.Lock()
	defer d.cfgMu.Unlock()

	ctx := context.Background()

	var updateRequest RuntimeConfigUpdate
	logger := ginContextLogger(c)
	if err := c.ShouldBindJSON(&updateRequest); err != nil {
		logger.Error("bad payload", tint.Err(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	existingConfig := d.runtimeConfig
	rollbackConfig := *existingConfig

	updateData, err := json.Marshal(updateRequest)
	if err != nil {
		logger.ErrorContext(c, "Error marshaling update request", tint.Err(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error marshaling update request"})
		return
	}

	var updates map[string]any
	err = json.Unmarshal(updateData, &updates)
	if err != nil {
		logger.ErrorContext(c, "Error unmarshalling update request", tint.Err(err))
		c.JSON(
			http.StatusInternalServerError,
			gin.H{"error": "Error unmarshalling update request"},
		)
		return
	}
	logger.InfoContext(c, "Applying updates", "updates", updates)

	var updateError error

	var statusCode int
	var ginResponse gin.H

	_ = h.d.writeDB.Transaction(
		func(tx *gorm.DB) error {
			updateError = tx.Model(existingConfig).Updates(updates).Error
			if updateError != nil {
				statusCode = http.StatusInternalServerError
				ginResponse = gin.H{"error": "Error updating config"}
				return updateError
			}

			updateError = structValidator.Struct(existingConfig)
			if updateError != nil {
				statusCode = http.StatusBadRequest
				ginResponse = gin.H{"error": "Error validating config"}
				return updateError
			}
			return nil
		},
	)

	if updateError != nil {
		h.d.runtimeConfig = &rollbackConfig
		logger.ErrorContext(c, "Error updating config", tint.Err(updateError))
		c.JSON(statusCode, ginResponse)
		return
	}

	d.setRuntimeLevels(*existingConfig)

	wasPaused := d.paused.Swap(existingConfig.Paused)
	switch {
	case wasPaused && !existingConfig.Paused:
		logger.Info("unpaused bot")
	case existingConfig.Paused && !wasPaused:
		logger.Warn("paused bot")
	}

	updateDiscordBotStatus(d, logger, rollbackConfig, existingConfig)

	if existingConfig.DiscordNotificationChannelID != rollbackConfig.DiscordNotificationChannelID {
		go sendStartupMessage(h.d.discord, logger, *existingConfig)
	}

	// any change in slash command parameters means we need to overwrite
	// the commands so the changes take effect
	g := new(errgroup.Group)

	g.Go(
		func() error {
			e := overwriteDiscordCommands(
				h.d.discord,
				logger,
				rollbackConfig,
				*existingConfig,
			)
			if e != nil {
				e = fmt.Errorf("error overwriting commands: %w", err)
			}
			return e
		},
	)

	g.Go(
		func() error {
			e := updateUsersFromRuntimeConfig(
				ctx,
				h.d.writeDB,
				updateRequest,
				&rollbackConfig,
			)
			if e != nil {
				e = fmt.Errorf("error updating users: %w", e)
			}
			return e
		},
	)

	if updErr := g.Wait(); updErr != nil {
		logger.Error("error processing update(s)", tint.Err(updErr))
	}

	c.JSON(http.StatusAccepted, existingConfig)

	sent := h.d.dbNotifier.ReloadRuntimeConfig(ctx)
	if !sent {
		logger.Error("error sending config update notification")
	}

	sent = h.d.dbNotifier.ReloadUserCache(ctx)
	if !sent {
		logger.Error("error sending user cache notification")
	}

}

// updateUser handles the HTTP PATCH request to update a user's information.
//
// This function validates the request payload, checks for the existence of the user,
// and updates the user's information in the database. It ensures that the request
// limits are consistent and responds with the updated user information.
//
// Parameters:
//   - c: The Gin context for the request.
//
// Responses:
//   - 200 OK: Returns the updated user information.
//   - 400 Bad Request: If the request payload is invalid or the request limits are inconsistent.
//   - 404 Not Found: If the user does not exist.
//   - 500 Internal Server Error: If there is an error updating the user information.
func (h *APIHandlers) updateUser(c *gin.Context) {
	log := ginContextLogger(c)

	var update apiPatchUser
	if err := c.ShouldBindJSON(&update); err != nil {
		log.Warn("bad request", tint.Err(err))
		c.JSON(http.StatusBadRequest, httpError{Error: err.Error()})
		return
	}
	userID := c.Param("id")
	user := h.d.writeDB.GetUser(userID)
	if user == nil {
		log.Warn("User not found", columnUserID, userID)
		c.JSON(http.StatusNotFound, httpError{Error: "User not found"})
		return
	}

	updateContent, err := json.Marshal(update)
	if err != nil {
		log.Error("error marshaling update request", tint.Err(err))
		c.JSON(http.StatusInternalServerError, httpError{Error: "error marshaling update request"})
		return
	}

	var updateData map[string]any
	if err = json.Unmarshal(updateContent, &updateData); err != nil {
		log.Error("error unmarshalling update request", tint.Err(err))
		c.JSON(
			http.StatusInternalServerError,
			httpError{Error: "error unmarshalling update request"},
		)
		return
	}

	if len(updateData) == 0 {
		c.JSON(http.StatusAccepted, user)
		return
	}

	log.Info("updating user", "user", user, "updates", updateData)

	_, err = h.d.writeDB.Updates(user, updateData)
	if err != nil {
		log.Error("error updating user", columnUserID, userID, tint.Err(err))
		_ = h.d.writeDB.ReloadUser(userID)
		c.JSON(http.StatusInternalServerError, httpError{Error: "error updating User"})
		return
	}
	c.JSON(http.StatusAccepted, h.d.writeDB.ReloadUser(userID))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	h.d.dbNotifier.UserUpdated(ctx, userID)
}

// botQuit handles the HTTP POST request to quit the DisConcierge bot.
//
// This function sends a stop signal to the bot, which will initiate the shutdown process.
// It responds immediately to the client, indicating that the quit request has been received.
//
// Parameters:
//   - c: The Gin context for the request.
//
// Responses:
//   - 200 OK: Returns a message indicating that the quit request has been received.
func (h *APIHandlers) botQuit(c *gin.Context) {
	log := ginContextLogger(c)
	log.Warn("sending stop signal")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	doneCh := make(chan struct{}, 1)
	go func() {
		h.d.dbNotifier.Stop(ctx)
		doneCh <- struct{}{}
		close(doneCh)
	}()
	select {
	case <-doneCh:
		ginReplyMessage(c, "quitting")
	case <-ctx.Done():
		log.Warn("timeout sending stop signal")
		c.JSON(http.StatusGatewayTimeout, httpError{Error: "timeout sending stop signal"})
	}

}

// clearThreads handles the HTTP POST request to clear all user threads.
//
// This function updates the database to set the thread ID of all users to nil,
// effectively clearing all threads. It then reloads the user cache to reflect
// the changes.
//
// Parameters:
//   - c: The Gin context for the request.
//
// Responses:
//   - 200 OK: Returns a message indicating the number of threads cleared.
//   - 500 Internal Server Error: Returns an error message if the operation fails.
func (h *APIHandlers) clearThreads(c *gin.Context) {
	h.d.writeDB.UserCacheLock()
	defer h.d.writeDB.UserCacheUnlock()

	affected, err := h.d.writeDB.UpdatesWhere(
		User{},
		map[string]any{columnUserThreadID: nil},
		"thread_id is not null",
	)
	log := ginContextLogger(c)
	if err != nil {
		log.Error("error clearing threads", tint.Err(err))
		ginReplyError(c, "error clearing threads")
		return
	}

	log.Info(fmt.Sprintf("Cleared %d threads", affected))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if !h.d.dbNotifier.ReloadUserCache(ctx) {
		log.Error("error sending user cache notification")
		ginReplyError(c, "error sending user cache notification")
		return
	}
	ginReplyMessage(
		c,
		fmt.Sprintf("cleared %d threads", affected),
	)
}

// getChatCommands handles the HTTP GET request to retrieve a list of chat commands.
//
// It supports pagination and filtering by user ID, enqueue date, and end date.
// The results can be sorted in ascending or descending order based on the creation date.
//
// Query Parameters:
//   - limit: The maximum number of records to return (default: 25).
//   - offset: The number of records to skip before starting to return records.
//   - order: The order in which to return the records (ascending or descending).
//   - user_id: Filter results by the user ID.
//   - start_date: Filter results to include only those created on or
//     after this date (format: YYYY-MM-DD).
//   - end_date: Filter results to include only those created before this date (format: YYYY-MM-DD).
//
// Responses:
//   - 200 OK: Returns a list of chat commands.
//   - 400 Bad Request: If the query parameters are invalid.
//   - 500 Internal Server Error: If there is an error retrieving the chat commands.
func (h *APIHandlers) getChatCommands(c *gin.Context) {
	var pagination GetChatCommandsQuery
	if err := c.ShouldBindQuery(&pagination); err != nil {
		c.JSON(http.StatusBadRequest, httpError{Error: "invalid pagination"})
		return
	}

	if pagination.Order == "" {
		pagination.Order = Descending
	}
	if pagination.Limit == 0 {
		pagination.Limit = 25
	}

	log := ginContextLogger(c)

	var chatCommands []ChatCommand

	query := h.d.db.Model(&ChatCommand{}).Preload(
		"User",
	).Limit(pagination.Limit).Offset(pagination.Offset)

	if pagination.UserID != "" {
		query = query.Where("user_id = ?", pagination.UserID)
	}

	if pagination.StartDate != "" {
		startDate, err := time.Parse("2006-01-02", pagination.StartDate)
		if err != nil {
			c.JSON(
				http.StatusBadRequest,
				httpError{Error: "invalid start_date format"},
			)
			return
		}
		query = query.Where("created_at >= ?", startDate.UnixMilli())
	}

	if pagination.EndDate != "" {
		endDate, err := time.Parse("2006-01-02", pagination.EndDate)
		if err != nil {
			c.JSON(
				http.StatusBadRequest,
				httpError{Error: "invalid end_date format"},
			)
			return
		}
		// Add one day to include the entire end date
		endDate = endDate.Add(24 * time.Hour)
		query = query.Where("created_at < ?", endDate.UnixMilli())
	}

	switch pagination.Order {
	case Descending:
		query = query.Order("created_at desc")
	default:
		query = query.Order("created_at asc")
	}

	err := query.Find(&chatCommands).Error
	if err != nil {
		log.ErrorContext(
			c.Request.Context(),
			"error getting chat commands",
			tint.Err(err),
		)
		c.JSON(
			http.StatusInternalServerError,
			httpError{Error: "error getting chat commands"},
		)
		return
	}

	c.JSON(http.StatusOK, chatCommands)
}

// GetChatCommandsQuery represents the query parameters for fetching ChatCommand records.
type GetChatCommandsQuery struct {
	Pagination
	UserID    string `form:"user_id"`
	StartDate string `form:"start_date" binding:"omitempty,datetime=2006-01-02"`
	EndDate   string `form:"end_date" binding:"omitempty,datetime=2006-01-02"`
}

// Pagination represents the pagination parameters for API requests.
//
// Fields:
//   - Limit: The maximum number of records to return.
//   - Order: The order in which to return the records (ascending or descending).
//   - Offset: The number of records to skip before starting to return records.
type Pagination struct {
	Limit  int  `form:"limit" binding:"omitempty,min=1,max=100"`
	Order  Sort `form:"order" binding:"omitempty,oneof=asc desc"`
	Offset int  `form:"offset" binding:"omitempty,min=0"`
}

// GetUsersQuery represents the query parameters for fetching User records.
//
// Fields:
//   - Pagination: Embeds pagination parameters such as limit, order, and offset.
//   - IncludeStats: Indicates whether to include user statistics in the response.
type GetUsersQuery struct {
	Pagination
	IncludeStats bool `form:"include_stats" json:"include_stats"`
}

// Sort represents the sorting order for queries.
//
// It is used to specify the order in which results should be returned,
// either in ascending or descending order.
//
// Possible values:
//   - Ascending: Sort results in ascending order.
//   - Descending: Sort results in descending order.
type Sort string

// apiPatchUser accepts payload to update specific fields of a User record.
// Any non-nil value will be updated.
//
//nolint:lll // struct tags can't be split
type apiPatchUser struct {
	Priority                             *bool                      `json:"priority,omitempty" binding:"omitnil"`
	Ignored                              *bool                      `json:"ignored,omitempty" binding:"omitnil"`
	UserChatCommandLimit6h               *int                       `json:"user_chat_command_limit_6h,omitempty" binding:"omitnil,min=1"`
	OpenAIMaxCompletionTokens            *int                       `json:"openai_max_completion_tokens,omitempty" binding:"omitnil"`
	OpenAIMaxPromptTokens                *int                       `json:"openai_max_prompt_tokens,omitempty" binding:"omitnil,omitempty,min=256"`
	OpenAITruncationStrategyType         *openai.TruncationStrategy `json:"openai_truncation_strategy_type,omitempty"  binding:"omitnil,omitempty,oneof=auto last_messages"`
	OpenAITruncationStrategyLastMessages *int                       `json:"openai_truncation_strategy_last_messages,omitempty" binding:"omitnil,omitempty,min=1"`
	AssistantAdditionalInstructions      *string                    `json:"assistant_additional_instructions,omitempty" binding:"omitnil"`
	AssistantTemperature                 *float32                   `json:"assistant_temperature,omitempty" binding:"omitnil,min=0,max=2"`
	AssistantPollInterval                *Duration                  `json:"assistant_poll_interval,omitempty"`
	AssistantMaxPollInterval             *Duration                  `json:"assistant_max_poll_interval,omitempty"`
}

// userHistoryQueryParams represents the query parameters for fetching user history.
//
// Fields:
//   - Sort: Specifies the sorting order for the results. It can be either ascending or descending.
//   - Limit: Specifies the maximum number of records to return.
//   - IncludeReports: Indicates whether to include reports in the response.
type userHistoryQueryParams struct {
	Sort           Sort `form:"sort" json:"sort"`
	Limit          int  `form:"limit" json:"limit"`
	IncludeReports bool `form:"include_reports" json:"include_reports"`
}

// userHistoryItem represents a single item in a user's command history.
// It encapsulates details about a specific command execution, including
// user information, command content, and execution status.
type userHistoryItem struct {
	// UserID is the unique identifier of the user who executed the command.
	UserID string `json:"user_id"`

	// Username is the Discord username of the user.
	Username string `json:"username"`

	// GlobalName is the global display name of the user on Discord.
	GlobalName string `json:"global_name"`

	// Prompt is the original command or question submitted by the user.
	Prompt string `json:"prompt"`

	// Response is the bot's reply to the user's command. It may be nil if
	// the command hasn't been processed yet or failed to generate a response.
	Response *string `json:"response,omitempty"`

	// State represents the current processing state of the command.
	State ChatCommandState `json:"state"`

	// Step indicates the current step in the command execution process.
	Step ChatCommandStep `json:"step"`

	// RunStatus shows the status of the OpenAI run associated with this command.
	RunStatus openai.RunStatus `json:"run_status"`

	// RunID is the unique identifier for the OpenAI run.
	RunID string `json:"run_id"`

	// ThreadID is the identifier for the conversation thread this command belongs to.
	ThreadID string `json:"thread_id"`

	// Error contains any error message encountered during command processing.
	// It's empty if no errors occurred.
	Error string `json:"error,omitempty"`

	// CreatedAt is the timestamp when the command was created.
	CreatedAt time.Time `json:"created_at"`

	// ChatCommandID is the unique identifier for this specific command instance.
	ChatCommandID uint `json:"chat_command_id"`

	// InteractionID is the Discord interaction identifier associated with this command.
	InteractionID string `json:"interaction_id"`

	// Context provides additional context about the command execution environment.
	Context string `json:"context"`

	// Private indicates whether this was a private command (private response).
	Private bool `json:"private"`

	// Feedback contains any user feedback provided for this command.
	Feedback string `json:"feedback"`
}

// userWithStats represents a User along with their associated usage statistics.
// This struct combines basic user information with detailed statistics about
// their interactions with the bot, providing a comprehensive view of the user's
// activity and usage patterns.
type userWithStats struct {
	// User contains the basic information about the user, including
	// their ID, username, and other relevant Discord user data.
	User

	// UserStats contains detailed statistics about the user's interactions
	// with the bot. It may be nil if stats are not available or have not
	// been calculated.
	UserStats *UserStats `json:"stats,omitempty"`
}

// loggedInResponse represents the response returned when a user is successfully logged in.
//
// Fields:
//   - Username: The username of the logged-in user.
type loggedInResponse struct {
	Username string `json:"username"`
}

// healthCheckResponse represents the response structure for a health check endpoint.
//
// Fields:
//   - Paused: Indicates whether the bot is currently paused.
//   - QueueSize: The current size of the processing queue.
//   - DiscordGatewayConnected: Indicates whether the Discord gateway is connected.
type healthCheckResponse struct {
	Paused                  bool `json:"paused"`
	QueueSize               int  `json:"queue_size"`
	DiscordGatewayConnected bool `json:"discord_gateway_connected"`
}

// httpReply represents a standard HTTP response message.
//
// Fields:
//   - Message: The message content of the HTTP response.
type httpReply struct {
	Message string `json:"message"`
}

// httpError represents an error message returned ot the client
//
// Fields:
//   - Message: The message content of the HTTP response.
type httpError struct {
	Error string `json:"error"`
}

// userLogin represents the payload for user login requests.
//
// Fields:
//   - Username: The username of the user attempting to log in.
//   - Password: The password of the user attempting to log in.
type userLogin struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// adminSetupPayload represents the payload for the initial admin setup.
//
// Fields:
//   - Username: The username for the admin account.
//   - Password: The password for the admin account.
//   - ConfirmPassword: The confirmation of the password to ensure it matches.
type adminSetupPayload struct {
	Username        string `json:"username" binding:"required"`
	Password        string `json:"password" binding:"required,eqfield=ConfirmPassword"`
	ConfirmPassword string `json:"confirm_password" binding:"required"`
}

// setupResponse is the response struct for the 'setup status'
// endpoint. If an admin username/password haven't been yet,
// Required will be true, indicating setup is needed.
// This is used by the frontend to know when to redirect a
// web UI user to the setup page to set the credentials.
type setupResponse struct {
	Required bool `json:"required"`
}

// authMiddleware returns a Gin middleware function for authentication.
//
// It retrieves the session from the request and checks if the user is
// authenticated. If the user is not authenticated, it aborts the request
// with a 401 Unauthorized status.
//
// If the bot is pending setup (no admin credentials have been set),
// it also returns HTTP 401.
// Parameters:
//   - d: A pointer to the DisConcierge instance.
//
// Returns:
//   - A Gin middleware function that handles authentication.
func authMiddleware(d *DisConcierge) gin.HandlerFunc {
	return func(c *gin.Context) {
		store := d.api.store
		logger := d.logger
		if logger == nil {
			logger = slog.Default()
		}
		if d.pendingSetup.Load() {
			logger.Warn("admin username and password not set")
			c.AbortWithStatusJSON(
				http.StatusUnauthorized,
				httpError{Error: "unauthorized"},
			)
		}

		session, err := store.Get(c.Request, sessionVarName)
		if err != nil {
			logger.Error("error getting session", tint.Err(err))
			c.AbortWithStatusJSON(
				http.StatusUnauthorized,
				httpError{Error: "unauthorized"},
			)
			return
		}

		if session == nil {
			logger.Error("session is nil")
			c.AbortWithStatusJSON(
				http.StatusUnauthorized,
				httpError{Error: "unauthorized"},
			)
			return
		}

		d.logger.Debug("session values", "session_values", session.Values)
		username, ok := session.Values[sessionVarField]

		if !ok || username == "" {
			logger.Warn(
				"username not found in session",
				"headers",
				c.Request.Header,
			)
			c.AbortWithStatusJSON(
				http.StatusUnauthorized,
				httpError{Error: "unauthorized"},
			)
			return
		}

		logger.Info("got session", sessionVarField, username)

		c.Next()
	}
}

// requestIDMiddleware generates a Gin middleware function that assigns a
// unique request ID to each incoming request.
//
// It generates a random hexadecimal string and sets it in the Gin context
// under the key "X-Request-ID".
// This ID can be used for tracking and logging purposes.
func requestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := generateRandomHexString(32)
		if err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		c.Set(xRequestIDHeader, id)
		if requestID, exists := c.Get(xRequestIDHeader); exists {
			c.Header(xRequestIDHeader, requestID.(string))
		}
		c.Next()
	}
}

// ginContextLogger returns the slog.Logger from the given gin context,
// or, if it doesn't exist, creates a logger with request details included,
// and sets the logger in the context so the next call to ginContextLogger
// will return the new logger.
func ginContextLogger(c *gin.Context) *slog.Logger {
	var requestLogger *slog.Logger
	logger, ok := c.Get(string(loggerContextKey))
	if ok {
		requestLogger, ok = logger.(*slog.Logger)
		if ok {
			return requestLogger
		}
	}
	requestLogger = slog.Default()
	requestID, _ := c.Get(xRequestIDHeader)
	path := c.Request.URL.Path
	raw := c.Request.URL.RawQuery
	if raw != "" {
		path = path + "?" + raw
	}

	requestLogger = requestLogger.With(
		slog.Group(
			"request",
			"method", c.Request.Method,
			"path", path,
			"remote_addr", c.Request.RemoteAddr,
			"remote_ip", c.RemoteIP(),
			"user_agent", c.Request.UserAgent(),
			"referer", c.Request.Referer(),
		),
		slog.Any(xRequestIDHeader, requestID),
	)
	c.Set(string(loggerContextKey), requestLogger)
	return requestLogger
}

// ginLoggingMiddleware returns a Gin middleware function for logging HTTP requests.
//
// It logs the request method, path, remote address, user agent, referer, and the duration
// of the request. If there are any errors, it logs them as well.
func ginLoggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		requestLogger := ginContextLogger(c)
		c.Next()
		latency := time.Since(start)

		var errs []error
		for _, e := range c.Errors.ByType(gin.ErrorTypePrivate) {
			errs = append(errs, *e)
		}
		if len(errs) > 0 {
			requestLogger.Error(
				fmt.Sprintf(
					"%s %s finished with errors",
					c.Request.Method,
					c.Request.URL,
				),
				"duration", latency,
				"errors", errs,
				slog.Group(
					"response",
					"status_code", c.Writer.Status(),
					"body_size", c.Writer.Size(),
				),
			)
		} else {
			requestLogger.Info(
				fmt.Sprintf("%s %s finished", c.Request.Method, c.Request.URL),
				"duration", latency,
				slog.Group(
					"response",
					"status_code", c.Writer.Status(),
					"body_size", c.Writer.Size(),
				),
			)
		}
	}
}

// metricMiddleware returns a Gin middleware function for tracking API request
// metrics.
//
// It increments the request count for each unique combination of HTTP
// method and URL path.
// The metrics are stored in the API's requestMetrics map, which is protected
// by a mutex.
func metricMiddleware(a *API) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer c.Next()

		a.requestMetricsMu.Lock()
		defer a.requestMetricsMu.Unlock()

		key := fmt.Sprintf("%s %s", c.Request.Method, c.Request.URL.Path)
		_, ok := a.requestMetrics[key]
		if !ok {
			a.requestMetrics[key] = 1
			return
		}
		a.requestMetrics[key]++
	}
}

// ginReplyMessage sends a JSON response with a message,
// with HTTP status code 200, via the gin context.
// This is shorthand for something like:
//
//	c.JSON(http.StatusOK, gin.H{"message": message})
func ginReplyMessage(c *gin.Context, message string) {
	c.JSON(http.StatusOK, httpReply{Message: message})
}

// ginReplyError sends a JSON response with a message,
// with HTTP status code 500, via the gin context.
// This is shorthand for something like:
//
//	c.JSON(http.StatusInternalServerError, gin.H{"error": err})
func ginReplyError(c *gin.Context, err string) {
	c.AbortWithStatusJSON(http.StatusInternalServerError, httpError{Error: err})
}

// generateSelfSignedCert generates a self-signed TLS certificate and
// private key, valid from the current time for 1 year.
func generateSelfSignedCert(
	certFile string,
	keyFile string,
) (tls.Certificate, error) {
	// Generate a private key
	priv, err := rsa.GenerateKey(cryprand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	certTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"DisConcierge"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(
		cryprand.Reader,
		&certTemplate,
		&certTemplate,
		&priv.PublicKey,
		priv,
	)
	if err != nil {
		return tls.Certificate{}, err
	}

	certOut, err := os.Create(certFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	defer func() {
		_ = certOut.Close()
	}()

	if err = pem.Encode(
		certOut,
		&pem.Block{Type: "CERTIFICATE", Bytes: derBytes},
	); err != nil {
		return tls.Certificate{}, err
	}

	keyOut, err := os.Create(keyFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	defer func() {
		_ = keyOut.Close()
	}()

	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	if err = pem.Encode(
		keyOut,
		&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes},
	); err != nil {
		return tls.Certificate{}, err
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return tls.Certificate{}, err
	}

	return cert, nil
}

// getFileSystem returns an HTTP file system for serving static files.
//
// This function retrieves the embedded file system from the `reactUI` variable,
// which contains the static files for the React UI. If there is an error
// accessing the embedded file system, it logs the error and returns nil.
//
// Returns:
//   - http.FileSystem: The file system for serving static files, or nil if an error occurs.
func getFileSystem() http.FileSystem {
	fsys, err := fs.Sub(reactUI, "static")
	if err != nil {
		panic(err)
	}
	return SPAFileSystem{fs: http.FS(fsys)}
}

// overwriteDiscordCommands handles the HTTP POST request to overwrite Discord commands.
//
// This function overwrites the existing commands with the new set of commands
// provided in the request payload. It interacts with the Discord API to update
// the commands and sends a response indicating the success or failure of the operation.
//
// Parameters:
//   - c: The Gin context for the request.
//
// Responses:
//   - 200 OK: If the commands were successfully overwritten.
//   - 500 Internal Server Error: If there was an error overwriting the commands.
func validatePatchUser(field reflect.Value) any {
	if value, ok := field.Interface().(apiPatchUser); ok {
		if value.AssistantPollInterval != nil {
			pollDuration := *value.AssistantPollInterval
			if pollDuration.Duration < 100*time.Millisecond {
				return fmt.Errorf("poll interval must be at least 100ms")
			}
			if pollDuration.Duration > 60*time.Second {
				return fmt.Errorf("poll interval must be at most 60s")
			}
		}

		if value.AssistantMaxPollInterval != nil {
			maxDuration := *value.AssistantMaxPollInterval
			if maxDuration.Duration < 100*time.Millisecond {
				return fmt.Errorf("max poll interval must be at least 100ms")
			}
		}

		if value.AssistantMaxPollInterval != nil && value.AssistantPollInterval != nil {
			assistantPollInterval := *value.AssistantPollInterval
			maxInterval := *value.AssistantMaxPollInterval
			if maxInterval.Duration < assistantPollInterval.Duration {
				return "assistant_max_poll_interval must be >= assistant_poll_interval"
			}
		}
	}
	return nil
}

//nolint:gochecknoinits // gotta register the validators
func init() {
	structValidator.SetTagName("binding")
	structValidator.RegisterCustomTypeFunc(validateQueueConfig, QueueConfig{})
	structValidator.RegisterCustomTypeFunc(
		validateRuntimeUpdateLimits,
		RuntimeConfigUpdate{},
	)
	structValidator.RegisterCustomTypeFunc(
		validateOpenAIRunSettings,
		OpenAIRunSettings{},
	)
	structValidator.RegisterCustomTypeFunc(
		validatePatchUser,
		apiPatchUser{},
	)
}

// overwriteDiscordCommands handles the HTTP POST request to overwrite Discord commands.
//
// This function overwrites the existing commands with the new set of commands
// provided in the request payload. It interacts with the Discord API to update
// the commands and sends a response indicating the success or failure of the operation.
//
// Parameters:
//   - c: The Gin context for the request.
//
// Responses:
//   - 200 OK: If the commands were successfully overwritten.
//   - 500 Internal Server Error: If there was an error overwriting the commands.
func sendStartupMessage(d *Discord, logger *slog.Logger, config RuntimeConfig) {
	if !config.DiscordGatewayEnabled {
		return
	}
	if config.DiscordNotificationChannelID == "" {
		return
	}

	if sendErr := d.channelMessageSend(
		config.DiscordNotificationChannelID,
		d.config.StartupMessage,
	); sendErr != nil {
		logger.Error("error sending startup message", tint.Err(sendErr))
	}
}

// overwriteDiscordCommands handles the HTTP POST request to overwrite Discord commands.
//
// This function overwrites the existing commands with the new set of commands
// provided in the request payload. It interacts with the Discord API to update
// the commands and sends a response indicating the success or failure of the operation.
//
// Parameters:
//   - c: The Gin context for the request.
//
// Responses:
//   - 200 OK: If the commands were successfully overwritten.
//   - 500 Internal Server Error: If there was an error overwriting the commands.
func overwriteDiscordCommands(
	d *Discord,
	logger *slog.Logger,
	oldState RuntimeConfig,
	currentState RuntimeConfig,
) error {
	if currentState.ChatCommandMaxLength != oldState.ChatCommandMaxLength ||
		currentState.ChatCommandDescription != oldState.ChatCommandDescription ||
		currentState.ChatCommandOptionDescription != oldState.ChatCommandOptionDescription ||
		currentState.PrivateCommandDescription != oldState.PrivateCommandDescription {
		logger.Info("app command fields changed, overwriting")
		registered, registerErr := d.registerCommands(currentState)
		if registerErr != nil {
			logger.Error(
				"error registering commands",
				tint.Err(registerErr),
			)
		} else {
			logger.Info("registered commands", "commands", registered)
		}
		return registerErr
	}
	return nil
}

// ChatCommandDetail represents the detailed view of an ChatCommand including
// related OpenAI API calls
type ChatCommandDetail struct {
	ChatCommand   ChatCommand          `json:"chat_command"`
	CreateThread  *OpenAICreateThread  `json:"create_thread,omitempty"`
	CreateMessage *OpenAICreateMessage `json:"create_message,omitempty"`
	ListMessages  []OpenAIListMessages `json:"list_messages,omitempty"`
	CreateRun     *OpenAICreateRun     `json:"create_run,omitempty"`
	RetrieveRuns  []OpenAIRetrieveRun  `json:"retrieve_runs,omitempty"`
	ListRunSteps  []OpenAIListRunSteps `json:"list_run_steps,omitempty"`
}

// getChatCommandDetail handles the HTTP GET request to retrieve the details
// of a specific chat command.
//
// This function fetches the detailed information of a chat command,
// including related OpenAI API calls, and sends this information as
// a JSON response.
//
// Parameters:
//   - c: The Gin context for the request.
//
// Responses:
//   - 200 OK: Returns the detailed information of the chat command.
//   - 404 Not Found: If the chat command does not exist.
//   - 500 Internal Server Error: If there is an error retrieving the chat command details.
func (h *APIHandlers) getChatCommandDetail(c *gin.Context) {
	logger := ginContextLogger(c)
	id := c.Param("id")
	chatCommandID, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		logger.Error("invalid chat command id", tint.Err(err))
		c.JSON(
			http.StatusBadRequest,
			httpError{Error: "invalid chat command id"},
		)
		return
	}
	logger = logger.With(slog.Group("chat_command", "id", id))
	logger.Info("retrieving chat_command")
	if id == "" {
		c.JSON(http.StatusBadRequest, httpError{Error: "missing id parameter"})
		return
	}

	var chatCommand ChatCommand
	if err = h.d.db.Preload("User").Take(
		&chatCommand,
		"id = ?", chatCommandID,
	).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, httpError{Error: "chat command not found"})
		} else {
			c.JSON(http.StatusInternalServerError, httpError{Error: "error fetching chat command"})
		}
		return
	}

	detail := ChatCommandDetail{ChatCommand: chatCommand}

	// TODO technically, a ChatCommand can have multiple OpenAI API calls
	//   to CreateThread, CreateMessage and CreateRun. Update the model here
	//   accordingly.
	wg := sync.WaitGroup{}

	wg.Add(1)
	go func() {
		defer wg.Done()
		h.d.db.Where("chat_command_id = ?", chatCommand.ID).Take(&detail.CreateThread)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		h.d.db.Where("chat_command_id = ?", chatCommand.ID).Take(&detail.CreateMessage)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		h.d.db.Where("chat_command_id = ?", chatCommand.ID).Find(&detail.ListMessages)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		h.d.db.Where("chat_command_id = ?", chatCommand.ID).Take(&detail.CreateRun)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		h.d.db.Where("chat_command_id = ?", chatCommand.ID).Find(&detail.RetrieveRuns)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		h.d.db.Where("chat_command_id = ?", chatCommand.ID).Find(&detail.ListRunSteps)
	}()

	wg.Wait()
	c.JSON(http.StatusOK, detail)
}

// getDiscordMessages handles the HTTP GET request to retrieve a list of Discord messages.
//
// This function supports pagination and filtering by user ID, enqueue date, and end date.
// The results can be sorted in ascending or descending order based on the creation date.
//
// Parameters:
//   - c: The Gin context for the request.
//
// Responses:
//   - 200 OK: Returns a list of Discord messages.
//   - 400 Bad Request: If the query parameters are invalid.
//   - 500 Internal Server Error: If there is an error retrieving the Discord messages.
func (h *APIHandlers) getDiscordMessages(c *gin.Context) {
	var pagination Pagination
	if err := c.ShouldBindQuery(&pagination); err != nil {
		c.JSON(http.StatusBadRequest, httpError{Error: "invalid pagination"})
		return
	}

	if pagination.Order == "" {
		pagination.Order = Ascending
	}
	if pagination.Limit == 0 {
		pagination.Limit = 25
	}

	log := ginContextLogger(c)

	var messages []DiscordMessage
	query := h.d.db.Model(&DiscordMessage{})

	var err error
	switch pagination.Order {
	case Descending:
		err = query.Limit(pagination.Limit).Offset(
			pagination.Offset,
		).Order("id desc").Find(&messages).Error
	default:
		err = query.Limit(pagination.Limit).Offset(
			pagination.Offset,
		).Order("id asc").Find(&messages).Error
	}

	if err != nil {
		log.ErrorContext(
			c,
			"error getting discord messages",
			tint.Err(err),
		)
		c.JSON(
			http.StatusInternalServerError,
			httpError{Error: "error getting discord messages"},
		)
		return
	}

	c.JSON(http.StatusOK, messages)
}

// SPAFileSystem is a custom file system for serving the bot's React frontend
//
// This struct wraps an existing http.FileSystem and provides custom behavior
// for serving files, particularly useful for SPAs where the server needs to
// handle client-side routing.
//
// Fields:
//   - fs: The underlying http.FileSystem that this SPAFileSystem wraps.
type SPAFileSystem struct {
	fs http.FileSystem
}

func (s SPAFileSystem) Open(name string) (http.File, error) {
	f, err := s.fs.Open(name)
	if os.IsNotExist(err) {
		return s.fs.Open("index.html")
	}
	return f, err
}

// GetOpenAIRetrieveRunLogsQuery represents the query parameters for fetching
// OpenAIRetrieveRun records.
type GetOpenAIRetrieveRunLogsQuery struct {
	Pagination
	ChatCommandID *uint `form:"chat_command_id"`
}

// getOpenAIRetrieveRunLogs handles the HTTP GET request to retrieve OpenAIRetrieveRun logs.
//
// This function supports pagination and filtering by chat_command_id. It validates
// the query parameters, retrieves the logs from the database, and returns
// them as a JSON response.
//
// Parameters:
//   - c: The Gin context for the request.
//
// Responses:
//   - 200 OK: Returns the list of OpenAIRetrieveRun logs.
//   - 400 Bad Request: If the query parameters are invalid.
//   - 500 Internal Server Error: If there is an error retrieving the logs.
func (h *APIHandlers) getOpenAIRetrieveRunLogs(c *gin.Context) {
	var query GetOpenAIRetrieveRunLogsQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		c.JSON(http.StatusBadRequest, httpError{Error: "invalid query parameters"})
		return
	}

	if query.Order == "" {
		query.Order = Descending
	}
	if query.Limit == 0 {
		query.Limit = 25
	}

	log := ginContextLogger(c)

	db := h.d.db.Model(&OpenAIRetrieveRun{})

	if query.ChatCommandID != nil {
		db = db.Where("chat_command_id = ?", query.ChatCommandID)
	}

	var totalCount int64
	if err := db.Count(&totalCount).Error; err != nil {
		log.ErrorContext(c, "error counting OpenAIRetrieveRun logs", tint.Err(err))
		c.JSON(http.StatusInternalServerError, httpError{Error: "error retrieving logs"})
		return
	}

	var logs []OpenAIRetrieveRun

	switch query.Order {
	case Descending:
		db = db.Order("created_at DESC")
	default:
		db = db.Order("created_at ASC")
	}

	if err := db.Limit(query.Limit).Offset(query.Offset).Find(&logs).Error; err != nil {
		log.ErrorContext(c, "error retrieving OpenAIRetrieveRun logs", tint.Err(err))
		c.JSON(http.StatusInternalServerError, httpError{Error: "error retrieving logs"})
		return
	}

	c.JSON(
		http.StatusOK, gin.H{
			"total":  totalCount,
			"offset": query.Offset,
			"limit":  query.Limit,
			"logs":   logs,
		},
	)
}

// GetOpenAICreateThreadLogsQuery represents the query parameters for fetching
// OpenAICreateThread records.
type GetOpenAICreateThreadLogsQuery struct {
	Pagination
	ChatCommandID *uint `form:"chat_command_id"`
}

// getOpenAICreateThreadLogs handles the HTTP GET request to retrieve OpenAICreateThread logs.
//
// This function supports pagination and filtering by chat_command_id.
// It validates the query parameters, retrieves the logs from the database,
// and returns them as a JSON response.
//
// Parameters:
//   - c: The Gin context for the request.
//
// Responses:
//   - 200 OK: Returns the list of OpenAICreateThread logs.
//   - 400 Bad Request: If the query parameters are invalid.
//   - 500 Internal Server Error: If there is an error retrieving the logs.
func (h *APIHandlers) getOpenAICreateThreadLogs(c *gin.Context) {
	var query GetOpenAICreateThreadLogsQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		c.JSON(http.StatusBadRequest, httpError{Error: "invalid query parameters"})
		return
	}

	if query.Order == "" {
		query.Order = Descending
	}
	if query.Limit == 0 {
		query.Limit = 25
	}

	log := ginContextLogger(c)

	db := h.d.db.Model(&OpenAICreateThread{})

	if query.ChatCommandID != nil {
		db = db.Where("chat_command_id = ?", query.ChatCommandID)
	}

	var totalCount int64
	if err := db.Count(&totalCount).Error; err != nil {
		log.ErrorContext(c, "error counting OpenAICreateThread logs", tint.Err(err))
		c.JSON(http.StatusInternalServerError, httpError{Error: "error retrieving logs"})
		return
	}

	var logs []OpenAICreateThread

	switch query.Order {
	case Descending:
		db = db.Order("created_at DESC")
	default:
		db = db.Order("created_at ASC")
	}

	if err := db.Limit(query.Limit).Offset(query.Offset).Find(&logs).Error; err != nil {
		log.ErrorContext(c, "error retrieving OpenAICreateThread logs", tint.Err(err))
		c.JSON(http.StatusInternalServerError, httpError{Error: "error retrieving logs"})
		return
	}

	c.JSON(
		http.StatusOK, gin.H{
			"total":  totalCount,
			"offset": query.Offset,
			"limit":  query.Limit,
			"logs":   logs,
		},
	)
}

// GetOpenAICreateMessageLogsQuery represents the query parameters for fetching
// OpenAICreateMessage records.
type GetOpenAICreateMessageLogsQuery struct {
	Pagination
	ChatCommandID *uint `form:"chat_command_id"`
}

// getOpenAICreateMessageLogs handles the HTTP GET request to retrieve OpenAICreateMessage logs.
//
// This function supports pagination and filtering by chat_command_id.
// It validates the query parameters, retrieves the logs from the database,
// and returns them as a JSON response.
//
// Parameters:
//   - c: The Gin context for the request.
//
// Responses:
//   - 200 OK: Returns the list of OpenAICreateMessage logs.
//   - 400 Bad Request: If the query parameters are invalid.
//   - 500 Internal Server Error: If there is an error retrieving the logs.
func (h *APIHandlers) getOpenAICreateMessageLogs(c *gin.Context) {
	var query GetOpenAICreateMessageLogsQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		c.JSON(http.StatusBadRequest, httpError{Error: "invalid query parameters"})
		return
	}

	if query.Order == "" {
		query.Order = Descending
	}
	if query.Limit == 0 {
		query.Limit = 25
	}

	log := ginContextLogger(c)

	db := h.d.db.Model(&OpenAICreateMessage{})

	if query.ChatCommandID != nil {
		db = db.Where("chat_command_id = ?", query.ChatCommandID)
	}

	var totalCount int64
	if err := db.Count(&totalCount).Error; err != nil {
		log.ErrorContext(c, "error counting OpenAICreateMessage logs", tint.Err(err))
		c.JSON(http.StatusInternalServerError, httpError{Error: "error retrieving logs"})
		return
	}

	var logs []OpenAICreateMessage

	switch query.Order {
	case Descending:
		db = db.Order("created_at DESC")
	default:
		db = db.Order("created_at ASC")
	}

	if err := db.Limit(query.Limit).Offset(query.Offset).Find(&logs).Error; err != nil {
		log.ErrorContext(c, "error retrieving OpenAICreateMessage logs", tint.Err(err))
		c.JSON(http.StatusInternalServerError, httpError{Error: "error retrieving logs"})
		return
	}

	c.JSON(
		http.StatusOK, gin.H{
			"total":  totalCount,
			"offset": query.Offset,
			"limit":  query.Limit,
			"logs":   logs,
		},
	)
}

// GetOpenAICreateRunLogsQuery represents the query parameters for fetching OpenAICreateRun records.
type GetOpenAICreateRunLogsQuery struct {
	Pagination
	ChatCommandID *uint `form:"chat_command_id"`
}

// getOpenAICreateRunLogs handles the HTTP GET request to retrieve OpenAICreateRun logs.
//
// This function supports pagination and filtering by chat_command_id. It validates the
// query parameters, retrieves the logs from the database, and returns them as a JSON response.
//
// Parameters:
//   - c: The Gin context for the request.
//
// Responses:
//   - 200 OK: Returns the list of OpenAICreateRun logs.
//   - 400 Bad Request: If the query parameters are invalid.
//   - 500 Internal Server Error: If there is an error retrieving the logs.
func (h *APIHandlers) getOpenAICreateRunLogs(c *gin.Context) {
	var query GetOpenAICreateRunLogsQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		c.JSON(http.StatusBadRequest, httpError{Error: "invalid query parameters"})
		return
	}

	if query.Order == "" {
		query.Order = Descending
	}
	if query.Limit == 0 {
		query.Limit = 25
	}

	log := ginContextLogger(c)

	db := h.d.db.Model(&OpenAICreateRun{})

	if query.ChatCommandID != nil {
		db = db.Where("chat_command_id = ?", query.ChatCommandID)
	}

	var totalCount int64
	if err := db.Count(&totalCount).Error; err != nil {
		log.ErrorContext(c, "error counting OpenAICreateRun logs", tint.Err(err))
		c.JSON(http.StatusInternalServerError, httpError{Error: "error retrieving logs"})
		return
	}

	var logs []OpenAICreateRun

	switch query.Order {
	case Descending:
		db = db.Order("created_at DESC")
	default:
		db = db.Order("created_at ASC")
	}

	if err := db.Limit(query.Limit).Offset(query.Offset).Find(&logs).Error; err != nil {
		log.ErrorContext(c, "error retrieving OpenAICreateRun logs", tint.Err(err))
		c.JSON(http.StatusInternalServerError, httpError{Error: "error retrieving logs"})
		return
	}

	c.JSON(
		http.StatusOK, gin.H{
			"total":  totalCount,
			"offset": query.Offset,
			"limit":  query.Limit,
			"logs":   logs,
		},
	)
}

// GetOpenAIListMessagesLogsQuery represents the query parameters for fetching
// OpenAIListMessages records.
type GetOpenAIListMessagesLogsQuery struct {
	Pagination
	ChatCommandID *uint `form:"chat_command_id"`
}

// getOpenAIListMessagesLogs handles the HTTP GET request to retrieve OpenAIListMessages logs.
//
// This function supports pagination and filtering by chat_command_id.
// It validates the query parameters, retrieves the logs from the database,
// and returns them as a JSON response.
//
// Parameters:
//   - c: The Gin context for the request.
//
// Responses:
//   - 200 OK: Returns the list of OpenAIListMessages logs.
//   - 400 Bad Request: If the query parameters are invalid.
//   - 500 Internal Server Error: If there is an error retrieving the logs.
func (h *APIHandlers) getOpenAIListMessagesLogs(c *gin.Context) {
	var query GetOpenAIListMessagesLogsQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		c.JSON(http.StatusBadRequest, httpError{Error: "invalid query parameters"})
		return
	}

	if query.Order == "" {
		query.Order = Descending
	}
	if query.Limit == 0 {
		query.Limit = 25
	}

	log := ginContextLogger(c)

	db := h.d.db.Model(&OpenAIListMessages{})

	if query.ChatCommandID != nil {
		db = db.Where("chat_command_id = ?", query.ChatCommandID)
	}

	var totalCount int64
	if err := db.Count(&totalCount).Error; err != nil {
		log.ErrorContext(c, "error counting OpenAIListMessages logs", tint.Err(err))
		c.JSON(http.StatusInternalServerError, httpError{Error: "error retrieving logs"})
		return
	}

	var logs []OpenAIListMessages

	switch query.Order {
	case Descending:
		db = db.Order("created_at DESC")
	default:
		db = db.Order("created_at ASC")
	}

	if err := db.Limit(query.Limit).Offset(query.Offset).Find(&logs).Error; err != nil {
		log.ErrorContext(c, "error retrieving OpenAIListMessages logs", tint.Err(err))
		c.JSON(http.StatusInternalServerError, httpError{Error: "error retrieving logs"})
		return
	}

	c.JSON(
		http.StatusOK, gin.H{
			"total":  totalCount,
			"offset": query.Offset,
			"limit":  query.Limit,
			"logs":   logs,
		},
	)
}

// GetOpenAIListRunStepsLogsQuery represents the query parameters for fetching
// OpenAIListRunSteps records.
type GetOpenAIListRunStepsLogsQuery struct {
	Pagination
	ChatCommandID *uint `form:"chat_command_id"`
}

// getOpenAIListRunStepsLogs handles the HTTP GET request to retrieve OpenAIListRunSteps logs.
//
// This function supports pagination and filtering by chat_command_id.
// It validates the query parameters, retrieves the logs from the database,
// and returns them as a JSON response.
//
// Parameters:
//   - c: The Gin context for the request.
//
// Responses:
//   - 200 OK: Returns the list of OpenAIListRunSteps logs.
//   - 400 Bad Request: If the query parameters are invalid.
//   - 500 Internal Server Error: If there is an error retrieving the logs.
func (h *APIHandlers) getOpenAIListRunStepsLogs(c *gin.Context) {
	var query GetOpenAIListRunStepsLogsQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		c.JSON(http.StatusBadRequest, httpError{Error: "invalid query parameters"})
		return
	}

	if query.Order == "" {
		query.Order = Descending
	}
	if query.Limit == 0 {
		query.Limit = 25
	}

	log := ginContextLogger(c)

	db := h.d.db.Model(&OpenAIListRunSteps{})

	if query.ChatCommandID != nil {
		db = db.Where("chat_command_id = ?", query.ChatCommandID)
	}

	var totalCount int64
	if err := db.Count(&totalCount).Error; err != nil {
		log.ErrorContext(c, "error counting OpenAIListRunSteps logs", tint.Err(err))
		c.JSON(http.StatusInternalServerError, httpError{Error: "error retrieving logs"})
		return
	}

	var logs []OpenAIListRunSteps

	switch query.Order {
	case Descending:
		db = db.Order("created_at DESC")
	default:
		db = db.Order("created_at ASC")
	}

	if err := db.Limit(query.Limit).Offset(query.Offset).Find(&logs).Error; err != nil {
		log.ErrorContext(c, "error retrieving OpenAIListRunSteps logs", tint.Err(err))
		c.JSON(http.StatusInternalServerError, httpError{Error: "error retrieving logs"})
		return
	}

	c.JSON(
		http.StatusOK, gin.H{
			"total":  totalCount,
			"offset": query.Offset,
			"limit":  query.Limit,
			"logs":   logs,
		},
	)
}

// GetUserFeedbackQuery represents the query parameters for fetching UserFeedback records.
type GetUserFeedbackQuery struct {
	Pagination
	ChatCommandID *uint   `form:"chat_command_id"`
	UserID        *string `form:"user_id"`
}

// getUserFeedback handles the HTTP GET request to retrieve UserFeedback records.
//
// This function supports pagination and filtering by chat_command_id and user_id.
// It validates the query parameters, retrieves the feedback from the database,
// and returns them as a JSON response.
//
// Parameters:
//   - c: The Gin context for the request.
//
// Responses:
//   - 200 OK: Returns the list of UserFeedback records.
//   - 400 Bad Request: If the query parameters are invalid.
//   - 500 Internal Server Error: If there is an error retrieving the feedback.
func (h *APIHandlers) getUserFeedback(c *gin.Context) {
	var query GetUserFeedbackQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		c.JSON(http.StatusBadRequest, httpError{Error: "invalid query parameters"})
		return
	}

	if query.Order == "" {
		query.Order = Descending
	}
	if query.Limit == 0 {
		query.Limit = 25
	}

	log := ginContextLogger(c)

	db := h.d.db.Model(&UserFeedback{})

	if query.ChatCommandID != nil {
		db = db.Where("chat_command_id = ?", query.ChatCommandID)
	}
	if query.UserID != nil {
		db = db.Where("user_id = ?", query.UserID)
	}

	var totalCount int64
	if err := db.Count(&totalCount).Error; err != nil {
		log.ErrorContext(c, "error counting UserFeedback records", tint.Err(err))
		c.JSON(http.StatusInternalServerError, httpError{Error: "error retrieving feedback"})
		return
	}

	var feedback []UserFeedback

	switch query.Order {
	case Descending:
		db = db.Order("created_at DESC")
	default:
		db = db.Order("created_at ASC")
	}

	if err := db.Limit(query.Limit).Offset(query.Offset).Find(&feedback).Error; err != nil {
		log.ErrorContext(c, "error retrieving UserFeedback records", tint.Err(err))
		c.JSON(http.StatusInternalServerError, httpError{Error: "error retrieving feedback"})
		return
	}

	c.JSON(
		http.StatusOK, gin.H{
			"total":    totalCount,
			"offset":   query.Offset,
			"limit":    query.Limit,
			"feedback": feedback,
		},
	)
}

func (h *APIHandlers) getDiscordGatewayBot(c *gin.Context) {
	gb, err := h.d.discord.session.GatewayBot(
		discordgo.WithRetryOnRatelimit(false),
		discordgo.WithRestRetries(1),
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, httpError{Error: "error fetching gateway bot"})
		return
	}
	c.JSON(http.StatusOK, gb)
}

func updateDiscordBotStatus(
	d *DisConcierge,
	logger *slog.Logger,
	rollbackConfig RuntimeConfig,
	existingConfig *RuntimeConfig,
) {
	switch {
	case rollbackConfig.DiscordGatewayEnabled && !existingConfig.DiscordGatewayEnabled:
		if discErr := d.discord.session.Close(); discErr != nil {
			logger.Error("error closing discord connection", tint.Err(discErr))
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
					logger.Error("error updating discord status", tint.Err(discErr))
				}
			}
		case existingConfig.DiscordCustomStatus != rollbackConfig.DiscordCustomStatus:
			if discErr := d.discord.session.UpdateCustomStatus(
				existingConfig.DiscordCustomStatus,
			); discErr != nil {
				logger.Error("error updating discord status", tint.Err(discErr))
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
			logger.Error("error opening discord connection", tint.Err(discErr))
		}
	}
}
