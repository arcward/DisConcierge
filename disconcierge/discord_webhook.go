package disconcierge

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/bwmarrin/discordgo"
	"github.com/gin-gonic/gin"
	"github.com/lmittmann/tint"
	"io"
	"log/slog"
	"net/http"
	"os"
)

type DiscordWebhookServer struct {
	config     DiscordWebhookServerConfig
	httpServer *http.Server
	engine     *gin.Engine
	logger     *slog.Logger
}

func (d *DiscordWebhookServer) Serve(_ context.Context) error {
	if d.httpServer.TLSConfig == nil {
		d.logger.Warn("starting server without TLS")
		return d.httpServer.ListenAndServe()
	}
	return d.httpServer.ListenAndServeTLS("", "")

}

// newWebhookServer creates and returns a new [DiscordWebhookServer], and/or
// any errors that occurred during creation.
func newWebhookServer(
	d *DisConcierge,
	config DiscordWebhookServerConfig,
) (*DiscordWebhookServer, error) {
	logger := slog.New(
		tint.NewHandler(
			os.Stdout, &tint.Options{
				Level:     config.LogLevel,
				AddSource: true,
			},
		),
	)

	r := gin.New()
	api := &DiscordWebhookServer{config: config, engine: r}

	httpServer := &http.Server{
		Addr:              config.Listen,
		Handler:           r,
		ReadTimeout:       config.ReadTimeout,
		ReadHeaderTimeout: config.ReadHeaderTimeout,
		WriteTimeout:      config.WriteTimeout,
	}
	if config.SSL != nil {
		tlsCfg, e := tlsConfig(config.SSL)
		if e != nil {
			return nil, fmt.Errorf("error loading webhook SSL certs: %w", e)
		}
		httpServer.TLSConfig = tlsCfg
	}
	api.httpServer = httpServer

	api.logger = logger.With(loggerNameKey, "discord_webhook")

	if d.config.Development {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
		r.Use(gin.Recovery())
	}
	r.Use(
		requestIDMiddleware(),
		ginLoggingMiddleware(),
		discordRequestAuthenticationMiddleware(d.discord.publicKey),
	)

	r.POST(
		apiDiscordInteractions,
		func(c *gin.Context) {
			d.webhookInteractionHandler(c)
		},
	)
	return api, nil
}

// WebhookHandler is a handler for Discord interactions received via webhook.
// See: https://discord.com/developers/docs/interactions/overview#setting-up-an-endpoint-validating-security-request-headers
//
//nolint:lll  // can't split link
type WebhookHandler struct {
	ginContext *gin.Context
	InteractionHandler
}

func (WebhookHandler) InteractionReceiveMethod() DiscordInteractionReceiveMethod {
	return discordInteractionReceiveMethodWebhook
}

func (w WebhookHandler) Respond(
	_ context.Context,
	response *discordgo.InteractionResponse,
	_ ...discordgo.RequestOption,
) error {
	w.ginContext.JSON(http.StatusOK, response)
	return nil
}

// webhookReceiveHandler returns a [gin.Handler] for handling Discord webhook
// interactions
func webhookReceiveHandler(ctx context.Context, d *DisConcierge) func(c *gin.Context) {
	return func(c *gin.Context) {
		requestID, _ := c.Get(xRequestIDHeader)
		logger := ginContextLogger(c).With(
			slog.Group(
				"webhook_request",
				"remote_addr", c.Request.RemoteAddr,
				"remote_ip", c.RemoteIP(),
				"path", c.Request.Method,
				xRequestIDHeader, requestID,
			),
		)

		runCtx := WithLogger(ctx, logger)

		defer func() {
			_ = c.Request.Body.Close()
		}()
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			logger.ErrorContext(runCtx, "error getting raw data", tint.Err(err))
			c.JSON(http.StatusInternalServerError, httpError{Error: "error getting raw data"})
			return
		}

		var interaction discordgo.InteractionCreate
		if e := json.Unmarshal(body, &interaction); e != nil {
			logger.ErrorContext(runCtx, "error unmarshalling body", tint.Err(err))
			c.JSON(http.StatusBadRequest, httpError{Error: "error unmarshalling body"})
			return
		}
		i := &interaction
		handler := WebhookHandler{
			ginContext:         c,
			InteractionHandler: d.getInteractionHandlerFunc(ctx, i),
		}
		d.handleInteraction(runCtx, handler)
	}
}

// discordRequestAuthenticationMiddleware is a middleware for verifying Discord
// webhook requests.
// See: https://discord.com/developers/docs/interactions/overview#setting-up-an-endpoint-validating-security-request-headers
//
//nolint:lll // can't split link
func discordRequestAuthenticationMiddleware(publicKey ed25519.PublicKey) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger := ginContextLogger(c)
		if !verifyRequest(c.Request, publicKey) {
			logger.WarnContext(c, "invalid signature")
			c.JSON(http.StatusUnauthorized, httpError{Error: "invalid signature"})
			return
		}
		c.Next()
	}
}

// verifyRequest verifies the authenticity of a Discord webhook request.
//
// This function checks the request's signature and timestamp headers to validate
// the request. It reads the request
// body and verifies the signature using the provided public key.
func verifyRequest(r *http.Request, key ed25519.PublicKey) bool {
	var msg bytes.Buffer

	signature := r.Header.Get("X-Signature-Ed25519")
	if signature == "" {
		return false
	}

	sig, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}

	if len(sig) != ed25519.SignatureSize || sig[63]&224 != 0 {
		return false
	}

	timestamp := r.Header.Get("X-Signature-Timestamp")
	if timestamp == "" {
		return false
	}

	msg.WriteString(timestamp)

	defer func() {
		_ = r.Body.Close()
	}()
	var body bytes.Buffer

	defer func() {
		r.Body = io.NopCloser(&body)
	}()

	_, err = io.Copy(&msg, io.TeeReader(r.Body, &body))
	if err != nil {
		return false
	}

	return ed25519.Verify(key, msg.Bytes(), sig)
}
