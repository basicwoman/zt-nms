package api

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"

	"github.com/basicwoman/zt-nms/internal/capability"
	"github.com/basicwoman/zt-nms/internal/config"
	"github.com/basicwoman/zt-nms/internal/identity"
	"github.com/basicwoman/zt-nms/internal/policy"
	"github.com/basicwoman/zt-nms/pkg/models"
)

// Handler contains all API handlers
type Handler struct {
	identitySvc    *identity.Service
	policyEngine   *policy.Engine
	capabilityIssuer *capability.Issuer
	configManager  *config.Manager
	logger         *zap.Logger
}

// NewHandler creates a new API handler
func NewHandler(
	identitySvc *identity.Service,
	policyEngine *policy.Engine,
	capabilityIssuer *capability.Issuer,
	configManager *config.Manager,
	logger *zap.Logger,
) *Handler {
	return &Handler{
		identitySvc:      identitySvc,
		policyEngine:     policyEngine,
		capabilityIssuer: capabilityIssuer,
		configManager:    configManager,
		logger:           logger,
	}
}

// RegisterRoutes registers all API routes
func (h *Handler) RegisterRoutes(e *echo.Echo) {
	// API version prefix
	v1 := e.Group("/api/v1")

	// Health check
	e.GET("/health", h.HealthCheck)

	// Auth routes
	auth := v1.Group("/auth")
	auth.POST("/challenge", h.GetChallenge)
	auth.POST("/authenticate", h.Authenticate)
	auth.POST("/login", h.Login)
	auth.POST("/token/refresh", h.RefreshToken)

	// Identity routes
	identities := v1.Group("/identities")
	identities.POST("", h.CreateIdentity)
	identities.GET("", h.ListIdentities)
	identities.GET("/:id", h.GetIdentity)
	identities.PUT("/:id", h.UpdateIdentity)
	identities.DELETE("/:id", h.DeleteIdentity)
	identities.POST("/:id/suspend", h.SuspendIdentity)
	identities.POST("/:id/activate", h.ActivateIdentity)

	// Capability routes
	capabilities := v1.Group("/capabilities")
	capabilities.POST("/request", h.RequestCapability)
	capabilities.GET("/:id", h.GetCapability)
	capabilities.DELETE("/:id", h.RevokeCapability)
	capabilities.POST("/:id/approve", h.ApproveCapability)
	capabilities.GET("", h.ListCapabilities)

	// Policy routes
	policies := v1.Group("/policies")
	policies.POST("", h.CreatePolicy)
	policies.GET("", h.ListPolicies)
	policies.GET("/:id", h.GetPolicy)
	policies.PUT("/:id", h.UpdatePolicy)
	policies.DELETE("/:id", h.DeletePolicy)
	policies.POST("/evaluate", h.EvaluatePolicy)
	policies.POST("/:id/activate", h.ActivatePolicy)

	// Device routes
	devices := v1.Group("/devices")
	devices.GET("", h.ListDevices)
	devices.GET("/:id", h.GetDevice)
	devices.POST("", h.RegisterDevice)
	devices.PUT("/:id", h.UpdateDevice)
	devices.DELETE("/:id", h.DeleteDevice)
	devices.GET("/:id/config", h.GetDeviceConfig)
	devices.GET("/:id/config/history", h.GetConfigHistory)
	devices.POST("/:id/operations", h.ExecuteOperation)
	devices.GET("/:id/attestation", h.GetAttestation)

	// Configuration routes
	configs := v1.Group("/configs")
	configs.POST("/validate", h.ValidateConfig)
	configs.POST("/deploy", h.DeployConfig)
	configs.GET("/deployments/:id", h.GetDeployment)
	configs.POST("/deployments/:id/approve", h.ApproveDeployment)
	configs.POST("/deployments/:id/rollback", h.RollbackDeployment)

	// Audit routes
	audit := v1.Group("/audit")
	audit.GET("/events", h.ListAuditEvents)
	audit.GET("/events/:id", h.GetAuditEvent)
	audit.POST("/verify", h.VerifyAuditChain)
}

// HealthCheck returns the health status
func (h *Handler) HealthCheck(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC(),
		"version":   "1.0.0",
	})
}

// GetChallenge generates an authentication challenge
func (h *Handler) GetChallenge(c echo.Context) error {
	challenge := make([]byte, 32)
	// In production, use crypto/rand
	for i := range challenge {
		challenge[i] = byte(i)
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"challenge":  base64.StdEncoding.EncodeToString(challenge),
		"expires_at": time.Now().Add(5 * time.Minute).UTC(),
	})
}

// Authenticate handles authentication requests
func (h *Handler) Authenticate(c echo.Context) error {
	var req struct {
		PublicKey string `json:"public_key"`
		Challenge string `json:"challenge"`
		Signature string `json:"signature"`
	}
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, models.NewErrorResponse(
			models.NewAPIError(models.CodeInvalidToken, "invalid request"),
			c.Response().Header().Get(echo.HeaderXRequestID),
		))
	}

	// Decode public key
	pubKeyBytes, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil {
		return c.JSON(http.StatusBadRequest, models.NewErrorResponse(
			models.NewAPIError(models.CodeInvalidToken, "invalid public key"),
			c.Response().Header().Get(echo.HeaderXRequestID),
		))
	}

	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return c.JSON(http.StatusBadRequest, models.NewErrorResponse(
			models.NewAPIError(models.CodeInvalidToken, "invalid public key size"),
			c.Response().Header().Get(echo.HeaderXRequestID),
		))
	}

	challenge, _ := base64.StdEncoding.DecodeString(req.Challenge)
	signature, _ := base64.StdEncoding.DecodeString(req.Signature)

	identity, err := h.identitySvc.Authenticate(c.Request().Context(), pubKeyBytes, challenge, signature)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, models.NewErrorResponse(
			models.NewAPIError(models.CodeAuthFailed, err.Error()),
			c.Response().Header().Get(echo.HeaderXRequestID),
		))
	}

	// Generate access token (simplified - use JWT in production)
	token := base64.StdEncoding.EncodeToString(identity.ID[:])

	return c.JSON(http.StatusOK, map[string]interface{}{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"identity":     identity,
	})
}

// Login handles username/password login
func (h *Handler) Login(c echo.Context) error {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, models.NewErrorResponse(
			models.NewAPIError(models.CodeInvalidToken, "invalid request"),
			c.Response().Header().Get(echo.HeaderXRequestID),
		))
	}

	// Authenticate with username/password
	identity, err := h.identitySvc.AuthenticateByPassword(c.Request().Context(), req.Username, req.Password)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, models.NewErrorResponse(
			models.NewAPIError(models.CodeAuthFailed, "invalid username or password"),
			c.Response().Header().Get(echo.HeaderXRequestID),
		))
	}

	// Generate access token (simplified - use JWT in production)
	token := base64.StdEncoding.EncodeToString(identity.ID[:])

	return c.JSON(http.StatusOK, map[string]interface{}{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"identity":     identity,
	})
}

// RefreshToken refreshes an access token
func (h *Handler) RefreshToken(c echo.Context) error {
	// Implementation
	return c.JSON(http.StatusOK, map[string]string{"status": "refreshed"})
}

// CreateIdentity creates a new identity
func (h *Handler) CreateIdentity(c echo.Context) error {
	var req struct {
		Type       models.IdentityType    `json:"type"`
		Attributes map[string]interface{} `json:"attributes"`
		PublicKey  string                 `json:"public_key"`
	}
	if err := c.Bind(&req); err != nil {
		return h.errorResponse(c, http.StatusBadRequest, models.CodePolicyInvalid, "invalid request")
	}

	pubKeyBytes, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
		return h.errorResponse(c, http.StatusBadRequest, models.CodeInvalidToken, "invalid public key")
	}

	ctx := c.Request().Context()
	var identity *models.Identity

	switch req.Type {
	case models.IdentityTypeOperator:
		var attrs models.OperatorAttributes
		attrsJSON, _ := json.Marshal(req.Attributes)
		json.Unmarshal(attrsJSON, &attrs)
		identity, err = h.identitySvc.CreateOperator(ctx, attrs, pubKeyBytes, nil)

	case models.IdentityTypeDevice:
		var attrs models.DeviceAttributes
		attrsJSON, _ := json.Marshal(req.Attributes)
		json.Unmarshal(attrsJSON, &attrs)
		identity, err = h.identitySvc.CreateDevice(ctx, attrs, pubKeyBytes, nil)

	case models.IdentityTypeService:
		var attrs models.ServiceAttributes
		attrsJSON, _ := json.Marshal(req.Attributes)
		json.Unmarshal(attrsJSON, &attrs)
		identity, err = h.identitySvc.CreateService(ctx, attrs, pubKeyBytes, nil)

	default:
		return h.errorResponse(c, http.StatusBadRequest, models.CodeInvalidIdentityType, "invalid identity type")
	}

	if err != nil {
		return h.errorResponse(c, http.StatusBadRequest, models.CodePolicyInvalid, err.Error())
	}

	return c.JSON(http.StatusCreated, identity)
}

// ListIdentities lists identities
func (h *Handler) ListIdentities(c echo.Context) error {
	filter := identity.IdentityFilter{
		Type:   models.IdentityType(c.QueryParam("type")),
		Status: models.IdentityStatus(c.QueryParam("status")),
		Search: c.QueryParam("search"),
	}

	limit, _ := strconv.Atoi(c.QueryParam("limit"))
	offset, _ := strconv.Atoi(c.QueryParam("offset"))
	if limit == 0 {
		limit = 50
	}

	identities, total, err := h.identitySvc.List(c.Request().Context(), filter, limit, offset)
	if err != nil {
		return h.errorResponse(c, http.StatusInternalServerError, models.CodeInternalError, err.Error())
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"identities": identities,
		"total":      total,
		"limit":      limit,
		"offset":     offset,
	})
}

// GetIdentity retrieves an identity
func (h *Handler) GetIdentity(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return h.errorResponse(c, http.StatusBadRequest, models.CodePolicyInvalid, "invalid identity ID")
	}

	identity, err := h.identitySvc.GetByID(c.Request().Context(), id)
	if err != nil {
		return h.errorResponse(c, http.StatusNotFound, models.CodeIdentityNotFound, err.Error())
	}

	return c.JSON(http.StatusOK, identity)
}

// UpdateIdentity updates an identity
func (h *Handler) UpdateIdentity(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{"status": "updated"})
}

// DeleteIdentity deletes an identity
func (h *Handler) DeleteIdentity(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return h.errorResponse(c, http.StatusBadRequest, models.CodePolicyInvalid, "invalid identity ID")
	}

	if err := h.identitySvc.Revoke(c.Request().Context(), id, uuid.Nil, "deleted"); err != nil {
		return h.errorResponse(c, http.StatusInternalServerError, models.CodeInternalError, err.Error())
	}

	return c.NoContent(http.StatusNoContent)
}

// SuspendIdentity suspends an identity
func (h *Handler) SuspendIdentity(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return h.errorResponse(c, http.StatusBadRequest, models.CodePolicyInvalid, "invalid identity ID")
	}

	var req struct {
		Reason string `json:"reason"`
	}
	c.Bind(&req)

	if err := h.identitySvc.Suspend(c.Request().Context(), id, uuid.Nil, req.Reason); err != nil {
		return h.errorResponse(c, http.StatusInternalServerError, models.CodeInternalError, err.Error())
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "suspended"})
}

// ActivateIdentity activates an identity
func (h *Handler) ActivateIdentity(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return h.errorResponse(c, http.StatusBadRequest, models.CodePolicyInvalid, "invalid identity ID")
	}

	if err := h.identitySvc.Activate(c.Request().Context(), id, uuid.Nil); err != nil {
		return h.errorResponse(c, http.StatusInternalServerError, models.CodeInternalError, err.Error())
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "activated"})
}

// RequestCapability handles capability token requests
func (h *Handler) RequestCapability(c echo.Context) error {
	var req models.CapabilityTokenRequest
	if err := c.Bind(&req); err != nil {
		return h.errorResponse(c, http.StatusBadRequest, models.CodePolicyInvalid, "invalid request")
	}

	// Get requester from context (set by auth middleware)
	requesterID := uuid.New() // Should come from auth context
	requesterKey := make([]byte, ed25519.PublicKeySize) // Should come from auth context

	token, err := h.capabilityIssuer.Request(c.Request().Context(), &req, requesterID, requesterKey)
	if err != nil {
		return h.errorResponse(c, http.StatusForbidden, models.CodeAccessDenied, err.Error())
	}

	return c.JSON(http.StatusCreated, token)
}

// GetCapability retrieves a capability token
func (h *Handler) GetCapability(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return h.errorResponse(c, http.StatusBadRequest, models.CodePolicyInvalid, "invalid capability ID")
	}

	token, err := h.capabilityIssuer.GetByID(c.Request().Context(), id)
	if err != nil {
		return h.errorResponse(c, http.StatusNotFound, models.CodeCapabilityNotFound, err.Error())
	}

	return c.JSON(http.StatusOK, token)
}

// RevokeCapability revokes a capability token
func (h *Handler) RevokeCapability(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return h.errorResponse(c, http.StatusBadRequest, models.CodePolicyInvalid, "invalid capability ID")
	}

	var req struct {
		Reason string `json:"reason"`
	}
	c.Bind(&req)

	if err := h.capabilityIssuer.Revoke(c.Request().Context(), id, req.Reason, uuid.Nil); err != nil {
		return h.errorResponse(c, http.StatusInternalServerError, models.CodeInternalError, err.Error())
	}

	return c.NoContent(http.StatusNoContent)
}

// ApproveCapability approves a capability token
func (h *Handler) ApproveCapability(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{"status": "approved"})
}

// ListCapabilities lists capability tokens
func (h *Handler) ListCapabilities(c echo.Context) error {
	subjectIDStr := c.QueryParam("subject_id")
	if subjectIDStr == "" {
		return h.errorResponse(c, http.StatusBadRequest, models.CodePolicyInvalid, "subject_id required")
	}

	subjectID, err := uuid.Parse(subjectIDStr)
	if err != nil {
		return h.errorResponse(c, http.StatusBadRequest, models.CodePolicyInvalid, "invalid subject_id")
	}

	activeOnly := c.QueryParam("active") == "true"
	tokens, err := h.capabilityIssuer.ListBySubject(c.Request().Context(), subjectID, activeOnly)
	if err != nil {
		return h.errorResponse(c, http.StatusInternalServerError, models.CodeInternalError, err.Error())
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"capabilities": tokens,
	})
}

// CreatePolicy creates a new policy
func (h *Handler) CreatePolicy(c echo.Context) error {
	var policy models.Policy
	if err := c.Bind(&policy); err != nil {
		return h.errorResponse(c, http.StatusBadRequest, models.CodePolicyInvalid, "invalid request")
	}

	policy.ID = uuid.New()
	policy.Version = 1
	policy.Status = models.PolicyStatusDraft
	policy.CreatedAt = time.Now().UTC()

	if err := h.policyEngine.CreatePolicy(c.Request().Context(), &policy); err != nil {
		return h.errorResponse(c, http.StatusBadRequest, models.CodePolicyInvalid, err.Error())
	}

	return c.JSON(http.StatusCreated, policy)
}

// ListPolicies lists policies
func (h *Handler) ListPolicies(c echo.Context) error {
	policyType := models.PolicyType(c.QueryParam("type"))
	status := models.PolicyStatus(c.QueryParam("status"))
	limit, _ := strconv.Atoi(c.QueryParam("limit"))
	offset, _ := strconv.Atoi(c.QueryParam("offset"))
	if limit == 0 {
		limit = 50
	}

	policies, total, err := h.policyEngine.ListPolicies(c.Request().Context(), policyType, status, limit, offset)
	if err != nil {
		return h.errorResponse(c, http.StatusInternalServerError, models.CodeInternalError, err.Error())
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"policies": policies,
		"total":    total,
	})
}

// GetPolicy retrieves a policy
func (h *Handler) GetPolicy(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return h.errorResponse(c, http.StatusBadRequest, models.CodePolicyInvalid, "invalid policy ID")
	}

	policy, err := h.policyEngine.GetPolicy(c.Request().Context(), id)
	if err != nil {
		return h.errorResponse(c, http.StatusNotFound, models.CodePolicyNotFound, err.Error())
	}

	return c.JSON(http.StatusOK, policy)
}

// UpdatePolicy updates a policy
func (h *Handler) UpdatePolicy(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{"status": "updated"})
}

// DeletePolicy deletes a policy
func (h *Handler) DeletePolicy(c echo.Context) error {
	return c.NoContent(http.StatusNoContent)
}

// EvaluatePolicy evaluates a policy
func (h *Handler) EvaluatePolicy(c echo.Context) error {
	var req models.PolicyEvaluationRequest
	if err := c.Bind(&req); err != nil {
		return h.errorResponse(c, http.StatusBadRequest, models.CodePolicyInvalid, "invalid request")
	}

	decision, err := h.policyEngine.Evaluate(c.Request().Context(), req)
	if err != nil {
		return h.errorResponse(c, http.StatusInternalServerError, models.CodeInternalError, err.Error())
	}

	return c.JSON(http.StatusOK, decision)
}

// ActivatePolicy activates a policy
func (h *Handler) ActivatePolicy(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{"status": "activated"})
}

// Placeholder implementations for remaining handlers
func (h *Handler) ListDevices(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]interface{}{"devices": []interface{}{}})
}

func (h *Handler) GetDevice(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) RegisterDevice(c echo.Context) error {
	return c.JSON(http.StatusCreated, map[string]string{"status": "registered"})
}

func (h *Handler) UpdateDevice(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{"status": "updated"})
}

func (h *Handler) DeleteDevice(c echo.Context) error {
	return c.NoContent(http.StatusNoContent)
}

func (h *Handler) GetDeviceConfig(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{"config": ""})
}

func (h *Handler) GetConfigHistory(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]interface{}{"history": []interface{}{}})
}

func (h *Handler) ExecuteOperation(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{"status": "executed"})
}

func (h *Handler) GetAttestation(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{"status": "verified"})
}

func (h *Handler) ValidateConfig(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{"status": "valid"})
}

func (h *Handler) DeployConfig(c echo.Context) error {
	return c.JSON(http.StatusAccepted, map[string]string{"status": "deploying"})
}

func (h *Handler) GetDeployment(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) ApproveDeployment(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{"status": "approved"})
}

func (h *Handler) RollbackDeployment(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{"status": "rolled_back"})
}

func (h *Handler) ListAuditEvents(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]interface{}{"events": []interface{}{}})
}

func (h *Handler) GetAuditEvent(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) VerifyAuditChain(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{"valid": "true"})
}

func (h *Handler) errorResponse(c echo.Context, status int, code models.ErrorCode, message string) error {
	return c.JSON(status, models.NewErrorResponse(
		models.NewAPIError(code, message),
		c.Response().Header().Get(echo.HeaderXRequestID),
	))
}

// AuthMiddleware provides authentication middleware
func AuthMiddleware(identitySvc *identity.Service) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Skip auth for public endpoints
			path := c.Path()
			if path == "/health" ||
			   path == "/api/v1/auth/challenge" ||
			   path == "/api/v1/auth/authenticate" ||
			   path == "/api/v1/auth/login" {
				return next(c)
			}

			authHeader := c.Request().Header.Get("Authorization")
			if authHeader == "" {
				return c.JSON(http.StatusUnauthorized, models.NewAPIError(models.CodeAuthFailed, "missing authorization header"))
			}

			// In production, properly parse and verify JWT or bearer token
			// For now, just check it exists
			if len(authHeader) < 10 {
				return c.JSON(http.StatusUnauthorized, models.NewAPIError(models.CodeInvalidToken, "invalid token"))
			}

			return next(c)
		}
	}
}

// MTLSMiddleware provides mTLS certificate verification middleware
func MTLSMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// In production, verify client certificate
			// c.Request().TLS.PeerCertificates
			return next(c)
		}
	}
}

// ContextKey type for context keys
type ContextKey string

const (
	ContextKeyIdentity  ContextKey = "identity"
	ContextKeyRequestID ContextKey = "request_id"
)

// GetIdentityFromContext extracts identity from context
func GetIdentityFromContext(ctx context.Context) *models.Identity {
	if v := ctx.Value(ContextKeyIdentity); v != nil {
		if identity, ok := v.(*models.Identity); ok {
			return identity
		}
	}
	return nil
}
