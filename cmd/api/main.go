package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/viper"
	"go.uber.org/zap"

	"github.com/basicwoman/zt-nms/internal/analytics"
	"github.com/basicwoman/zt-nms/internal/api"
	"github.com/basicwoman/zt-nms/internal/attestation"
	"github.com/basicwoman/zt-nms/internal/audit"
	"github.com/basicwoman/zt-nms/internal/capability"
	"github.com/basicwoman/zt-nms/internal/identity"
	"github.com/basicwoman/zt-nms/internal/inventory"
	"github.com/basicwoman/zt-nms/internal/policy"
	"github.com/basicwoman/zt-nms/pkg/models"
)

func main() {
	logger, _ := zap.NewProduction()
	defer logger.Sync()

	if err := loadConfig(); err != nil {
		logger.Fatal("Failed to load configuration", zap.Error(err))
	}

	dbPool, err := initDatabase(context.Background())
	if err != nil {
		logger.Fatal("Failed to connect to database", zap.Error(err))
	}
	defer dbPool.Close()

	identityRepo := identity.NewPostgresRepository(dbPool)
	identitySvc, _ := identity.NewService(identityRepo, nil, logger, nil)

	policyRepo := policy.NewPostgresRepository(dbPool)
	policyCache := policy.NewInMemoryCache()
	policyEngine := policy.NewEngine(policyRepo, policyCache, logger)

	// Load active policies into memory
	if err := policyEngine.LoadPolicies(context.Background()); err != nil {
		logger.Warn("Failed to load policies, starting with empty policy set", zap.Error(err))
	}

	capabilityIssuer, _ := capability.NewIssuer(nil, policyEngine, &capability.IssuerConfig{
		IssuerID: viper.GetString("issuer.id"),
	}, logger)

	handler := api.NewHandler(identitySvc, policyEngine, capabilityIssuer, nil, logger)

	// Initialize inventory service with identity integration
	inventoryRepo := inventory.NewPostgresRepository(dbPool)
	identityAdapter := inventory.NewIdentityServiceAdapter(identitySvc)
	inventorySvc := inventory.NewService(inventoryRepo, identityAdapter, nil, logger, nil)

	// Initialize audit service
	auditRepo := audit.NewPostgresRepository(dbPool)
	auditSvc, err := audit.NewService(auditRepo, nil, logger, nil)
	if err != nil {
		logger.Warn("Failed to initialize audit service", zap.Error(err))
	}

	// Initialize analytics engine with PostgreSQL data source
	analyticsDataSource := analytics.NewPostgresDataSource(dbPool)
	analyticsEngine := analytics.NewEngine(nil, analyticsDataSource, logger, nil)

	// Initialize attestation service with in-memory repository
	attestationRepo := attestation.NewInMemoryRepository()
	attestationIdentitySvc := &attestationIdentityAdapter{
		identitySvc:  identitySvc,
		inventorySvc: inventorySvc,
	}
	attestationSvc := attestation.NewVerifier(attestationRepo, attestationIdentitySvc, nil, nil, logger, &attestation.Config{
		NonceExpiry:         5 * time.Minute,
		QuarantineOnFailure: true,
		AlertOnFailure:      false,
	})

	// Initialize extended handler with all services
	extendedHandler := api.NewExtendedHandler(handler, inventorySvc, attestationSvc, auditSvc, analyticsEngine)

	e := echo.New()
	e.HideBanner = true

	e.Use(middleware.RequestID())
	e.Use(middleware.Recover())
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: viper.GetStringSlice("cors.allowed_origins"),
		AllowMethods: []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete},
		AllowHeaders: []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAuthorization},
	}))
	e.Use(middleware.RateLimiter(middleware.NewRateLimiterMemoryStore(100)))
	e.Use(api.AuthMiddleware(identitySvc))

	handler.RegisterRoutes(e)
	extendedHandler.RegisterExtendedRoutes(e)
	e.GET("/metrics", echo.WrapHandler(promhttp.Handler()))

	serverAddr := fmt.Sprintf(":%d", viper.GetInt("server.port"))
	go func() {
		logger.Info("Starting API Gateway", zap.String("address", serverAddr))
		if viper.GetBool("server.tls.enabled") {
			e.StartTLS(serverAddr, viper.GetString("server.tls.cert_file"), viper.GetString("server.tls.key_file"))
		} else {
			e.Start(serverAddr)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	e.Shutdown(ctx)
}

func loadConfig() error {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("/etc/zt-nms/")
	viper.AddConfigPath("./configs")
	viper.SetDefault("server.port", 8080)
	viper.SetDefault("database.host", "localhost")
	viper.SetDefault("database.port", 5432)
	viper.SetDefault("database.name", "ztnms")
	viper.SetDefault("database.sslmode", "disable")
	viper.SetDefault("issuer.id", "zt-nms-issuer")
	viper.SetDefault("server.tls.enabled", false)
	viper.SetDefault("cors.allowed_origins", []string{"*"})

	// Bind environment variables with proper keys
	viper.SetEnvPrefix("ZTNMS")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	// Read config file (optional, env vars take precedence)
	viper.ReadInConfig()

	return nil
}

func initDatabase(ctx context.Context) (*pgxpool.Pool, error) {
	sslmode := viper.GetString("database.sslmode")
	if sslmode == "" {
		sslmode = "disable"
	}
	connString := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		viper.GetString("database.user"),
		viper.GetString("database.password"),
		viper.GetString("database.host"),
		viper.GetInt("database.port"),
		viper.GetString("database.name"),
		sslmode,
	)
	config, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database config: %w", err)
	}
	config.MaxConns = 25
	return pgxpool.NewWithConfig(ctx, config)
}

// attestationIdentityAdapter adapts identity and inventory services for attestation
type attestationIdentityAdapter struct {
	identitySvc  *identity.Service
	inventorySvc *inventory.Service
}

func (a *attestationIdentityAdapter) GetByID(ctx context.Context, id uuid.UUID) (*models.Identity, error) {
	return a.identitySvc.GetByID(ctx, id)
}

func (a *attestationIdentityAdapter) UpdateTrustStatus(ctx context.Context, id uuid.UUID, status string) error {
	return a.inventorySvc.UpdateTrustStatus(ctx, id, inventory.TrustStatus(status))
}
