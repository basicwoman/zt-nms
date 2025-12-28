package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/basicwoman/zt-nms/pkg/models"
)

// Service provides identity management operations
type Service struct {
	repo       Repository
	caPrivKey  ed25519.PrivateKey
	caPubKey   ed25519.PublicKey
	caCert     *x509.Certificate
	logger     *zap.Logger
	auditLog   AuditLogger
}

// AuditLogger interface for audit logging
type AuditLogger interface {
	LogIdentityEvent(ctx context.Context, eventType models.AuditEventType, identity *models.Identity, actor *uuid.UUID, result models.AuditResult, details map[string]interface{}) error
}

// ServiceConfig contains configuration for the identity service
type ServiceConfig struct {
	CAPrivateKeyPEM []byte
	CACertPEM       []byte
}

// NewService creates a new identity service
func NewService(repo Repository, config *ServiceConfig, logger *zap.Logger, auditLog AuditLogger) (*Service, error) {
	s := &Service{
		repo:     repo,
		logger:   logger,
		auditLog: auditLog,
	}

	// Parse CA private key
	if config != nil && config.CAPrivateKeyPEM != nil {
		block, _ := pem.Decode(config.CAPrivateKeyPEM)
		if block != nil {
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err == nil {
				if edKey, ok := key.(ed25519.PrivateKey); ok {
					s.caPrivKey = edKey
					s.caPubKey = edKey.Public().(ed25519.PublicKey)
				}
			}
		}
	}

	// Parse CA certificate
	if config != nil && config.CACertPEM != nil {
		block, _ := pem.Decode(config.CACertPEM)
		if block != nil {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				s.caCert = cert
			}
		}
	}

	return s, nil
}

// CreateOperator creates a new operator identity
func (s *Service) CreateOperator(ctx context.Context, attrs models.OperatorAttributes, publicKey ed25519.PublicKey, createdBy *uuid.UUID) (*models.Identity, error) {
	if attrs.Username == "" {
		return nil, models.NewAPIError(models.CodePolicyInvalid, "username is required")
	}
	if attrs.Email == "" {
		return nil, models.NewAPIError(models.CodePolicyInvalid, "email is required")
	}

	existing, err := s.repo.GetByUsername(ctx, attrs.Username)
	if err == nil && existing != nil {
		return nil, models.ErrIdentityExists
	}

	identity := models.NewOperatorIdentity(attrs, publicKey, createdBy)

	if s.caPrivKey != nil && s.caCert != nil {
		cert, err := s.issueCertificate(identity, "operator")
		if err != nil {
			s.logger.Error("Failed to issue certificate", zap.Error(err))
		} else {
			identity.Certificate = cert
		}
	}

	if err := s.repo.Create(ctx, identity); err != nil {
		return nil, err
	}

	if s.auditLog != nil {
		s.auditLog.LogIdentityEvent(ctx, models.AuditEventIdentityCreate, identity, createdBy, models.AuditResultSuccess, map[string]interface{}{
			"username": attrs.Username,
			"email":    attrs.Email,
			"groups":   attrs.Groups,
		})
	}

	s.logger.Info("Created operator identity", zap.String("id", identity.ID.String()), zap.String("username", attrs.Username))
	return identity, nil
}

// CreateDevice creates a new device identity
func (s *Service) CreateDevice(ctx context.Context, attrs models.DeviceAttributes, publicKey ed25519.PublicKey, createdBy *uuid.UUID) (*models.Identity, error) {
	if attrs.Hostname == "" {
		return nil, models.NewAPIError(models.CodePolicyInvalid, "hostname is required")
	}
	if attrs.ManagementIP == "" {
		return nil, models.NewAPIError(models.CodePolicyInvalid, "management_ip is required")
	}

	identity := models.NewDeviceIdentity(attrs, publicKey, createdBy)

	if s.caPrivKey != nil && s.caCert != nil {
		cert, err := s.issueCertificate(identity, "device")
		if err != nil {
			s.logger.Error("Failed to issue certificate", zap.Error(err))
		} else {
			identity.Certificate = cert
		}
	}

	if err := s.repo.Create(ctx, identity); err != nil {
		return nil, err
	}

	if s.auditLog != nil {
		s.auditLog.LogIdentityEvent(ctx, models.AuditEventIdentityCreate, identity, createdBy, models.AuditResultSuccess, map[string]interface{}{
			"hostname":      attrs.Hostname,
			"vendor":        attrs.Vendor,
			"management_ip": attrs.ManagementIP,
		})
	}

	s.logger.Info("Created device identity", zap.String("id", identity.ID.String()), zap.String("hostname", attrs.Hostname))
	return identity, nil
}

// CreateService creates a new service identity
func (s *Service) CreateService(ctx context.Context, attrs models.ServiceAttributes, publicKey ed25519.PublicKey, createdBy *uuid.UUID) (*models.Identity, error) {
	if attrs.Name == "" {
		return nil, models.NewAPIError(models.CodePolicyInvalid, "name is required")
	}

	identity := models.NewServiceIdentity(attrs, publicKey, createdBy)

	if s.caPrivKey != nil && s.caCert != nil {
		cert, err := s.issueCertificate(identity, "service")
		if err != nil {
			s.logger.Error("Failed to issue certificate", zap.Error(err))
		} else {
			identity.Certificate = cert
		}
	}

	if err := s.repo.Create(ctx, identity); err != nil {
		return nil, err
	}

	if s.auditLog != nil {
		s.auditLog.LogIdentityEvent(ctx, models.AuditEventIdentityCreate, identity, createdBy, models.AuditResultSuccess, map[string]interface{}{
			"name":    attrs.Name,
			"owner":   attrs.Owner,
			"purpose": attrs.Purpose,
		})
	}

	s.logger.Info("Created service identity", zap.String("id", identity.ID.String()), zap.String("name", attrs.Name))
	return identity, nil
}

// GetByID retrieves an identity by ID
func (s *Service) GetByID(ctx context.Context, id uuid.UUID) (*models.Identity, error) {
	return s.repo.GetByID(ctx, id)
}

// GetByPublicKey retrieves an identity by public key
func (s *Service) GetByPublicKey(ctx context.Context, publicKey ed25519.PublicKey) (*models.Identity, error) {
	return s.repo.GetByPublicKey(ctx, publicKey)
}

// Authenticate authenticates an identity using signature verification
func (s *Service) Authenticate(ctx context.Context, publicKey ed25519.PublicKey, challenge, signature []byte) (*models.Identity, error) {
	identity, err := s.repo.GetByPublicKey(ctx, publicKey)
	if err != nil {
		if s.auditLog != nil {
			s.auditLog.LogIdentityEvent(ctx, models.AuditEventIdentityAuthFailed, nil, nil, models.AuditResultFailure, map[string]interface{}{
				"reason": "identity_not_found",
			})
		}
		return nil, models.ErrAuthenticationFailed
	}

	if identity.Status != models.IdentityStatusActive {
		if s.auditLog != nil {
			s.auditLog.LogIdentityEvent(ctx, models.AuditEventIdentityAuthFailed, identity, nil, models.AuditResultFailure, map[string]interface{}{
				"reason": "identity_not_active",
				"status": identity.Status,
			})
		}
		switch identity.Status {
		case models.IdentityStatusSuspended:
			return nil, models.ErrIdentitySuspended
		case models.IdentityStatusRevoked:
			return nil, models.ErrIdentityRevoked
		default:
			return nil, models.ErrAuthenticationFailed
		}
	}

	if !ed25519.Verify(identity.PublicKey, challenge, signature) {
		if s.auditLog != nil {
			s.auditLog.LogIdentityEvent(ctx, models.AuditEventIdentityAuthFailed, identity, nil, models.AuditResultFailure, map[string]interface{}{
				"reason": "invalid_signature",
			})
		}
		return nil, models.ErrAuthenticationFailed
	}

	if s.auditLog != nil {
		s.auditLog.LogIdentityEvent(ctx, models.AuditEventIdentityAuth, identity, &identity.ID, models.AuditResultSuccess, nil)
	}

	return identity, nil
}

// AuthenticateByPassword authenticates an operator using username/password
func (s *Service) AuthenticateByPassword(ctx context.Context, username, password string) (*models.Identity, error) {
	identity, err := s.repo.GetByUsername(ctx, username)
	if err != nil {
		if s.auditLog != nil {
			s.auditLog.LogIdentityEvent(ctx, models.AuditEventIdentityAuthFailed, nil, nil, models.AuditResultFailure, map[string]interface{}{
				"reason":   "user_not_found",
				"username": username,
			})
		}
		return nil, models.ErrAuthenticationFailed
	}

	if identity.Status != models.IdentityStatusActive {
		if s.auditLog != nil {
			s.auditLog.LogIdentityEvent(ctx, models.AuditEventIdentityAuthFailed, identity, nil, models.AuditResultFailure, map[string]interface{}{
				"reason": "identity_not_active",
				"status": identity.Status,
			})
		}
		return nil, models.ErrAuthenticationFailed
	}

	// Verify password
	if err := s.repo.VerifyPassword(ctx, identity.ID, password); err != nil {
		if s.auditLog != nil {
			s.auditLog.LogIdentityEvent(ctx, models.AuditEventIdentityAuthFailed, identity, nil, models.AuditResultFailure, map[string]interface{}{
				"reason": "invalid_password",
			})
		}
		return nil, models.ErrAuthenticationFailed
	}

	if s.auditLog != nil {
		s.auditLog.LogIdentityEvent(ctx, models.AuditEventIdentityAuth, identity, &identity.ID, models.AuditResultSuccess, map[string]interface{}{
			"method": "password",
		})
	}

	return identity, nil
}

// Suspend suspends an identity
func (s *Service) Suspend(ctx context.Context, id uuid.UUID, suspendedBy uuid.UUID, reason string) error {
	identity, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return err
	}

	if err := s.repo.UpdateStatus(ctx, id, models.IdentityStatusSuspended); err != nil {
		return err
	}

	if s.auditLog != nil {
		s.auditLog.LogIdentityEvent(ctx, models.AuditEventIdentityUpdate, identity, &suspendedBy, models.AuditResultSuccess, map[string]interface{}{
			"action": "suspend",
			"reason": reason,
		})
	}

	s.logger.Info("Suspended identity", zap.String("id", id.String()), zap.String("reason", reason))
	return nil
}

// Revoke revokes an identity
func (s *Service) Revoke(ctx context.Context, id uuid.UUID, revokedBy uuid.UUID, reason string) error {
	identity, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return err
	}

	if err := s.repo.UpdateStatus(ctx, id, models.IdentityStatusRevoked); err != nil {
		return err
	}

	if s.auditLog != nil {
		s.auditLog.LogIdentityEvent(ctx, models.AuditEventIdentityUpdate, identity, &revokedBy, models.AuditResultSuccess, map[string]interface{}{
			"action": "revoke",
			"reason": reason,
		})
	}

	s.logger.Info("Revoked identity", zap.String("id", id.String()), zap.String("reason", reason))
	return nil
}

// Activate activates a suspended identity
func (s *Service) Activate(ctx context.Context, id uuid.UUID, activatedBy uuid.UUID) error {
	identity, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return err
	}

	if identity.Status == models.IdentityStatusRevoked {
		return errors.New("cannot activate revoked identity")
	}

	if err := s.repo.UpdateStatus(ctx, id, models.IdentityStatusActive); err != nil {
		return err
	}

	if s.auditLog != nil {
		s.auditLog.LogIdentityEvent(ctx, models.AuditEventIdentityUpdate, identity, &activatedBy, models.AuditResultSuccess, map[string]interface{}{
			"action": "activate",
		})
	}

	s.logger.Info("Activated identity", zap.String("id", id.String()))
	return nil
}

// List lists identities with filtering
func (s *Service) List(ctx context.Context, filter IdentityFilter, limit, offset int) ([]*models.Identity, int, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	return s.repo.List(ctx, filter, limit, offset)
}

// issueCertificate issues a certificate for an identity
func (s *Service) issueCertificate(identity *models.Identity, certType string) ([]byte, error) {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	var commonName string
	switch identity.Type {
	case models.IdentityTypeOperator:
		attrs, _ := identity.GetOperatorAttributes()
		if attrs != nil {
			commonName = attrs.Username
		}
	case models.IdentityTypeDevice:
		attrs, _ := identity.GetDeviceAttributes()
		if attrs != nil {
			commonName = attrs.Hostname
		}
	case models.IdentityTypeService:
		attrs, _ := identity.GetServiceAttributes()
		if attrs != nil {
			commonName = attrs.Name
		}
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         commonName,
			Organization:       []string{"ZT-NMS"},
			OrganizationalUnit: []string{certType},
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, s.caCert, identity.PublicKey, s.caPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return certPEM, nil
}
