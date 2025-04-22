package service

import (
	"context"
	"fmt"
	"garde/internal/models"
	"garde/internal/repository"
	"garde/pkg/crypto"
	"garde/pkg/mfa"
	"garde/pkg/session"
	"math/rand"
	"os"
	"strings"
	"time"

	"garde/pkg/errors"
	"garde/pkg/mail"
	"garde/pkg/validation"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const (
	maxResetAttempts      = 5
	securityCodeKeyPrefix = "security_code"
)

type AuthService struct {
	repo             *repository.RedisRepository
	securityAnalyzer *SecurityAnalyzer
}

type ValidationResult struct {
	Response *models.SessionValidationResponse
	UserID   string
}

func NewAuthService(repo *repository.RedisRepository) *AuthService {
	return &AuthService{
		repo:             repo,
		securityAnalyzer: NewSecurityAnalyzer(repo),
	}
}

// Service returns regular errors
func (s *AuthService) Login(ctx context.Context, req *models.LoginRequest, ip, userAgent string) (*models.LoginResponse, error) {

	if os.Getenv("DISABLE_IP_BLACKLISTING") != "true" {
		// Check if IP is blocked
		isBlocked, err := s.repo.IsIPBlocked(ctx, ip)
		if err != nil {
			fmt.Printf("Failed to check IP block status: %v\n", err)
		}
		if isBlocked {
			return nil, fmt.Errorf(errors.ErrAccessRestricted)
		}
	}

	// Get user for security checks
	user, err := s.repo.GetUserByEmail(ctx, req.Email)
	if err != nil {
		return nil, fmt.Errorf(errors.ErrAuthFailed)
	}

	// Check for suspicious patterns including multiple IP sessions
	if os.Getenv("DISABLE_RAPID_REQUEST_CHECK") != "true" {
		patterns := s.securityAnalyzer.DetectSuspiciousPatterns(ctx, user.ID, ip, userAgent)
		if len(patterns) > 0 {
			// Record all detected patterns
			for _, pattern := range patterns {
				s.securityAnalyzer.RecordPattern(ctx, user.ID, pattern, ip, userAgent)
			}
			return nil, fmt.Errorf(errors.ErrAuthFailed)
		}
	}

	valid, err := crypto.VerifyPassword(req.Password, user.PasswordHash)
	if err != nil || !valid {
		// Record failed attempt
		failedAttempts, err := s.repo.RecordFailedLogin(ctx, req.Email, ip)
		if err != nil {
			fmt.Printf("Failed to record failed login: %v\n", err)
		}

		// Block if threshold exceeded
		if os.Getenv("DISABLE_IP_BLACKLISTING") != "true" && failedAttempts >= session.FailedLoginThreshold {
			s.repo.BlockIP(ctx, ip, session.FailedLoginBlockDuration)
			user.Status = models.UserStatusLockedBySecurity
			s.repo.StoreUser(ctx, user)
			return nil, fmt.Errorf(errors.ErrAccessRestricted)
		}
		return nil, fmt.Errorf(errors.ErrAuthFailed)
	}

	// Check MFA requirement
	if user.MFAEnabled || user.MFAEnforced {
		if req.MFACode == "" {
			return nil, fmt.Errorf(errors.ErrMFARequired)
		}
		if !mfa.ValidateCode(user.MFASecret, req.MFACode) {
			return nil, fmt.Errorf(errors.ErrInvalidMFACode)
		}
	}

	// Generate session
	sessionID, err := session.GenerateSessionID()
	if err != nil {
		return nil, fmt.Errorf(errors.ErrAuthFailed)
	}

	sessionData := &session.SessionData{
		UserID:    user.ID,
		IP:        session.HashString(ip),
		UserAgent: session.HashString(userAgent),
		CreatedAt: time.Now(),
	}

	if err := s.repo.StoreSessionData(ctx, sessionID, sessionData, session.SessionDuration); err != nil {
		return nil, fmt.Errorf(errors.ErrAuthFailed)
	}

	// Update last login time
	user.LastLogin = time.Now()
	if err := s.repo.StoreUser(ctx, user); err != nil {
		fmt.Printf("Failed to update last login time: %v\n", err)
	}

	return &models.LoginResponse{
		SessionID: sessionID,
	}, nil
}

func (s *AuthService) Logout(ctx context.Context, sessionID string) error {
	// Get user info before deleting session
	sessionData, err := s.repo.GetSessionData(ctx, sessionID)
	if err != nil {
		return fmt.Errorf(errors.ErrAuthFailed)
	}

	// Delete session
	err = s.repo.DeleteSession(ctx, sessionID)
	if err != nil {
		// If deletion fails, add to blacklist as fallback
		blacklistErr := s.repo.BlacklistSession(ctx, sessionID, session.BlacklistDuration)
		if blacklistErr != nil {
			return fmt.Errorf(errors.ErrAuthFailed)
		}
		// Log that we fell back to blacklisting
		fmt.Printf("Session deletion failed, added to blacklist: %v\n", err)
	}

	// Clean up all security records
	if err := s.securityAnalyzer.CleanupSecurityRecords(ctx, sessionData.UserID, "", ""); err != nil {
		// Log but don't fail the logout
		fmt.Printf("Failed to cleanup security records: %v\n", err)
	}

	return nil
}

func (s *AuthService) ValidateSession(ctx context.Context, sessionID, ip, userAgent string) (*ValidationResult, error) {
	// First check if session is blacklisted
	isBlacklisted, err := s.repo.IsSessionBlacklisted(ctx, sessionID)
	if err != nil {
		fmt.Printf("Error checking blacklist: %v\n", err)
		return &ValidationResult{
			Response: &models.SessionValidationResponse{
				Valid: false,
			},
		}, nil
	}

	if isBlacklisted {
		fmt.Printf("Session is blacklisted: %s (first 10 chars)\n", sessionID[:10])
		return &ValidationResult{
			Response: &models.SessionValidationResponse{
				Valid: false,
			},
		}, nil
	}

	// Get session data
	sessionData, err := s.repo.GetSessionData(ctx, sessionID)
	if err != nil {
		fmt.Printf("Error getting session data: %v\n", err)
		return &ValidationResult{
			Response: &models.SessionValidationResponse{
				Valid: false,
			},
		}, nil
	}

	fmt.Printf("Session found for user: %s\n", sessionData.UserID)

	// Use pattern detector for sophisticated validation
	patterns := s.securityAnalyzer.DetectSuspiciousPatterns(ctx, sessionData.UserID, ip, userAgent)
	if len(patterns) > 0 {
		// Record all detected patterns
		for _, pattern := range patterns {
			s.securityAnalyzer.RecordPattern(ctx, sessionData.UserID, pattern, ip, userAgent)
		}

		// Blacklist this specific session
		if err := s.repo.BlacklistSession(ctx, sessionID, session.BlacklistDuration); err != nil {
			fmt.Printf("Failed to blacklist suspicious session: %v\n", err)
		}

		// Then try to delete it
		if err := s.repo.DeleteSession(ctx, sessionID); err != nil {
			fmt.Printf("Failed to delete suspicious session: %v\n", err)
		}

		fmt.Printf("Suspicious patterns detected for session %s: %v\n", sessionID, patterns)
		return &ValidationResult{
			Response: &models.SessionValidationResponse{
				Valid: false,
			},
		}, nil
	}

	// Verify IP and user agent match
	if session.HashString(ip) != sessionData.IP || session.HashString(userAgent) != sessionData.UserAgent {
		return &ValidationResult{
			Response: &models.SessionValidationResponse{
				Valid: false,
			},
		}, nil
	}

	// Check session age
	if time.Since(sessionData.CreatedAt) > session.SessionDuration {
		fmt.Printf("Session %s has expired\n", sessionID)
		s.repo.DeleteSession(ctx, sessionID)
		return &ValidationResult{
			Response: &models.SessionValidationResponse{
				Valid: false,
			},
		}, nil
	}

	fmt.Printf("Session validation successful for user: %s\n", sessionData.UserID)

	return &ValidationResult{
		Response: &models.SessionValidationResponse{
			Valid: true,
		},
		UserID: sessionData.UserID,
	}, nil
}

func (s *AuthService) NeedsMFASetup(ctx context.Context, email string) (bool, error) {
	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		return false, err
	}

	return user.Status == models.UserStatusOk &&
		user.MFAEnforced &&
		!user.MFAEnabled, nil
}

// Update SetupMFA to work without session when needed
func (s *AuthService) SetupMFA(ctx context.Context, userIDOrEmail string) (*models.MFAResponse, error) {
	var user *models.User
	var err error

	// Try to get user by ID first (for authenticated requests)
	user, err = s.repo.GetUserByID(ctx, userIDOrEmail)
	if err != nil {
		// If not found by ID, try email (for unauthenticated requests)
		user, err = s.repo.GetUserByEmail(ctx, userIDOrEmail)
		if err != nil {
			return nil, fmt.Errorf(errors.ErrMFASetupFailed)
		}
	}

	// Block if MFA is already enabled and verified
	if user.MFAEnabled {
		return nil, fmt.Errorf(errors.ErrMFAAlreadyEnabled)
	}

	// Check if user is allowed to setup MFA without auth
	needsSetup, _ := s.NeedsMFASetup(ctx, user.Email)
	if !needsSetup {
		// If doesn't need setup, ensure request is authenticated
		if _, err := s.repo.GetUserByID(ctx, userIDOrEmail); err != nil {
			return nil, fmt.Errorf(errors.ErrUnauthorized)
		}
	}

	// Generate new secret
	key, err := mfa.GenerateSecret(user.Email)
	if err != nil {
		return nil, fmt.Errorf(errors.ErrMFASetupFailed)
	}

	// Store secret temporarily with TTL
	if err := s.repo.StoreTempMFASecret(ctx, user.ID, key.Secret); err != nil {
		return nil, fmt.Errorf(errors.ErrMFASetupFailed)
	}

	return &models.MFAResponse{
		QRCodeURL: key.URL, // Only return QR code, not raw secret
	}, nil
}

func (s *AuthService) VerifyAndEnableMFA(ctx context.Context, userID string, code string) error {
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf(errors.ErrMFAVerificationFailed)
	}

	// Get temporary secret
	tempSecret, err := s.repo.GetTempMFASecret(ctx, user.ID)
	if err != nil {
		return fmt.Errorf(errors.ErrMFAVerificationFailed)
	}

	// Verify code using temporary secret
	if !mfa.ValidateCode(tempSecret, code) {
		return fmt.Errorf(errors.ErrInvalidMFACode)
	}

	// If verification successful, save secret to user and enable MFA
	user.MFASecret = tempSecret
	user.MFAEnabled = true
	user.UpdatedAt = time.Now()

	// Save user first
	if err := s.repo.StoreUser(ctx, user); err != nil {
		return fmt.Errorf(errors.ErrMFAVerificationFailed)
	}

	// Then delete temp secret
	if err := s.repo.DeleteTempMFASecret(ctx, user.ID); err != nil {
		return fmt.Errorf(errors.ErrMFAVerificationFailed)
	}

	return nil
}

func (s *AuthService) CreateUser(ctx context.Context, req *models.CreateUserRequest) (*models.CreateUserResponse, error) {
	// Check if email already exists
	existingUser, err := s.repo.GetUserByEmail(ctx, req.Email)
	if err == nil && existingUser != nil {
		return nil, fmt.Errorf(errors.ErrEmailAlreadyExists)
	}

	// Password is required for new users
	if req.Password == "" {
		return nil, fmt.Errorf(errors.ErrInvalidRequest)
	}

	hashedPassword, err := crypto.HashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf(errors.ErrUserCreationFailed)
	}

	// Check if MFA is enforced globally
	mfaEnforced := os.Getenv("ENFORCE_MFA") == "true"

	// Check if this email is in ADMIN_USERS
	adminUsers := strings.Split(os.Getenv("ADMIN_USERS"), ",")
	isAdmin := false
	for _, adminEmail := range adminUsers {
		if strings.TrimSpace(adminEmail) == req.Email {
			isAdmin = true
			break
		}
	}

	user := &models.User{
		ID:           uuid.New().String(),
		Email:        req.Email,
		PasswordHash: hashedPassword,
		Status:       models.UserStatusPendingApproval,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		MFAEnforced:  mfaEnforced,
	}

	// If user is admin, set status to active and grant all permissions
	if isAdmin {
		user.Status = models.UserStatusOk
		user.Permissions = models.AdminPermissions()
	} else {
		user.Permissions = models.DefaultPermissions()
	}

	if err := s.repo.StoreUser(ctx, user); err != nil {
		return nil, fmt.Errorf(errors.ErrUserCreationFailed)
	}

	return &models.CreateUserResponse{
		UserID: user.ID,
	}, nil
}

func (s *AuthService) UpdateUser(ctx context.Context, adminID string, targetUserID string, req *models.UpdateUserRequest, isSuperUser bool, isAdmin bool) error {

	// Get admin user for group checks
	admin, err := s.repo.GetUserByID(ctx, adminID)
	if err != nil {
		fmt.Printf("Failed to get admin user by ID: %v\n", err)
		return fmt.Errorf(errors.ErrOperationFailed)
	}

	// Get the target user
	targetUser, err := s.repo.GetUserByID(ctx, targetUserID)
	if err != nil {
		fmt.Printf("Failed to get target user by ID: %v\n", err)
		return fmt.Errorf(errors.ErrUserNotFound)
	}

	// Only superuser can modify superuser
	if targetUser.Email == os.Getenv("SUPERUSER_EMAIL") && !isSuperUser {
		return fmt.Errorf(errors.ErrUnauthorized)
	}

	// Check if admin has permission to modify this user
	if !isSuperUser && !isAdmin {
		fmt.Printf("Unauthorized to update - User is neither superuser nor admin\n")
		return fmt.Errorf(errors.ErrUnauthorized)
	}

	// Check if groups system is loaded for admin operations
	// Superusers are exempt from group sharing checks
	if !isSuperUser && isAdmin {
		if !models.IsGroupsLoaded() {
			return fmt.Errorf(errors.ErrGroupsNotLoaded)
		}

		// If updating groups, check if admin is in the groups they're trying to add
		if req.Groups != nil {
			for group, enabled := range *req.Groups {
				if enabled && !admin.Groups[group] {
					fmt.Printf("Unauthorized to update - Admin not in group %s\n", group)
					return fmt.Errorf(errors.ErrUnauthorized)
				}
			}
		} else if !models.SharesAnyUserGroup(admin.Groups, targetUser.Groups) {
			fmt.Printf("Unauthorized to update - Admin doesn't share groups with target user\n")
			return fmt.Errorf(errors.ErrUnauthorized)
		}
	}

	// Track update attempt in audit log
	err = s.repo.RecordAuditLog(ctx, targetUserID, map[string]interface{}{
		"type":      "update_attempt",
		"admin_id":  adminID,
		"timestamp": time.Now(),
	}, 10, 30*24*time.Hour)
	if err != nil {
		fmt.Printf("Failed to record audit log: %v\n", err)
	}

	// Store original state for comparison
	originalStatus := targetUser.Status
	originalMFAEnforced := targetUser.MFAEnforced

	// **** IMPORTANT: Save original PendingUpdates to restore later if not approving/rejecting ****
	originalPendingUpdates := targetUser.PendingUpdates

	// Handle update request approval/rejection
	if targetUser.PendingUpdates != nil && (req.ApproveUpdate || req.RejectUpdate) {
		if req.ApproveUpdate {
			if targetUser.PendingUpdates.Fields.Permissions != nil {
				if !models.IsPermissionsLoaded() {
					return fmt.Errorf(errors.ErrPermissionsNotLoaded)
				}
				// Update permissions with the pending updates
				for perm, enabled := range *targetUser.PendingUpdates.Fields.Permissions {
					targetUser.Permissions[perm] = enabled
				}
			}
			if targetUser.PendingUpdates.Fields.Groups != nil {
				if !models.IsGroupsLoaded() {
					return fmt.Errorf(errors.ErrGroupsNotLoaded)
				}
				// Create a new map to store the merged groups
				mergedGroups := models.UserGroups{}

				// Copy all existing groups
				for group, enabled := range targetUser.Groups {
					mergedGroups[group] = enabled
				}

				// Add or update groups from pending updates
				for group, enabled := range *targetUser.PendingUpdates.Fields.Groups {
					mergedGroups[group] = enabled
				}

				targetUser.Groups = mergedGroups
			}

			// Update status to active if currently pending
			if targetUser.Status == models.UserStatusPendingApproval {
				targetUser.Status = models.UserStatusOk
			}
		}
		// Clear pending updates regardless of approve/reject
		targetUser.PendingUpdates = nil
	}

	// Update fields if provided
	if req.Status != nil {
		targetUser.Status = *req.Status

		// If status is changed to locked, blacklist and revoke all sessions
		if *req.Status == models.UserStatusLockedByAdmin ||
			*req.Status == models.UserStatusLockedBySecurity {

			// Get all active sessions
			sessions, err := s.repo.GetUserActiveSessions(ctx, targetUser.ID)
			if err != nil {
				return fmt.Errorf(errors.ErrOperationFailed)
			}

			// Blacklist and delete each session
			for _, sessionID := range sessions {
				if err := s.repo.BlacklistSession(ctx, sessionID, session.BlacklistDuration); err != nil {
					fmt.Printf("Failed to blacklist session %s: %v\n", sessionID, err)
				}
				if err := s.repo.DeleteSession(ctx, sessionID); err != nil {
					fmt.Printf("Failed to delete session %s: %v\n", sessionID, err)
				}
			}
		}
	}

	if req.MFAEnforced != nil {
		targetUser.MFAEnforced = *req.MFAEnforced
	}

	if req.Permissions != nil {
		if !models.IsPermissionsLoaded() {
			return fmt.Errorf(errors.ErrPermissionsNotLoaded)
		}
		// Validate permissions exist
		for perm := range *req.Permissions {
			if info := models.GetPermissionInfo(perm); info.Name != string(perm) {
				return fmt.Errorf(errors.ErrUnauthorized)
			}
		}
		targetUser.Permissions = *req.Permissions
	}

	// Add support for direct groups updates
	if req.Groups != nil {
		// Superusers are exempt from group validation
		if !isSuperUser {
			if !models.IsGroupsLoaded() {
				return fmt.Errorf(errors.ErrGroupsNotLoaded)
			}
			// Validate groups exist
			for group := range *req.Groups {
				if !models.IsValidUserGroup(group) {
					return fmt.Errorf(errors.ErrUnauthorized)
				}
			}
		}

		// Convert directly without type casting
		userGroups := models.UserGroups{}
		for group, enabled := range *req.Groups {
			userGroups[group] = enabled
		}

		// Update the groups
		targetUser.Groups = userGroups
	}

	// **** IMPORTANT: After all updates, restore PendingUpdates if not approving/rejecting ****
	if !req.ApproveUpdate && !req.RejectUpdate {
		targetUser.PendingUpdates = originalPendingUpdates
	}

	// Only update timestamp if changes were made
	if targetUser.Status != originalStatus ||
		targetUser.MFAEnforced != originalMFAEnforced ||
		req.Permissions != nil ||
		req.Groups != nil {
		targetUser.UpdatedAt = time.Now()
		if err := s.repo.StoreUser(ctx, targetUser); err != nil {
			return fmt.Errorf(errors.ErrOperationFailed)
		}

		// Record successful update in audit log
		s.repo.RecordAuditLog(ctx, targetUserID, map[string]interface{}{
			"type":      "update_success",
			"admin_id":  adminID,
			"timestamp": time.Now(),
		}, 10, 30*24*time.Hour)
	}

	return nil
}

// Initialize superuser during startup
func (s *AuthService) InitializeSuperUser(ctx context.Context) error {
	superuserEmail := os.Getenv("SUPERUSER_EMAIL")
	superuserPassword := os.Getenv("SUPERUSER_PASSWORD")

	// Hash the password once since we'll need it in multiple places
	hashedPassword, err := crypto.HashPassword(superuserPassword)
	if err != nil {
		return fmt.Errorf(errors.ErrSuperUserInitFailed)
	}

	// Check if MFA is enforced globally
	mfaEnforced := os.Getenv("ENFORCE_MFA") == "true"

	// Try to get user by the configured superuser email
	user, err := s.repo.GetUserByEmail(ctx, superuserEmail)
	if err == nil {
		// User exists with this email, update their password
		user.PasswordHash = hashedPassword
		user.MFAEnforced = mfaEnforced
		user.Status = models.UserStatusOk // Ensure superuser is active
		user.UpdatedAt = time.Now()
		if err := s.repo.StoreUser(ctx, user); err != nil {
			return fmt.Errorf(errors.ErrSuperUserInitFailed)
		}
		return nil
	}

	// If user doesn't exist, create new superuser
	newUser := &models.User{
		ID:           models.SuperUserID,
		Email:        superuserEmail,
		PasswordHash: hashedPassword,
		Status:       models.UserStatusOk, // Superuser starts active
		MFAEnforced:  mfaEnforced,         // Set based on environment variable
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := s.repo.StoreUser(ctx, newUser); err != nil {
		return fmt.Errorf(errors.ErrSuperUserInitFailed)
	}

	return nil
}

func (s *AuthService) RevokeUserSession(ctx context.Context, adminID string, targetUserID string, isSuperUser bool, isAdmin bool) error {

	// Get admin user for group checks
	admin, err := s.repo.GetUserByID(ctx, adminID)
	if err != nil {
		return fmt.Errorf(errors.ErrUnauthorized)
	}

	// Get target user
	targetUser, err := s.repo.GetUserByID(ctx, targetUserID)
	if err != nil {
		return fmt.Errorf(errors.ErrUserNotFound)
	}

	// Only superuser can revoke superuser's sessions
	if targetUser.Email == os.Getenv("SUPERUSER_EMAIL") && !isSuperUser {
		return fmt.Errorf(errors.ErrUnauthorized)
	}

	// Superusers can revoke any user's sessions
	if isSuperUser {
		// Get all active sessions using existing repository method
		sessions, err := s.repo.GetUserActiveSessions(ctx, targetUserID)
		if err != nil {
			return fmt.Errorf(errors.ErrOperationFailed)
		}

		for _, sessionID := range sessions {
			if err := s.repo.BlacklistSession(ctx, sessionID, session.BlacklistDuration); err != nil {
				fmt.Printf("Failed to blacklist session %s: %v\n", sessionID, err)
			}
			if err := s.repo.DeleteSession(ctx, sessionID); err != nil {
				fmt.Printf("Failed to delete session %s: %v\n", sessionID, err)
			}
		}
		return nil
	}

	// Admins can only revoke sessions for users who share their groups
	if isAdmin && models.SharesAnyUserGroup(admin.Groups, targetUser.Groups) {
		// Get all active sessions using existing repository method
		sessions, err := s.repo.GetUserActiveSessions(ctx, targetUserID)
		if err != nil {
			return fmt.Errorf(errors.ErrOperationFailed)
		}

		for _, sessionID := range sessions {
			if err := s.repo.BlacklistSession(ctx, sessionID, session.BlacklistDuration); err != nil {
				fmt.Printf("Failed to blacklist session %s: %v\n", sessionID, err)
			}
			if err := s.repo.DeleteSession(ctx, sessionID); err != nil {
				fmt.Printf("Failed to delete session %s: %v\n", sessionID, err)
			}
		}
		return nil
	}

	return fmt.Errorf(errors.ErrUnauthorized)
}

func (s *AuthService) ResetPassword(ctx context.Context, req *models.PasswordResetRequest) error {
	// Get user
	user, err := s.repo.GetUserByEmail(ctx, req.Email)
	if err != nil {
		return fmt.Errorf(errors.ErrUserNotFound)
	}

	// Don't allow reset for superuser
	if user.Email == os.Getenv("SUPERUSER_EMAIL") {
		return fmt.Errorf(errors.ErrUnauthorized)
	}

	// Check attempts
	attempts, err := s.repo.TrackResetAttempt(ctx, user.ID)
	if err != nil {
		return fmt.Errorf(errors.ErrOperationFailed)
	}
	if attempts > maxResetAttempts {
		// Lock user account
		user.Status = models.UserStatusLockedBySecurity
		if err := s.repo.StoreUser(ctx, user); err != nil {
			return fmt.Errorf(errors.ErrOperationFailed)
		}
		return fmt.Errorf(errors.ErrTooManyAttempts)
	}

	// Verify OTP first and delete it immediately after verification
	storedOTP, err := s.repo.GetOTP(ctx, user.ID)
	if err != nil {
		return fmt.Errorf(errors.ErrInvalidOTP)
	}

	// Delete OTP regardless of verification outcome
	defer s.repo.DeleteOTP(ctx, user.ID)

	if valid, err := crypto.VerifyPassword(req.OTP, storedOTP); err != nil || !valid {
		return fmt.Errorf(errors.ErrInvalidOTP)
	}

	// Check MFA if enabled
	if user.MFAEnabled {
		if req.MFACode == "" {
			return fmt.Errorf(errors.ErrMFARequired)
		}
		if !mfa.ValidateCode(user.MFASecret, req.MFACode) {
			return fmt.Errorf(errors.ErrInvalidMFACode)
		}
	}

	// Validate new password
	if err := validation.ValidatePassword(req.NewPassword); err != nil {
		return err
	}

	// All verifications passed, update password
	hashedPassword, err := crypto.HashPassword(req.NewPassword)
	if err != nil {
		return fmt.Errorf(errors.ErrOperationFailed)
	}

	// Update user
	user.PasswordHash = hashedPassword
	user.Status = models.UserStatusPendingApproval
	user.UpdatedAt = time.Now()

	if err := s.repo.StoreUser(ctx, user); err != nil {
		return fmt.Errorf(errors.ErrOperationFailed)
	}

	// Revoke all sessions after password change
	sessions, err := s.repo.GetUserActiveSessions(ctx, user.ID)
	if err != nil {
		fmt.Printf("Failed to get active sessions: %v\n", err)
		return nil // Continue with login despite session revocation failure
	}

	for _, sessionID := range sessions {
		if err := s.repo.DeleteSession(ctx, sessionID); err != nil {
			s.repo.BlacklistSession(ctx, sessionID, session.BlacklistDuration)
		}
	}

	return nil
}

func (s *AuthService) DisableMFA(ctx context.Context, userID string, code string) error {
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf(errors.ErrUserNotFound)
	}

	// Check if MFA is enforced
	if user.MFAEnforced {
		return fmt.Errorf(errors.ErrUnauthorized)
	}

	// Verify MFA code
	if !mfa.ValidateCode(user.MFASecret, code) {
		return fmt.Errorf(errors.ErrInvalidMFACode)
	}

	// Disable MFA
	user.MFAEnabled = false
	user.MFASecret = "" // Clear the secret
	user.UpdatedAt = time.Now()

	if err := s.repo.StoreUser(ctx, user); err != nil {
		return fmt.Errorf(errors.ErrOperationFailed)
	}

	return nil
}

func (s *AuthService) ChangePassword(ctx context.Context, userID string, req *models.ChangePasswordRequest) error {
	// Get user
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf(errors.ErrUserNotFound)
	}

	// Don't allow superuser password change through this endpoint
	if user.Email == os.Getenv("SUPERUSER_EMAIL") {
		return fmt.Errorf(errors.ErrUnauthorized)
	}

	// Verify old password
	valid, err := crypto.VerifyPassword(req.OldPassword, user.PasswordHash)
	if err != nil || !valid {
		return fmt.Errorf(errors.ErrInvalidCredentials)
	}

	// If user has MFA enabled, verify MFA code
	if user.MFAEnabled {
		if req.MFACode == "" {
			return fmt.Errorf(errors.ErrMFARequired)
		}
		if !mfa.ValidateCode(user.MFASecret, req.MFACode) {
			return fmt.Errorf(errors.ErrInvalidMFACode)
		}
	}

	// Hash and set new password
	hashedPassword, err := crypto.HashPassword(req.NewPassword)
	if err != nil {
		return fmt.Errorf(errors.ErrOperationFailed)
	}

	user.PasswordHash = hashedPassword
	user.UpdatedAt = time.Now()

	if err := s.repo.StoreUser(ctx, user); err != nil {
		return fmt.Errorf(errors.ErrOperationFailed)
	}

	// Extract the current session ID from context if available
	var currentSessionID string
	if gc, ok := ctx.(*gin.Context); ok {
		sessionCookie, err := gc.Cookie("session")
		if err == nil && sessionCookie != "" {
			currentSessionID = sessionCookie
		}

		// Check authorization header if cookie not found
		if currentSessionID == "" {
			authHeader := gc.GetHeader("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				currentSessionID = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		// Also check if stored in context
		if sessionID, exists := gc.Get("session_id"); exists && currentSessionID == "" {
			currentSessionID = fmt.Sprintf("%v", sessionID)
		}
	} else {
		// For non-gin contexts (like in tests), try to get session ID from context values
		if sessionID, ok := ctx.Value("session_id").(string); ok {
			currentSessionID = sessionID
		}
	}

	// Revoke all existing sessions except the current one to prevent connection crash
	sessions, err := s.repo.GetUserActiveSessions(ctx, user.ID)
	if err != nil {
		return fmt.Errorf(errors.ErrOperationFailed)
	}

	for _, sessionID := range sessions {
		// Skip the current session to prevent the connection from being terminated
		if sessionID == currentSessionID {
			fmt.Printf("Preserving current session: %s\n", sessionID[:10])
			continue
		}

		if err := s.repo.DeleteSession(ctx, sessionID); err != nil {
			s.repo.BlacklistSession(ctx, sessionID, session.BlacklistDuration)
		}
	}

	return nil
}

func (s *AuthService) SendOTP(ctx context.Context, email string) error {
	// Get user by email
	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		// Return success even if email doesn't exist (security through obscurity)
		return nil
	}

	// Don't allow OTP for superuser
	if user.Email == os.Getenv("SUPERUSER_EMAIL") {
		return nil
	}

	// Generate 5-letter OTP
	otp := make([]byte, 5)
	for i := range otp {
		otp[i] = byte('A' + rand.Intn(26))
	}
	otpStr := string(otp)

	// Hash OTP
	hashedOTP, err := crypto.HashPassword(otpStr)
	if err != nil {
		return fmt.Errorf(errors.ErrOperationFailed)
	}

	// Store hashed OTP with TTL
	if err := s.repo.StoreOTP(ctx, user.ID, hashedOTP); err != nil {
		return fmt.Errorf(errors.ErrOperationFailed)
	}

	// Send OTP via email
	msg := fmt.Sprintf("Your one-time password is: %s\nThis code will expire in 5 minutes.", otpStr)
	if err := mail.SendMail(user.Email, "Password Reset OTP", msg); err != nil {
		return fmt.Errorf(errors.ErrEmailSendFailed)
	}

	return nil
}

func (s *AuthService) GetSessionData(ctx context.Context, sessionID string) (*session.SessionData, error) {
	return s.repo.GetSessionData(ctx, sessionID)
}

func (s *AuthService) GetCurrentUser(ctx context.Context, userID string) (*models.UserResponse, error) {
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf(errors.ErrUserNotFound)
	}

	return &models.UserResponse{
		ID:          user.ID,
		Email:       user.Email,
		LastLogin:   user.LastLogin,
		CreatedAt:   user.CreatedAt,
		UpdatedAt:   user.UpdatedAt,
		MFAEnabled:  user.MFAEnabled,
		MFAEnforced: user.MFAEnforced,
		Status:      user.Status,
		Permissions: user.Permissions,
		Groups:      user.Groups,
	}, nil
}

func (s *AuthService) ListUsers(ctx context.Context, adminID string) ([]models.UserResponse, error) {
	// Check if user has admin or superuser privileges first
	isSuperuserVal := ctx.Value("is_superuser")
	isAdminVal := ctx.Value("is_admin")

	// Handle nil values
	var isSuperuser, isAdmin bool
	if isSuperuserVal != nil {
		isSuperuser = isSuperuserVal.(bool)
	}
	if isAdminVal != nil {
		isAdmin = isAdminVal.(bool)
	}

	if !isSuperuser && !isAdmin {
		return nil, fmt.Errorf(errors.ErrUnauthorized)
	}

	// Get admin user for group checks
	admin, err := s.repo.GetUserByID(ctx, adminID)
	if err != nil {
		return nil, fmt.Errorf(errors.ErrUnauthorized)
	}

	// Check if groups system is loaded for admin operations
	if isAdmin && !isSuperuser {
		if !models.IsGroupsLoaded() {
			return nil, fmt.Errorf(errors.ErrGroupsNotLoaded)
		}
	}

	users, err := s.repo.GetAllUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf(errors.ErrOperationFailed)
	}

	var response []models.UserResponse
	for _, user := range users {
		// Superusers can see all users
		if isSuperuser {
			response = append(response, models.UserResponse{
				ID:             user.ID,
				Email:          user.Email,
				LastLogin:      user.LastLogin,
				CreatedAt:      user.CreatedAt,
				UpdatedAt:      user.UpdatedAt,
				MFAEnabled:     user.MFAEnabled,
				MFAEnforced:    user.MFAEnforced,
				Status:         user.Status,
				Permissions:    user.Permissions,
				Groups:         user.Groups,
				PendingUpdates: user.PendingUpdates,
			})
			continue
		}

		// Admins can only see users who share their groups
		if isAdmin && models.SharesAnyUserGroup(admin.Groups, user.Groups) {
			response = append(response, models.UserResponse{
				ID:             user.ID,
				Email:          user.Email,
				LastLogin:      user.LastLogin,
				CreatedAt:      user.CreatedAt,
				UpdatedAt:      user.UpdatedAt,
				MFAEnabled:     user.MFAEnabled,
				MFAEnforced:    user.MFAEnforced,
				Status:         user.Status,
				Permissions:    user.Permissions,
				Groups:         user.Groups,
				PendingUpdates: user.PendingUpdates,
			})
		}
	}

	return response, nil
}

func (s *AuthService) GetUser(ctx context.Context, adminID, targetUserID string, isSuperUser bool, isAdmin bool) (*models.UserResponse, error) {

	// Check if the user is neither a superuser nor an admin
	if !isSuperUser && !isAdmin {
		return nil, fmt.Errorf(errors.ErrUnauthorized)
	}

	// Get admin user for group checks
	admin, err := s.repo.GetUserByID(ctx, adminID)
	if err != nil {
		return nil, fmt.Errorf(errors.ErrUnauthorized)
	}

	// Get target user
	targetUser, err := s.repo.GetUserByID(ctx, targetUserID)
	if err != nil {
		return nil, fmt.Errorf(errors.ErrUserNotFound)
	}

	fmt.Printf("GetUser - Target user ID: %s\n", targetUser.ID)
	fmt.Printf("GetUser - Target user has pending updates: %v\n", targetUser.PendingUpdates != nil)
	if targetUser.PendingUpdates != nil {
		fmt.Printf("GetUser - Pending update request made at: %s\n", targetUser.PendingUpdates.RequestedAt.Format(time.RFC3339))
	}

	// Superusers can see any user
	if isSuperUser {
		response := &models.UserResponse{
			ID:             targetUser.ID,
			Email:          targetUser.Email,
			LastLogin:      targetUser.LastLogin,
			CreatedAt:      targetUser.CreatedAt,
			UpdatedAt:      targetUser.UpdatedAt,
			MFAEnabled:     targetUser.MFAEnabled,
			MFAEnforced:    targetUser.MFAEnforced,
			Status:         targetUser.Status,
			Permissions:    targetUser.Permissions,
			Groups:         targetUser.Groups,
			PendingUpdates: targetUser.PendingUpdates,
		}
		// Log minimal info for superuser response
		fmt.Printf("GetUser - Prepared response for superuser (user ID: %s)\n", response.ID)
		fmt.Printf("GetUser - Response has pending updates: %v\n", response.PendingUpdates != nil)
		return response, nil
	}

	// Check if groups system is loaded for admin operations
	if isAdmin {
		if !models.IsGroupsLoaded() {
			return nil, fmt.Errorf(errors.ErrGroupsNotLoaded)
		}
		if !models.SharesAnyUserGroup(admin.Groups, targetUser.Groups) {
			return nil, fmt.Errorf(errors.ErrUnauthorized)
		}
	}

	response := &models.UserResponse{
		ID:             targetUser.ID,
		Email:          targetUser.Email,
		LastLogin:      targetUser.LastLogin,
		CreatedAt:      targetUser.CreatedAt,
		UpdatedAt:      targetUser.UpdatedAt,
		MFAEnabled:     targetUser.MFAEnabled,
		MFAEnforced:    targetUser.MFAEnforced,
		Status:         targetUser.Status,
		Permissions:    targetUser.Permissions,
		Groups:         targetUser.Groups,
		PendingUpdates: targetUser.PendingUpdates,
	}

	return response, nil
}

func (s *AuthService) RequestUpdate(ctx context.Context, userID string, req *models.RequestUpdateRequest) error {

	// Immediately check if request is nil
	if req == nil {
		fmt.Println("Request is nil")
		return fmt.Errorf(errors.ErrInvalidRequest)
	}

	// Get current user
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		fmt.Printf("Error getting user: %v\n", err)
		return fmt.Errorf(errors.ErrUserNotFound)
	}

	fmt.Printf("User has PendingUpdates before: %v\n", user.PendingUpdates != nil)

	// Don't allow superuser to request updates
	if user.Email == os.Getenv("SUPERUSER_EMAIL") {
		fmt.Printf("Superuser (ID: %s) attempted to request updates\n", userID)
		return fmt.Errorf(errors.ErrUnauthorized)
	}

	// Verify both permissions and groups are not empty
	if len(req.Updates.Permissions) == 0 && len(req.Updates.Groups) == 0 {
		fmt.Printf("Both Permissions and Groups are empty - invalid request\n")
		return fmt.Errorf(errors.ErrInvalidRequest)
	}

	// Convert from RequestUpdateFields to UserUpdateFields
	permissions := models.UserPermissions{}
	for perm, enabled := range req.Updates.Permissions {
		permissions[perm] = enabled
	}

	groups := models.UserGroups{}
	for group, enabled := range req.Updates.Groups {
		groups[group] = enabled
	}

	var userUpdateFields models.UserUpdateFields
	if len(req.Updates.Permissions) > 0 {
		userUpdateFields.Permissions = &permissions
	}
	if len(req.Updates.Groups) > 0 {
		userUpdateFields.Groups = &groups
	}

	// Create update request
	updateReq := &models.UserUpdateRequest{
		RequestedAt: time.Now(),
		Fields:      userUpdateFields,
	}

	fmt.Printf("Creating update request for user ID: %s\n", userID)

	// Store update request
	user.PendingUpdates = updateReq
	fmt.Printf("User now has pending updates\n")

	// Update the user's status to pending approval if not already
	if user.Status != models.UserStatusPendingApproval {
		user.Status = models.UserStatusPendingApproval
		fmt.Printf("Setting user status to pending approval\n")
	}

	// Always update timestamp to force Redis to save the change
	user.UpdatedAt = time.Now()

	// Ensure updates are stored to Redis
	if err := s.repo.StoreUser(ctx, user); err != nil {
		fmt.Printf("Error storing user update: %v\n", err)
		return fmt.Errorf(errors.ErrOperationFailed)
	}

	// Verify the update was saved by retrieving the user again
	updatedUser, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		fmt.Printf("Error verifying user update: %v\n", err)
		return fmt.Errorf(errors.ErrOperationFailed)
	}

	if updatedUser.PendingUpdates == nil {
		fmt.Printf("Warning: PendingUpdates not found after save operation. Retrying...\n")

		// Try again with a direct update
		updatedUser.PendingUpdates = updateReq
		updatedUser.UpdatedAt = time.Now()
		if err := s.repo.StoreUser(ctx, updatedUser); err != nil {
			fmt.Printf("Error in retry storing user update: %v\n", err)
			return fmt.Errorf(errors.ErrOperationFailed)
		}
	}

	fmt.Printf("Update request stored successfully\n")
	return nil
}

func (s *AuthService) AcquireUserLock(ctx context.Context, userID string, ttl time.Duration) (bool, error) {
	return s.repo.AcquireUserLock(ctx, userID, ttl)
}

func (s *AuthService) ReleaseUserLock(ctx context.Context, userID string) error {
	return s.repo.ReleaseUserLock(ctx, userID)
}
