package service

import (
	"context"
	"fmt"
	"garde/internal/models"
	"garde/internal/repository"
	"garde/pkg/config"
	"garde/pkg/crypto"
	"garde/pkg/mfa"
	"garde/pkg/session"
	"log/slog"
	"math/rand"
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

func InitializeSuperUser(ctx context.Context, repo *repository.RedisRepository) error {
	email := config.Get("SUPERUSER_EMAIL")
	password := config.Get("SUPERUSER_PASSWORD")
	mfaEnforced := config.GetBool("ENFORCE_MFA")

	if email == "" || password == "" {
		return fmt.Errorf("superuser bootstrap failed: SUPERUSER_EMAIL or SUPERUSER_PASSWORD missing")
	}

	hashedPassword, err := crypto.HashPassword(password)
	if err != nil {
		return fmt.Errorf("superuser init failed: %w", err)
	}

	// If superuser exists, refresh password/status/permissions
	if user, err := repo.GetUserByEmail(ctx, email); err == nil && user != nil {
		user.PasswordHash = hashedPassword
		user.Status = models.UserStatusOk
		user.MFAEnforced = mfaEnforced
		user.Permissions = AdminPermissions()
		user.UpdatedAt = time.Now()
		if err := repo.StoreUser(ctx, user); err != nil {
			return fmt.Errorf("superuser init failed: %w", err)
		}
		slog.Info("Superuser refreshed from secrets")
		return nil
	}

	// Create new superuser
	now := time.Now()
	user := &models.User{
		ID:           uuid.New().String(),
		Email:        email,
		PasswordHash: hashedPassword,
		Status:       models.UserStatusOk,
		MFAEnforced:  mfaEnforced,
		CreatedAt:    now,
		UpdatedAt:    now,
		Permissions:  AdminPermissions(),
		Groups:       models.UserGroups{},
	}

	if err := repo.StoreUser(ctx, user); err != nil {
		return fmt.Errorf("superuser init failed: %w", err)
	}

	slog.Info("Superuser initialized from secrets")
	return nil
}

// ADMIN_USERS_JSON should be a JSON object: {"admin1@example.com":"Password1!","admin2@example.com":"Password2!"}
func InitializeAdminUsers(ctx context.Context, repo *repository.RedisRepository) error {
	adminMap := config.GetAdminUsersMap()
	if len(adminMap) == 0 {
		return nil
	}

	mfaEnforced := config.GetBool("ENFORCE_MFA")
	superEmail := config.Get("SUPERUSER_EMAIL")

	for email, password := range adminMap {
		if email == "" || password == "" || email == superEmail {
			// Skip invalid entries and the superuser (handled separately)
			continue
		}

		hashedPassword, err := crypto.HashPassword(password)
		if err != nil {
			return fmt.Errorf("admin init failed: %w", err)
		}

		// If admin exists, refresh credentials/status
		if user, err := repo.GetUserByEmail(ctx, email); err == nil && user != nil {
			user.PasswordHash = hashedPassword
			user.Status = models.UserStatusOk
			user.MFAEnforced = mfaEnforced
			if user.Groups == nil {
				user.Groups = models.UserGroups{}
			}
			user.UpdatedAt = time.Now()
			if err := repo.StoreUser(ctx, user); err != nil {
				return fmt.Errorf("admin init failed: %w", err)
			}
			continue
		}

		// Create new admin
		now := time.Now()
		user := &models.User{
			ID:           uuid.New().String(),
			Email:        email,
			PasswordHash: hashedPassword,
			Status:       models.UserStatusOk,
			MFAEnforced:  mfaEnforced,
			CreatedAt:    now,
			UpdatedAt:    now,
			Permissions:  AdminPermissions(),
			Groups:       models.UserGroups{},
		}

		if err := repo.StoreUser(ctx, user); err != nil {
			return fmt.Errorf("admin init failed: %w", err)
		}
	}

	slog.Info("Admin users initialized from secrets", "count", len(adminMap))
	return nil
}

// Service returns regular errors
func (s *AuthService) Login(ctx context.Context, req *models.LoginRequest, ip, userAgent string) (*models.LoginResponse, error) {

	if !config.GetBool("DISABLE_IP_BLACKLISTING") {
		// Check if IP is blocked
		isBlocked, err := s.repo.IsIPBlocked(ctx, ip)
		if err != nil {
			slog.Debug("Failed to check IP block status", "error", err)
		}
		if isBlocked {
			return nil, fmt.Errorf(errors.ErrAccessRestricted)
		}
	}

	// Get user for security checks
	user, err := s.repo.GetUserByEmail(ctx, req.Email)
	if err != nil {
		slog.Debug("User lookup failed during login", "email", req.Email, "error", err)
		return nil, fmt.Errorf(errors.ErrAuthFailed)
	}

	// Check if user is locked
	if user.Status == models.UserStatusLockedByAdmin || user.Status == models.UserStatusLockedBySecurity {
		slog.Info("Login attempt by locked user", "email", req.Email, "status", user.Status)
		return nil, fmt.Errorf(errors.ErrAccessRestricted)
	}

	// Global MFA enforcement by config
	if config.GetBool("ENFORCE_MFA") && !user.MFAEnforced {
		user.MFAEnforced = true
		if err := s.repo.StoreUser(ctx, user); err != nil {
			slog.Warn("Failed to enforce MFA for user", "email", req.Email, "error", err)
		}
	}

	// Check for suspicious patterns including multiple IP sessions
	// Determine user role for appropriate threshold
	superUserEmail := config.Get("SUPERUSER_EMAIL")
	isSuperuser := user.Email == superUserEmail
	adminMap := config.GetAdminUsersMap()
	isAdmin := len(adminMap) > 0 && adminMap[user.Email] != ""

	if !session.IsRapidRequestCheckDisabled() {
		patterns := s.securityAnalyzer.DetectSuspiciousPatternsWithRole(ctx, user.ID, ip, userAgent, isAdmin, isSuperuser)
		if len(patterns) > 0 {
			// Record all detected patterns
			for _, pattern := range patterns {
				s.securityAnalyzer.RecordPattern(ctx, user.ID, pattern, ip, userAgent)
			}
			return nil, fmt.Errorf(errors.ErrAuthFailed)
		}
	}

	valid, err := crypto.VerifyPassword(req.Password, user.PasswordHash)
	if err != nil {
		return nil, fmt.Errorf(errors.ErrAuthFailed)
	}
	if !valid {
		// Record failed attempt
		failedAttempts, err := s.repo.RecordFailedLogin(ctx, req.Email, ip)
		if err != nil {
			slog.Debug("Failed to record failed login", "error", err)
		}

		// Block if threshold exceeded
		if !config.GetBool("DISABLE_IP_BLACKLISTING") && failedAttempts >= session.FailedLoginThreshold {
			slog.Warn("IP blocked due to too many failed login attempts", "ip", ip, "attempts", failedAttempts)
			s.repo.BlockIP(ctx, ip, session.FailedLoginBlockDuration)
			user.Status = models.UserStatusLockedBySecurity
			s.repo.StoreUser(ctx, user)
			return nil, fmt.Errorf(errors.ErrAccessRestricted)
		}
		return nil, fmt.Errorf(errors.ErrAuthFailed)
	}

	// Check MFA requirement - only require code if MFA is actually set up
	// If MFA is enforced but not yet enabled, allow login and force setup later
	if user.MFAEnabled {
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
		slog.Debug("Failed to update last login time", "error", err, "user_id", user.ID)
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
		slog.Warn("Session deletion failed, added to blacklist", "error", err, "session_id", sessionID)
	}

	// Clean up all security records
	if err := s.securityAnalyzer.CleanupSecurityRecords(ctx, sessionData.UserID, "", ""); err != nil {
		// Log but don't fail the logout
		slog.Debug("Failed to cleanup security records", "error", err, "user_id", sessionData.UserID)
	}

	return nil
}

func (s *AuthService) ValidateSession(ctx context.Context, sessionID, ip, userAgent string) (*ValidationResult, error) {
	// First check if session is blacklisted
	isBlacklisted, err := s.repo.IsSessionBlacklisted(ctx, sessionID)
	if err != nil {
		slog.Debug("Error checking blacklist", "error", err)
		return &ValidationResult{
			Response: &models.SessionValidationResponse{
				Valid: false,
			},
		}, nil
	}

	if isBlacklisted {
		slog.Debug("Session is blacklisted", "session_id_prefix", sessionID[:10])
		return &ValidationResult{
			Response: &models.SessionValidationResponse{
				Valid: false,
			},
		}, nil
	}

	// Get session data
	sessionData, err := s.repo.GetSessionData(ctx, sessionID)
	if err != nil {
		slog.Debug("Error getting session data", "error", err)
		return &ValidationResult{
			Response: &models.SessionValidationResponse{
				Valid: false,
			},
		}, nil
	}

	slog.Debug("Session found", "user_id", sessionData.UserID)

	// Use pattern detector for sophisticated validation
	patterns := s.securityAnalyzer.DetectSuspiciousPatterns(ctx, sessionData.UserID, ip, userAgent)
	if len(patterns) > 0 {
		// Record all detected patterns
		for _, pattern := range patterns {
			s.securityAnalyzer.RecordPattern(ctx, sessionData.UserID, pattern, ip, userAgent)
		}

		// Blacklist this specific session
		if err := s.repo.BlacklistSession(ctx, sessionID, session.BlacklistDuration); err != nil {
			slog.Warn("Failed to blacklist suspicious session", "error", err, "session_id", sessionID)
		}

		// Then try to delete it
		if err := s.repo.DeleteSession(ctx, sessionID); err != nil {
			slog.Warn("Failed to delete suspicious session", "error", err, "session_id", sessionID)
		}

		slog.Info("Suspicious patterns detected for session", "session_id_prefix", sessionID[:10], "patterns", patterns)
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
		slog.Debug("Session has expired", "session_id_prefix", sessionID[:10])
		s.repo.DeleteSession(ctx, sessionID)
		return &ValidationResult{
			Response: &models.SessionValidationResponse{
				Valid: false,
			},
		}, nil
	}

	slog.Debug("Session validation successful", "user_id", sessionData.UserID)

	return &ValidationResult{
		Response: &models.SessionValidationResponse{
			Valid: true,
		},
		UserID: sessionData.UserID,
	}, nil
}

func (s *AuthService) NeedsMFASetup(ctx context.Context, userIDOrEmail string) (bool, error) {
	var user *models.User
	var err error

	// Try to get user by ID first, then by email
	user, err = s.repo.GetUserByID(ctx, userIDOrEmail)
	if err != nil {
		user, err = s.repo.GetUserByEmail(ctx, userIDOrEmail)
		if err != nil {
			return false, err
		}
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
		Secret:    key.Secret,
		QRCodeURL: key.QRCodeData,
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
	// Block public creation of the configured superuser; it is bootstrapped at startup
	if req.Email == config.Get("SUPERUSER_EMAIL") {
		return nil, fmt.Errorf(errors.ErrUnauthorized)
	}

	// Block public creation of configured admin users; they are initialized from secrets
	if isAdminEmail(req.Email) {
		return nil, fmt.Errorf(errors.ErrUnauthorized)
	}

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
	mfaEnforced := config.GetBool("ENFORCE_MFA")

	user := &models.User{
		ID:           uuid.New().String(),
		Email:        req.Email,
		PasswordHash: hashedPassword,
		Status:       models.UserStatusPendingApproval,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		MFAEnforced:  mfaEnforced,
		Groups:       models.UserGroups{},
	}

	user.Permissions = DefaultPermissions()

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
		slog.Warn("Failed to get admin user by ID", "error", err, "admin_id", adminID)
		return fmt.Errorf(errors.ErrOperationFailed)
	}

	// Get the target user
	targetUser, err := s.repo.GetUserByID(ctx, targetUserID)
	if err != nil {
		slog.Warn("Failed to get target user by ID", "error", err, "target_user_id", targetUserID)
		return fmt.Errorf(errors.ErrUserNotFound)
	}

	// Only superuser can modify superuser
	superUserEmail := config.Get("SUPERUSER_EMAIL")
	if targetUser.Email == superUserEmail && !isSuperUser {
		return fmt.Errorf(errors.ErrUnauthorized)
	}

	// Check if admin has permission to modify this user
	if !isSuperUser && !isAdmin {
		slog.Debug("Unauthorized update attempt", "reason", "user is neither superuser nor admin", "admin_id", adminID)
		return fmt.Errorf(errors.ErrUnauthorized)
	}

	// Check if groups system is loaded for admin operations
	// Superusers are exempt from group sharing checks
	if !isSuperUser && isAdmin {
		if !IsGroupsLoaded() {
			return fmt.Errorf(errors.ErrGroupsNotLoaded)
		}

		// Admin must share at least one group with target user (no "claiming" allowed)
		if !models.SharesAnyUserGroup(admin.Groups, targetUser.Groups) {
			slog.Debug("Unauthorized update attempt", "reason", "admin doesn't share groups with target user", "admin_id", adminID, "target_user_id", targetUserID)
			return fmt.Errorf(errors.ErrUnauthorized)
		}

		// If updating groups, check if admin is in the groups they're trying to ADD (not already present)
		if req.Groups != nil {
			for group, enabled := range *req.Groups {
				// Only check if admin is trying to ADD user to a new group
				// If user is already in the group, admin can keep them there
				isNewGroup := enabled && !targetUser.Groups[group]
				if isNewGroup && !admin.Groups[group] {
					return fmt.Errorf(errors.ErrUnauthorized)
				}
			}
		}
	}

	// Track update attempt in audit log
	err = s.repo.RecordAuditLog(ctx, targetUserID, map[string]interface{}{
		"type":      "update_attempt",
		"admin_id":  adminID,
		"timestamp": time.Now(),
	}, 10, 7*24*time.Hour)
	if err != nil {
		slog.Warn("Failed to record audit log", "error", err)
	}

	// Store original state for comparison
	originalStatus := targetUser.Status
	originalMFAEnforced := targetUser.MFAEnforced

	// **** IMPORTANT: Save original PendingUpdates to restore later if not approving/rejecting ****
	originalPendingUpdates := targetUser.PendingUpdates

	// Handle update request approval/rejection
	if targetUser.PendingUpdates != nil && (req.ApproveUpdate || req.RejectUpdate) {
		if req.ApproveUpdate {
			// Safeguard: Prevent removing all permissions
			if len(targetUser.PendingUpdates.Fields.PermissionsRemove) > 0 {
				if !IsPermissionsLoaded() {
					return fmt.Errorf(errors.ErrPermissionsNotLoaded)
				}
				// Count how many permissions user currently has
				currentCount := 0
				for _, enabled := range targetUser.Permissions {
					if enabled {
						currentCount++
					}
				}
				// Calculate final count after add/remove operations
				// Note: We don't check for duplicates (removing and adding same item) as that's unlikely
				finalCount := currentCount - len(targetUser.PendingUpdates.Fields.PermissionsRemove) + len(targetUser.PendingUpdates.Fields.PermissionsAdd)
				if finalCount <= 0 {
					slog.Warn("Update request rejected: would remove all permissions", "user_id", targetUserID)
					return fmt.Errorf(errors.ErrCannotRemoveAllPermissions)
				}
			}

			// Safeguard: Prevent removing all groups
			if len(targetUser.PendingUpdates.Fields.GroupsRemove) > 0 {
				if !IsGroupsLoaded() {
					return fmt.Errorf(errors.ErrGroupsNotLoaded)
				}
				// Count how many groups user currently has
				currentCount := 0
				for _, enabled := range targetUser.Groups {
					if enabled {
						currentCount++
					}
				}
				// Calculate final count after add/remove operations
				// Note: We don't check for duplicates (removing and adding same item) as that's unlikely
				finalCount := currentCount - len(targetUser.PendingUpdates.Fields.GroupsRemove) + len(targetUser.PendingUpdates.Fields.GroupsAdd)
				if finalCount <= 0 {
					slog.Warn("Update request rejected: would remove all groups", "user_id", targetUserID)
					return fmt.Errorf(errors.ErrCannotRemoveAllGroups)
				}
			}

			// Apply permission changes
			if len(targetUser.PendingUpdates.Fields.PermissionsAdd) > 0 || len(targetUser.PendingUpdates.Fields.PermissionsRemove) > 0 {
				if !IsPermissionsLoaded() {
					return fmt.Errorf(errors.ErrPermissionsNotLoaded)
				}

				// For non-superuser admins: verify admin can see all permissions they're approving
				if !isSuperUser && isAdmin {
					adminGroupNames := GetUserGroupNames(admin.Groups)
					// Check permissions to add - admin must be able to see them
					for _, perm := range targetUser.PendingUpdates.Fields.PermissionsAdd {
						if !IsValidPermission(perm) {
							continue
						}
						if len(adminGroupNames) > 0 && !IsPermissionVisibleToGroups(string(perm), adminGroupNames) {
							slog.Warn("Admin attempted to approve adding permission they cannot see", "admin_id", adminID, "permission", perm, "user_id", targetUserID)
							return fmt.Errorf(errors.ErrInvalidPermissionRequested + ": " + string(perm))
						}
					}
				}

				// Remove permissions
				for _, perm := range targetUser.PendingUpdates.Fields.PermissionsRemove {
					if IsValidPermission(perm) {
						delete(targetUser.Permissions, perm)
					}
				}
				// Add permissions
				for _, perm := range targetUser.PendingUpdates.Fields.PermissionsAdd {
					if IsValidPermission(perm) {
						targetUser.Permissions[perm] = true
					}
				}
			}

			// Apply group changes
			if len(targetUser.PendingUpdates.Fields.GroupsAdd) > 0 || len(targetUser.PendingUpdates.Fields.GroupsRemove) > 0 {
				if !IsGroupsLoaded() {
					return fmt.Errorf(errors.ErrGroupsNotLoaded)
				}

				// For non-superuser admins: verify admin is in all groups they're trying to add
				// (Remove is allowed for any groups once shared-group requirement is met, including the last shared group)
				groupsToAdd := targetUser.PendingUpdates.Fields.GroupsAdd
				if !isSuperUser && isAdmin {
					filteredGroupsAdd := []models.UserGroup{}
					unauthorizedGroups := []string{}
					for _, group := range targetUser.PendingUpdates.Fields.GroupsAdd {
						if admin.Groups[group] {
							filteredGroupsAdd = append(filteredGroupsAdd, group)
						} else {
							unauthorizedGroups = append(unauthorizedGroups, string(group))
							slog.Warn("Admin attempted to approve adding group they're not in", "admin_id", adminID, "group", group, "user_id", targetUserID)
						}
					}
					// Return error if admin tried to add groups they're not in
					if len(unauthorizedGroups) > 0 {
						groupsList := fmt.Sprintf("'%s'", strings.Join(unauthorizedGroups, "', '"))
						return fmt.Errorf("%s: %s", errors.ErrCannotAddGroupsNotIn, groupsList)
					}
					groupsToAdd = filteredGroupsAdd
				}

				// Remove groups (admins can remove any groups, including the last shared group)
				for _, group := range targetUser.PendingUpdates.Fields.GroupsRemove {
					if IsValidUserGroup(group) {
						delete(targetUser.Groups, group)
					}
				}
				// Add groups (filtered for admins)
				for _, group := range groupsToAdd {
					if IsValidUserGroup(group) {
						targetUser.Groups[group] = true
					}
				}
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
					slog.Warn("Failed to blacklist session", "error", err, "session_id", sessionID)
				}
				if err := s.repo.DeleteSession(ctx, sessionID); err != nil {
					slog.Warn("Failed to delete session", "error", err, "session_id", sessionID)
				}
			}
		}
	}

	if req.MFAEnforced != nil {
		targetUser.MFAEnforced = *req.MFAEnforced
	}

	if req.Permissions != nil {
		if !IsPermissionsLoaded() {
			return fmt.Errorf(errors.ErrPermissionsNotLoaded)
		}
		// Validate permissions exist and visibility (superuser exempt)
		if !isSuperUser {
			adminGroupNames := GetUserGroupNames(admin.Groups)
			for perm := range *req.Permissions {
				if !IsValidPermission(perm) {
					slog.Info("Invalid permission in update request", "permission", perm)
					return fmt.Errorf(errors.ErrUnauthorized)
				}
				// For admins: check visibility - can only grant permissions they can see
				if isAdmin && len(adminGroupNames) > 0 && (*req.Permissions)[perm] {
					if !IsPermissionVisibleToGroups(string(perm), adminGroupNames) {
						slog.Info("Admin attempted to grant permission they cannot see", "admin_id", adminID, "permission", perm, "user_id", targetUserID)
						return fmt.Errorf(errors.ErrInvalidPermissionRequested + ": " + string(perm))
					}
				}
			}
		}
		targetUser.Permissions = *req.Permissions
	}

	// Add support for direct groups updates
	if req.Groups != nil {
		// Validate groups (superusers exempt)
		if !isSuperUser {
			for group := range *req.Groups {
				if !IsGroupsLoaded() {
					slog.Debug("Groups system not loaded when trying to update user groups", "admin_id", adminID, "target_user_id", targetUserID)
					return fmt.Errorf(errors.ErrGroupsNotLoaded)
				}
				if !IsValidUserGroup(group) {
					slog.Debug("Invalid group requested in user update", "group", string(group), "admin_id", adminID, "target_user_id", targetUserID)
					return fmt.Errorf(errors.ErrUnauthorized)
				}
			}
		} else {
			slog.Debug("Superuser updating user groups - skipping group validation", "admin_id", adminID, "target_user_id", targetUserID, "groups", req.Groups)
		}

		// Convert directly without type casting
		userGroups := models.UserGroups{}
		for group, enabled := range *req.Groups {
			userGroups[group] = enabled
		}

		// Update the groups
		// Note: Admins can remove the last shared group (intentional - allows removing users from their group)
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
		req.Groups != nil ||
		req.ApproveUpdate ||
		req.RejectUpdate {
		targetUser.UpdatedAt = time.Now()
		if err := s.repo.StoreUser(ctx, targetUser); err != nil {
			return fmt.Errorf(errors.ErrOperationFailed)
		}

		// Record successful update in audit log
		s.repo.RecordAuditLog(ctx, targetUserID, map[string]interface{}{
			"type":      "update_success",
			"admin_id":  adminID,
			"timestamp": time.Now(),
		}, 10, 7*24*time.Hour)
	}

	return nil
}

func isAdminEmail(email string) bool {
	if adminMap := config.GetAdminUsersMap(); len(adminMap) > 0 {
		if _, ok := adminMap[email]; ok {
			return true
		}
	}
	return false
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
	if targetUser.Email == config.Get("SUPERUSER_EMAIL") && !isSuperUser {
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
				slog.Warn("Failed to blacklist session", "error", err, "session_id", sessionID)
			}
			if err := s.repo.DeleteSession(ctx, sessionID); err != nil {
				slog.Warn("Failed to delete session", "error", err, "session_id", sessionID)
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
				slog.Warn("Failed to blacklist session", "error", err, "session_id", sessionID)
			}
			if err := s.repo.DeleteSession(ctx, sessionID); err != nil {
				slog.Warn("Failed to delete session", "error", err, "session_id", sessionID)
			}
		}
		return nil
	}

	return fmt.Errorf(errors.ErrUnauthorized)
}

func (s *AuthService) DeleteUser(ctx context.Context, adminID string, targetUserID string, isSuperUser bool, isAdmin bool) error {
	admin, err := s.repo.GetUserByID(ctx, adminID)
	if err != nil {
		return fmt.Errorf(errors.ErrUnauthorized)
	}

	// Get target user
	targetUser, err := s.repo.GetUserByID(ctx, targetUserID)
	if err != nil {
		return fmt.Errorf(errors.ErrUserNotFound)
	}

	// Only superuser can delete superuser
	superUserEmail := config.Get("SUPERUSER_EMAIL")
	if targetUser.Email == superUserEmail && !isSuperUser {
		return fmt.Errorf(errors.ErrUnauthorized)
	}

	// Prevent self-deletion
	if adminID == targetUserID {
		return fmt.Errorf(errors.ErrUnauthorized)
	}

	// Check if admin has permission to delete this user
	if !isSuperUser && !isAdmin {
		return fmt.Errorf(errors.ErrUnauthorized)
	}

	// Superusers are exempt from group sharing checks
	if !isSuperUser && isAdmin {
		if !IsGroupsLoaded() {
			return fmt.Errorf(errors.ErrGroupsNotLoaded)
		}

		// Admin must share at least one group with target user
		if !models.SharesAnyUserGroup(admin.Groups, targetUser.Groups) {
			return fmt.Errorf(errors.ErrUnauthorized)
		}
	}

	// Revoke all active sessions
	sessions, err := s.repo.GetUserActiveSessions(ctx, targetUserID)
	if err != nil {
		slog.Warn("Failed to get active sessions for user deletion", "error", err, "user_id", targetUserID)
	} else {
		for _, sessionID := range sessions {
			if err := s.repo.BlacklistSession(ctx, sessionID, session.BlacklistDuration); err != nil {
				slog.Warn("Failed to blacklist session during user deletion", "error", err, "session_id", sessionID)
			}
			if err := s.repo.DeleteSession(ctx, sessionID); err != nil {
				slog.Warn("Failed to delete session during user deletion", "error", err, "session_id", sessionID)
			}
		}
	}

	// Clean up security records
	if err := s.securityAnalyzer.CleanupSecurityRecords(ctx, targetUserID, targetUser.Email, ""); err != nil {
		slog.Warn("Failed to cleanup security records during user deletion", "error", err, "user_id", targetUserID)
	}

	// Delete user from repository
	if err := s.repo.DeleteUser(ctx, targetUserID); err != nil {
		return fmt.Errorf(errors.ErrOperationFailed)
	}

	// Record deletion in audit log (using admin's audit log since target user is deleted)
	s.repo.RecordAuditLog(ctx, adminID, map[string]interface{}{
		"type":            "user_deleted",
		"deleted_user_id": targetUserID,
		"deleted_email":   targetUser.Email,
		"timestamp":       time.Now(),
	}, 10, 7*24*time.Hour)

	return nil
}

func (s *AuthService) ResetPassword(ctx context.Context, req *models.PasswordResetRequest) error {
	// Get user
	user, err := s.repo.GetUserByEmail(ctx, req.Email)
	if err != nil {
		return fmt.Errorf(errors.ErrUserNotFound)
	}

	// Don't allow reset for superuser
	if user.Email == config.Get("SUPERUSER_EMAIL") {
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
		slog.Debug("Failed to get active sessions", "error", err)
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
	if user.Email == config.Get("SUPERUSER_EMAIL") {
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
			slog.Debug("Preserving current session", "session_id_prefix", sessionID[:10])
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
	if user.Email == config.Get("SUPERUSER_EMAIL") {
		return nil
	}

	// Generate 5-letter OTP
	otp := make([]byte, 5)
	for i := range otp {
		otp[i] = byte('A' + rand.Intn(26))
	}
	otpStr := string(otp)

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

	// Filter permissions by visibility - regular users only see permissions visible to their groups
	userGroupNames := GetUserGroupNames(user.Groups)
	filteredPermissions := user.Permissions
	if len(userGroupNames) > 0 {
		visiblePerms := GetVisiblePermissions(userGroupNames)
		visiblePermSet := make(map[models.Permission]bool)
		for _, p := range visiblePerms {
			visiblePermSet[p] = true
		}
		// Only include permissions that are visible to user
		filteredPermissions = models.UserPermissions{}
		for perm, enabled := range user.Permissions {
			if enabled && visiblePermSet[perm] {
				filteredPermissions[perm] = true
			}
		}
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
		Permissions: filteredPermissions,
		Groups:      user.Groups,
	}, nil
}

func (s *AuthService) ListUsers(ctx context.Context, adminID string, isSuperUser bool, isAdmin bool) ([]models.UserResponse, error) {
	// Check if user has admin or superuser privileges first
	if !isSuperUser && !isAdmin {
		return nil, fmt.Errorf(errors.ErrUnauthorized)
	}

	// Get admin user for group checks
	admin, err := s.repo.GetUserByID(ctx, adminID)
	if err != nil {
		return nil, fmt.Errorf(errors.ErrUnauthorized)
	}

	// Check if groups system is loaded for admin operations
	if isAdmin && !isSuperUser {
		if !IsGroupsLoaded() {
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
		if isSuperUser {
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
			// Filter pending updates to only show groups admin can approve
			filteredPendingUpdates := filterPendingUpdatesForAdmin(user.PendingUpdates, admin.Groups)

			// Filter permissions by visibility for admins
			adminGroupNames := GetUserGroupNames(admin.Groups)
			filteredPermissions := user.Permissions
			if len(adminGroupNames) > 0 {
				visiblePerms := GetVisiblePermissions(adminGroupNames)
				visiblePermSet := make(map[models.Permission]bool)
				for _, p := range visiblePerms {
					visiblePermSet[p] = true
				}
				// Only include permissions that are visible to admin
				filteredPermissions = models.UserPermissions{}
				for perm, enabled := range user.Permissions {
					if enabled && visiblePermSet[perm] {
						filteredPermissions[perm] = true
					}
				}
			}

			response = append(response, models.UserResponse{
				ID:             user.ID,
				Email:          user.Email,
				LastLogin:      user.LastLogin,
				CreatedAt:      user.CreatedAt,
				UpdatedAt:      user.UpdatedAt,
				MFAEnabled:     user.MFAEnabled,
				MFAEnforced:    user.MFAEnforced,
				Status:         user.Status,
				Permissions:    filteredPermissions,
				Groups:         user.Groups,
				PendingUpdates: filteredPendingUpdates,
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
		return response, nil
	}

	// Check if groups system is loaded for admin operations
	if isAdmin {
		if !IsGroupsLoaded() {
			return nil, fmt.Errorf(errors.ErrGroupsNotLoaded)
		}
		if !models.SharesAnyUserGroup(admin.Groups, targetUser.Groups) {
			return nil, fmt.Errorf(errors.ErrUnauthorized)
		}
	}

	// Filter pending updates for admin (superuser sees all)
	pendingUpdates := targetUser.PendingUpdates
	if isAdmin && !isSuperUser {
		pendingUpdates = filterPendingUpdatesForAdmin(targetUser.PendingUpdates, admin.Groups)
	}

	// Filter permissions by visibility for admins
	filteredPermissions := targetUser.Permissions
	if isAdmin && !isSuperUser {
		adminGroupNames := GetUserGroupNames(admin.Groups)
		if len(adminGroupNames) > 0 {
			visiblePerms := GetVisiblePermissions(adminGroupNames)
			visiblePermSet := make(map[models.Permission]bool)
			for _, p := range visiblePerms {
				visiblePermSet[p] = true
			}
			// Only include permissions that are visible to admin
			filteredPermissions = models.UserPermissions{}
			for perm, enabled := range targetUser.Permissions {
				if enabled && visiblePermSet[perm] {
					filteredPermissions[perm] = true
				}
			}
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
		Permissions:    filteredPermissions,
		Groups:         targetUser.Groups,
		PendingUpdates: pendingUpdates,
	}

	return response, nil
}

func (s *AuthService) RequestUpdate(ctx context.Context, userID string, req *models.RequestUpdateRequest) error {

	if req == nil {
		slog.Warn("Request update failed", "reason", "request is nil", "user_id", userID)
		return fmt.Errorf(errors.ErrInvalidRequest)
	}

	// Get current user
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		slog.Warn("Request update failed", "error", err, "user_id", userID)
		return fmt.Errorf(errors.ErrUserNotFound)
	}

	// Don't allow superuser to request updates
	if user.Email == config.Get("SUPERUSER_EMAIL") {
		slog.Info("Superuser attempted to request updates", "user_id", userID)
		return fmt.Errorf(errors.ErrUnauthorized)
	}

	// Validate that at least one change is requested
	if len(req.Updates.PermissionsAdd) == 0 && len(req.Updates.PermissionsRemove) == 0 &&
		len(req.Updates.GroupsAdd) == 0 && len(req.Updates.GroupsRemove) == 0 {
		slog.Warn("Invalid update request", "reason", "empty permissions and groups", "user_id", userID)
		return fmt.Errorf(errors.ErrInvalidRequest)
	}

	var userUpdateFields models.UserUpdateFields

	// Validate and process permissions
	if len(req.Updates.PermissionsAdd) > 0 || len(req.Updates.PermissionsRemove) > 0 {
		if !IsPermissionsLoaded() {
			return fmt.Errorf(errors.ErrPermissionsNotLoaded)
		}

		// Get user's groups for visibility checking
		userGroupNames := GetUserGroupNames(user.Groups)

		// Validate permissions to add - users can only request permissions visible to their groups
		for _, permStr := range req.Updates.PermissionsAdd {
			perm := models.Permission(permStr)
			if !IsValidPermission(perm) {
				slog.Warn("Invalid permission requested to add", "permission", permStr, "user_id", userID)
				return fmt.Errorf(errors.ErrInvalidRequest)
			}
			// Check visibility - regular users can only request permissions visible to their groups
			if len(userGroupNames) > 0 && !IsPermissionVisibleToGroups(permStr, userGroupNames) {
				slog.Warn("User attempted to request permission not visible to their groups", "permission", permStr, "user_id", userID, "groups", userGroupNames)
				return fmt.Errorf(errors.ErrInvalidPermissionRequested + ": " + permStr)
			}
			userUpdateFields.PermissionsAdd = append(userUpdateFields.PermissionsAdd, perm)
		}
		// Validate permissions to remove - users can only remove permissions they have
		for _, permStr := range req.Updates.PermissionsRemove {
			perm := models.Permission(permStr)
			if !IsValidPermission(perm) {
				slog.Warn("Invalid permission requested to remove", "permission", permStr, "user_id", userID)
				return fmt.Errorf(errors.ErrInvalidRequest)
			}
			// Users can only remove permissions they currently have
			if !user.Permissions[perm] {
				slog.Warn("User attempted to remove permission they don't have", "permission", permStr, "user_id", userID)
				return fmt.Errorf(errors.ErrInvalidRequest)
			}
			userUpdateFields.PermissionsRemove = append(userUpdateFields.PermissionsRemove, perm)
		}
	}

	// Validate and process groups
	if len(req.Updates.GroupsAdd) > 0 || len(req.Updates.GroupsRemove) > 0 {
		if !IsGroupsLoaded() {
			return fmt.Errorf(errors.ErrGroupsNotLoaded)
		}
		// Validate groups to add
		for _, groupStr := range req.Updates.GroupsAdd {
			group := models.UserGroup(groupStr)
			if !IsValidUserGroup(group) {
				slog.Warn("Invalid group requested to add", "group", groupStr, "user_id", userID)
				return fmt.Errorf(errors.ErrInvalidRequest)
			}
			userUpdateFields.GroupsAdd = append(userUpdateFields.GroupsAdd, group)
		}
		// Validate groups to remove
		for _, groupStr := range req.Updates.GroupsRemove {
			group := models.UserGroup(groupStr)
			if !IsValidUserGroup(group) {
				slog.Warn("Invalid group requested to remove", "group", groupStr, "user_id", userID)
				return fmt.Errorf(errors.ErrInvalidRequest)
			}
			userUpdateFields.GroupsRemove = append(userUpdateFields.GroupsRemove, group)
		}
	}

	updateReq := &models.UserUpdateRequest{
		RequestedAt: time.Now(),
		Fields:      userUpdateFields,
	}

	// Store update request
	user.PendingUpdates = updateReq

	// Always update timestamp to force Redis to save the change
	user.UpdatedAt = time.Now()

	// Ensure updates are stored to Redis
	if err := s.repo.StoreUser(ctx, user); err != nil {
		slog.Error("Failed to store user update", "error", err, "user_id", userID)
		return fmt.Errorf(errors.ErrOperationFailed)
	}

	// Verify the update was saved by retrieving the user again
	updatedUser, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		slog.Error("Failed to verify user update", "error", err, "user_id", userID)
		return fmt.Errorf(errors.ErrOperationFailed)
	}

	if updatedUser.PendingUpdates == nil {
		slog.Warn("PendingUpdates not found after save operation. Retrying...", "user_id", userID)

		// Try again with a direct update
		updatedUser.PendingUpdates = updateReq
		updatedUser.UpdatedAt = time.Now()
		if err := s.repo.StoreUser(ctx, updatedUser); err != nil {
			slog.Error("Failed in retry storing user update", "error", err, "user_id", userID)
			return fmt.Errorf(errors.ErrOperationFailed)
		}
	}

	slog.Info("Update request stored successfully", "user_id", userID)
	return nil
}

func (s *AuthService) AcquireUserLock(ctx context.Context, userID string, ttl time.Duration) (bool, error) {
	return s.repo.AcquireUserLock(ctx, userID, ttl)
}

func (s *AuthService) ReleaseUserLock(ctx context.Context, userID string) error {
	return s.repo.ReleaseUserLock(ctx, userID)
}

func filterPendingUpdatesForAdmin(pending *models.UserUpdateRequest, adminGroups models.UserGroups) *models.UserUpdateRequest {
	if pending == nil {
		return nil
	}

	// Create filtered copy
	filtered := &models.UserUpdateRequest{
		RequestedAt: pending.RequestedAt,
		Fields:      models.UserUpdateFields{},
	}

	// Keep all permission requests (admins can approve any permission changes)
	filtered.Fields.PermissionsAdd = pending.Fields.PermissionsAdd
	filtered.Fields.PermissionsRemove = pending.Fields.PermissionsRemove

	// Filter group requests:
	// - Add: Admin can only add groups they're in (to prevent adding to groups they don't have access to)
	// - Remove: Admin can remove ANY groups once shared-group requirement is met (already checked at GetUser level)
	filteredGroupsAdd := []models.UserGroup{}
	filteredGroupsRemove := []models.UserGroup{}

	// Only allow adding groups the admin is in
	for _, group := range pending.Fields.GroupsAdd {
		if adminGroups[group] {
			filteredGroupsAdd = append(filteredGroupsAdd, group)
		}
	}

	// Allow removing ANY groups (admin already passed shared-group check to see this user)
	filteredGroupsRemove = append(filteredGroupsRemove, pending.Fields.GroupsRemove...)

	if len(filteredGroupsAdd) > 0 {
		filtered.Fields.GroupsAdd = filteredGroupsAdd
	}
	if len(filteredGroupsRemove) > 0 {
		filtered.Fields.GroupsRemove = filteredGroupsRemove
	}

	// Return nil if no changes remain after filtering
	if len(filtered.Fields.PermissionsAdd) == 0 && len(filtered.Fields.PermissionsRemove) == 0 &&
		len(filtered.Fields.GroupsAdd) == 0 && len(filtered.Fields.GroupsRemove) == 0 {
		return nil
	}

	return filtered
}
