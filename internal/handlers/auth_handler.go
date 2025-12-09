package handlers

import (
	"errors"
	"garde/internal/middleware"
	"garde/internal/models"
	"garde/internal/repository"
	"garde/internal/service"
	"garde/pkg/config"
	pkgerrors "garde/pkg/errors"
	"garde/pkg/session"
	"garde/pkg/validation"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type AuthHandler struct {
	authService *service.AuthService
}

func NewAuthHandler(authService *service.AuthService) *AuthHandler {
	return &AuthHandler{authService: authService}
}

// @Summary Login user
// @Description Authenticates a user and returns a session token. No mTLS required for this endpoint.
// @Tags Public Routes
// @Accept json
// @Produce json
// @Param request body models.LoginRequest true "Login credentials"
// @Success 200 {object} models.SuccessResponse{data=models.LoginResponse} "Returns session ID and sets session cookie"
// @Failure 400 {object} models.ErrorResponse "Invalid request format"
// @Failure 401 {object} models.ErrorResponse "Authentication failed, invalid credentials, MFA required, or invalid MFA code"
// @Failure 429 {object} models.ErrorResponse "Too many login attempts"
// @Router /login [post]
func (h *AuthHandler) Login(c *gin.Context) {
	req, exists := middleware.GetValidatedRequest[models.LoginRequest](c)
	if !exists {
		// If validation failed or middleware didn't run, return an error
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(pkgerrors.ErrInvalidRequest))
		return
	}

	resp, err := h.authService.Login(c.Request.Context(), &req, c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		c.JSON(http.StatusUnauthorized, models.NewErrorResponse(err.Error()))
		return
	}

	cookieDomain := config.Get("DOMAIN_NAME")

	// Set secure cookie with session ID
	c.SetCookie(
		"session",
		resp.SessionID,
		int(session.SessionDuration.Seconds()),
		"/",
		cookieDomain,
		true,
		true,
	)

	c.JSON(http.StatusOK, models.NewSuccessResponse(resp))
}

// @Summary Logout user
// @Description Invalidates the current session. No mTLS required for this endpoint.
// @Tags Protected Routes
// @Accept json
// @Produce json
// @Security SessionCookie
// @Security Bearer
// @Success 200 {object} models.SuccessResponse "Session invalidated successfully"
// @Failure 400 {object} models.ErrorResponse "No active session"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /logout [post]
func (h *AuthHandler) Logout(c *gin.Context) {
	sessionID, err := c.Cookie("session")
	if err != nil {
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(pkgerrors.ErrNoActiveSession))
		return
	}

	err = h.authService.Logout(c.Request.Context(), sessionID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.NewErrorResponse("Internal server error"))
		return
	}

	cookieDomain := config.Get("DOMAIN_NAME")

	// Set cookie with Max-Age=0 (immediate expiration) and expired Expires date as fallback
	c.SetCookie(
		"session",
		"",
		0, // Max-Age=0 for immediate expiration
		"/",
		cookieDomain, // Use environment variable
		true,
		true,
	)

	c.JSON(http.StatusOK, models.NewSuccessResponse(nil))
}

type ValidateResponse struct {
	UserID    string    `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

// @Summary Validate a session
// @Description Validates a session token. Require API key + mTLS. No other type of authentication is supported
// @Tags For Internal Services
// @Accept json
// @Produce json
// @Security SessionCookie
// @Security ApiKey
// @Security Bearer
// @Param session_id query string false "Session ID (required only for API requests with API key)"
// @Success 200 {object} models.SuccessResponse "Session validation result with Response.valid and UserID fields"
// @Failure 400 {object} models.ErrorResponse "Invalid session ID format or missing session ID for API request"
// @Failure 401 {object} models.ErrorResponse "Unauthorized - invalid session, missing mTLS certificate for API requests, or invalid API key"
// @Failure 403 {object} models.ErrorResponse "Forbidden - insufficient permissions (user not in admin's groups)"
// @Failure 500 {object} models.ErrorResponse "Internal server error or permissions system not loaded"
// @Router /validate [get]
func (h *AuthHandler) ValidateSession(c *gin.Context) {
	isAPIRequest, exists := c.Get("is_api_request")

	isAPI := exists && isAPIRequest != nil
	if isAPI {
		// API requests can validate any session
		sessionID := c.Query("session_id")
		sessionID, err := validation.Sanitize(sessionID)
		if err != nil {
			c.JSON(http.StatusBadRequest, models.NewErrorResponse(pkgerrors.ErrInvalidRequest))
			return
		}

		if err := validation.ValidateSessionID(sessionID); err != nil {
			c.JSON(http.StatusBadRequest, models.NewErrorResponse(pkgerrors.ErrInvalidRequest))
			return
		}

		resp, err := h.authService.ValidateSession(
			c.Request.Context(),
			sessionID,
			c.ClientIP(),
			c.Request.UserAgent(),
		)
		if err != nil || resp == nil || !resp.Response.Valid {
			c.JSON(http.StatusUnauthorized, models.NewErrorResponse(pkgerrors.ErrSessionInvalid))
			return
		}

		c.JSON(http.StatusOK, models.NewSuccessResponse(resp))
		return
	}

	// Regular validation flow(for admin, without API key)
	sessionID, exists := c.Get("session_id")
	if !exists || sessionID == nil {
		c.JSON(http.StatusUnauthorized, models.NewErrorResponse(pkgerrors.ErrSessionInvalid))
		return
	}

	sessionIDStr, ok := sessionID.(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, models.NewErrorResponse(pkgerrors.ErrOperationFailed))
		return
	}

	resp, err := h.authService.ValidateSession(
		c.Request.Context(),
		sessionIDStr,
		c.ClientIP(),
		c.Request.UserAgent(),
	)
	if err != nil || resp == nil || !resp.Response.Valid {
		c.JSON(http.StatusUnauthorized, models.NewErrorResponse(pkgerrors.ErrSessionInvalid))
		return
	}

	c.JSON(http.StatusOK, models.NewSuccessResponse(resp))
}

// @Summary Setup MFA
// @Description Sets up Multi-Factor Authentication for a user. No mTLS required for this endpoint. Requires authentication.
// @Tags Protected Routes
// @Accept json
// @Produce json
// @Security SessionCookie
// @Security Bearer
// @Success 200 {object} models.SuccessResponse{data=models.MFAResponse} "Returns MFA secret and QR code URL"
// @Failure 400 {object} models.ErrorResponse "MFA already enabled or setup failed"
// @Failure 401 {object} models.ErrorResponse "Unauthorized when using authenticated mode"
// @Failure 404 {object} models.ErrorResponse "User not found"
// @Failure 500 {object} models.ErrorResponse "Operation failed"
// @Router /users/mfa/setup [post]
func (h *AuthHandler) SetupMFA(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, models.NewErrorResponse(pkgerrors.ErrUnauthorized))
		return
	}

	resp, err := h.authService.SetupMFA(c.Request.Context(), userID.(string))
	if err != nil {
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(err.Error()))
		return
	}

	c.JSON(http.StatusOK, models.NewSuccessResponse(resp))
}

// @Summary Verify and enable MFA
// @Description Verifies MFA code and enables MFA for the user. No mTLS required for this endpoint. Requires authentication.
// @Tags Protected Routes
// @Accept json
// @Produce json
// @Security SessionCookie
// @Security Bearer
// @Param request body models.MFAVerifyRequest true "MFA verification code"
// @Success 200 {object} models.SuccessResponse "MFA enabled successfully"
// @Failure 400 {object} models.ErrorResponse "Invalid MFA code, invalid request format, or MFA already enabled"
// @Failure 401 {object} models.ErrorResponse "Unauthorized when using authenticated mode"
// @Failure 404 {object} models.ErrorResponse "User not found"
// @Failure 500 {object} models.ErrorResponse "Operation failed"
// @Router /users/mfa/verify [post]
func (h *AuthHandler) VerifyAndEnableMFA(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, models.NewErrorResponse(pkgerrors.ErrUnauthorized))
		return
	}

	// Get the validated request from the middleware context
	req, exists := middleware.GetValidatedRequest[models.MFAVerifyRequest](c)
	if !exists {
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(pkgerrors.ErrInvalidRequest))
		return
	}

	err := h.authService.VerifyAndEnableMFA(c.Request.Context(), userID.(string), req.Code)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(err.Error()))
		return
	}

	c.JSON(http.StatusOK, models.NewSuccessResponse(nil))
}

// @Summary Create new user
// @Description Creates a new user account with pending approval status. No mTLS required for this endpoint.
// @Tags Public Routes
// @Accept json
// @Produce json
// @Param request body models.CreateUserRequest true "User registration details"
// @Success 201 {object} models.SuccessResponse{data=models.CreateUserResponse} "Returns created user ID"
// @Failure 400 {object} models.ErrorResponse "Invalid request format, email format, password requirements not met, or email already exists"
// @Failure 500 {object} models.ErrorResponse "User creation failed"
// @Router /users [post]
func (h *AuthHandler) CreateUser(c *gin.Context) {
	// Get the validated request from the middleware context
	req, exists := middleware.GetValidatedRequest[models.CreateUserRequest](c)
	if !exists {
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(pkgerrors.ErrInvalidRequest))
		return
	}

	resp, err := h.authService.CreateUser(c.Request.Context(), &req)
	if err != nil {
		errStr := err.Error()
		if errStr == pkgerrors.ErrEmailAlreadyExists {
			c.JSON(http.StatusConflict, models.NewErrorResponse(errStr))
			return
		}
		if errStr == pkgerrors.ErrUnauthorized {
			c.JSON(http.StatusForbidden, models.NewErrorResponse(errStr))
			return
		}
		if errStr == pkgerrors.ErrInvalidRequest {
			c.JSON(http.StatusBadRequest, models.NewErrorResponse(errStr))
			return
		}
		c.JSON(http.StatusInternalServerError, models.NewErrorResponse(errStr))
		return
	}

	c.JSON(http.StatusCreated, models.NewSuccessResponse(resp))
}

// @Summary Update user information
// @Description Update user details or process pending update requests. Requires admin privileges. Requires permissions/groups system to be initialized (SQLite-based). Approval restrictions: Admins can only approve adding groups they are members of. Admins can only approve adding permissions visible to their groups. If a pending update request includes groups the admin is not in, approval will fail with error. If a pending update request includes permissions the admin cannot see, approval will fail with error. Cannot approve requests that would remove all permissions or all groups. Admins can remove any groups (including the last shared group - this will revoke their access to manage that user).
// @Tags Protected and Admin-Only Routes
// @Accept json
// @Produce json
// @Security SessionCookie
// @Security Bearer
// @Param user_id path string true "Target User ID to update"
// @Param request body models.UpdateUserRequest true "Update details including approve/reject flags for pending requests"
// @Success 200 {object} models.SuccessResponse{data=models.UserResponse} "User updated successfully"
// @Failure 400 {object} models.ErrorResponse "Invalid request"
// @Failure 401 {object} models.ErrorResponse "Unauthorized or admin tried to approve adding groups they're not a member of"
// @Failure 403 {object} models.ErrorResponse "Forbidden - insufficient permissions"
// @Failure 404 {object} models.ErrorResponse "User not found"
// @Failure 409 {object} models.ErrorResponse "User update in progress or concurrent update detected"
// @Failure 500 {object} models.ErrorResponse "Internal server error or permissions system not loaded"
// @Router /users/{user_id} [put]
func (h *AuthHandler) UpdateUser(c *gin.Context) {
	adminID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, models.NewErrorResponse(pkgerrors.ErrUnauthorized))
		return
	}

	userID := c.Param("user_id")

	// Try to acquire lock
	locked, err := h.authService.AcquireUserLock(c.Request.Context(), userID, 30*time.Second)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.NewErrorResponse("Failed to process request"))
		return
	}
	if !locked {
		c.JSON(http.StatusConflict, models.NewErrorResponse("User update in progress"))
		return
	}
	defer h.authService.ReleaseUserLock(c.Request.Context(), userID)

	var req models.UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(pkgerrors.ErrInvalidRequest))
		return
	}

	// Get superuser/admin flags
	isSuperUser := c.GetBool("is_superuser")
	isAdmin := c.GetBool("is_admin")

	// Update user
	if err := h.authService.UpdateUser(
		c.Request.Context(),
		adminID.(string),
		userID,
		&req,
		isSuperUser,
		isAdmin,
	); err != nil {
		if errors.Is(err, repository.ErrConcurrentUpdate) {
			c.JSON(http.StatusConflict, models.NewErrorResponse("User was modified by another request"))
			return
		}
		errStr := err.Error()
		if errStr == pkgerrors.ErrUserNotFound {
			c.JSON(http.StatusNotFound, models.NewErrorResponse(errStr))
			return
		}
		if errStr == pkgerrors.ErrUnauthorized ||
			errStr == pkgerrors.ErrInvalidPermissionRequested ||
			errStr == pkgerrors.ErrInvalidGroupRequested ||
			errStr == pkgerrors.ErrCannotRemoveAllPermissions ||
			errStr == pkgerrors.ErrCannotRemoveAllGroups ||
			errStr == pkgerrors.ErrCannotAddGroupsNotIn {
			c.JSON(http.StatusForbidden, models.NewErrorResponse(errStr))
			return
		}
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(errStr))
		return
	}

	// Fetch and return the updated user
	updatedUser, err := h.authService.GetUser(
		c.Request.Context(),
		adminID.(string),
		userID,
		c.GetBool("is_superuser"),
		c.GetBool("is_admin"),
	)
	if err != nil {
		// If we can't fetch the user, still return success but log the error
		slog.Warn("Failed to fetch updated user after update", "error", err, "user_id", userID)
		c.JSON(http.StatusOK, models.NewSuccessResponse(nil))
		return
	}

	c.JSON(http.StatusOK, models.NewSuccessResponse(updatedUser))
}

// @Summary Change password
// @Description Changes the user's password. No mTLS required for this endpoint.
// @Tags Protected Routes
// @Accept json
// @Produce json
// @Security SessionCookie
// @Security Bearer
// @Param request body models.ChangePasswordRequest true "Change password request"
// @Success 200 {object} models.SuccessResponse "Password changed successfully"
// @Failure 400 {object} models.ErrorResponse "Invalid request format, old password incorrect, or password requirements not met"
// @Failure 401 {object} models.ErrorResponse "Unauthorized or invalid session"
// @Failure 403 {object} models.ErrorResponse "MFA required or invalid MFA code"
// @Failure 404 {object} models.ErrorResponse "User not found"
// @Failure 500 {object} models.ErrorResponse "Operation failed"
// @Router /users/password/change [post]
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, models.NewErrorResponse(pkgerrors.ErrUnauthorized))
		return
	}

	// Get the validated request from the middleware context
	req, exists := middleware.GetValidatedRequest[models.ChangePasswordRequest](c)
	if !exists {
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(pkgerrors.ErrInvalidRequest))
		return
	}

	err := h.authService.ChangePassword(c.Request.Context(), userID.(string), &req)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(err.Error()))
		return
	}

	c.JSON(http.StatusOK, models.NewSuccessResponse("Password changed successfully"))
}

// @Summary Reset password
// @Description Resets the user's password using OTP, and optionally MFA. No mTLS required for this endpoint.
// @Tags Public Routes
// @Accept json
// @Produce json
// @Param request body models.PasswordResetRequest true "Password reset request"
// @Success 200 {object} models.SuccessResponse "Password reset successful but pending admin approval"
// @Failure 400 {object} models.ErrorResponse "Invalid request format, invalid OTP, invalid MFA code, or password requirements not met"
// @Failure 403 {object} models.ErrorResponse "Unauthorized, too many unsuccessful attempts"
// @Failure 404 {object} models.ErrorResponse "User not found"
// @Failure 500 {object} models.ErrorResponse "Operation failed"
// @Router /users/password/reset [post]
func (h *AuthHandler) ResetPassword(c *gin.Context) {
	// Get the validated request from the middleware context
	req, exists := middleware.GetValidatedRequest[models.PasswordResetRequest](c)
	if !exists {
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(pkgerrors.ErrInvalidRequest))
		return
	}

	if err := h.authService.ResetPassword(c.Request.Context(), &req); err != nil {
		errStr := err.Error()
		if errStr == pkgerrors.ErrUserNotFound {
			c.JSON(http.StatusNotFound, models.NewErrorResponse(errStr))
			return
		}
		if errStr == pkgerrors.ErrUnauthorized || errStr == pkgerrors.ErrTooManyAttempts {
			c.JSON(http.StatusForbidden, models.NewErrorResponse(errStr))
			return
		}
		if errStr == pkgerrors.ErrInvalidOTP || errStr == pkgerrors.ErrMFARequired || errStr == pkgerrors.ErrInvalidMFACode {
			c.JSON(http.StatusBadRequest, models.NewErrorResponse(errStr))
			return
		}
		c.JSON(http.StatusInternalServerError, models.NewErrorResponse(errStr))
		return
	}

	c.JSON(http.StatusOK, models.NewSuccessResponse("Password reset successful. Waiting for admin approval."))
}

// @Summary Revoke user sessions
// @Description Revokes all active sessions for a user. Requires permissions/groups system to be initialized (SQLite-based).
// @Tags Protected and Admin-Only Routes
// @Accept json
// @Produce json
// @Security SessionCookie
// @Security Bearer
// @Param request body models.RevokeSessionRequest true "Session revocation request with user ID"
// @Success 200 {object} models.SuccessResponse "Sessions revoked successfully"
// @Failure 400 {object} models.ErrorResponse "Invalid request format"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 403 {object} models.ErrorResponse "Forbidden - insufficient permissions"
// @Failure 500 {object} models.ErrorResponse "Internal server error or permissions system not loaded"
// @Router /sessions/revoke [post]
func (h *AuthHandler) RevokeUserSession(c *gin.Context) {
	adminID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, models.NewErrorResponse(pkgerrors.ErrUnauthorized))
		return
	}

	// Get the validated request from the middleware context
	req, exists := middleware.GetValidatedRequest[models.RevokeSessionRequest](c)
	if !exists {
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(pkgerrors.ErrInvalidRequest))
		return
	}

	err := h.authService.RevokeUserSession(
		c.Request.Context(),
		adminID.(string),
		req.UserID,
		c.GetBool("is_superuser"),
		c.GetBool("is_admin"),
	)
	if err != nil {
		errStr := err.Error()
		if errStr == pkgerrors.ErrUserNotFound {
			c.JSON(http.StatusNotFound, models.NewErrorResponse(errStr))
			return
		}
		if errStr == pkgerrors.ErrUnauthorized {
			c.JSON(http.StatusForbidden, models.NewErrorResponse(errStr))
			return
		}
		c.JSON(http.StatusInternalServerError, models.NewErrorResponse(errStr))
		return
	}

	c.JSON(http.StatusOK, models.NewSuccessResponse(nil))
}

// @Summary Disable MFA
// @Description Disables Multi-Factor Authentication for the authenticated user if not enforced. No mTLS required for this endpoint.
// @Tags Protected Routes
// @Accept json
// @Produce json
// @Security SessionCookie
// @Security Bearer
// @Param request body models.DisableMFARequest true "MFA verification code"
// @Success 200 {object} models.SuccessResponse "MFA disabled successfully"
// @Failure 400 {object} models.ErrorResponse "Invalid MFA code or invalid request format"
// @Failure 401 {object} models.ErrorResponse "Unauthorized or MFA enforced by policy"
// @Failure 404 {object} models.ErrorResponse "User not found"
// @Failure 500 {object} models.ErrorResponse "Operation failed"
// @Router /users/mfa/disable [post]
func (h *AuthHandler) DisableMFA(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, models.NewErrorResponse(pkgerrors.ErrUnauthorized))
		return
	}

	// Get the validated request from the middleware context
	req, exists := middleware.GetValidatedRequest[models.DisableMFARequest](c)
	if !exists {
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(pkgerrors.ErrInvalidRequest))
		return
	}

	err := h.authService.DisableMFA(c.Request.Context(), userID.(string), req.MFACode)
	if err != nil {
		statusCode := http.StatusBadRequest
		if err.Error() == pkgerrors.ErrUnauthorized {
			statusCode = http.StatusUnauthorized
		}
		c.JSON(statusCode, models.NewErrorResponse(err.Error()))
		return
	}

	c.JSON(http.StatusOK, models.NewSuccessResponse(nil))
}

// @Summary Request OTP for password reset
// @Description Sends a one-time password to user's primary email. No mTLS required for this endpoint.
// @Tags Public Routes
// @Accept json
// @Produce json
// @Param request body models.RequestOTPRequest true "Request OTP"
// @Success 200 {object} models.SuccessResponse "OTP sent successfully (or no-op if email doesn't exist)"
// @Failure 400 {object} models.ErrorResponse "Invalid email format or request"
// @Failure 500 {object} models.ErrorResponse "Operation failed"
// @Router /users/password/otp [post]
func (h *AuthHandler) RequestOTP(c *gin.Context) {
	// Get the validated request from the middleware context
	req, exists := middleware.GetValidatedRequest[models.RequestOTPRequest](c)
	if !exists {
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(pkgerrors.ErrInvalidRequest))
		return
	}

	if err := h.authService.SendOTP(c.Request.Context(), req.Email); err != nil {
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(err.Error()))
		return
	}

	c.JSON(http.StatusOK, models.NewSuccessResponse("If the email exists, an OTP has been sent"))
}

// @Summary Get current user information
// @Description Returns the authenticated user's information. Permissions are filtered by visibility - users (both regular users and admins) only see permissions visible to their groups. Superusers see all permissions. No mTLS required for this endpoint.
// @Tags Protected Routes
// @Accept json
// @Produce json
// @Security SessionCookie
// @Security Bearer
// @Success 200 {object} models.SuccessResponse{data=models.UserResponse} "Current user information"
// @Failure 401 {object} models.ErrorResponse "Unauthorized or invalid session"
// @Failure 404 {object} models.ErrorResponse "User not found"
// @Router /users/me [get]
func (h *AuthHandler) GetCurrentUser(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, models.NewErrorResponse(pkgerrors.ErrUnauthorized))
		return
	}

	user, err := h.authService.GetCurrentUser(c.Request.Context(), userID.(string))
	if err != nil {
		errStr := err.Error()
		if errStr == pkgerrors.ErrUserNotFound {
			c.JSON(http.StatusNotFound, models.NewErrorResponse(errStr))
			return
		}
		c.JSON(http.StatusInternalServerError, models.NewErrorResponse(errStr))
		return
	}

	c.JSON(http.StatusOK, models.NewSuccessResponse(user))
}

// @Summary List users
// @Description Returns users with their details and pending requests. Admins see users in their groups, superusers see all. Permission visibility filtering: Regular users only see permissions visible to their groups in their own data. Admins see user's permissions, but filtered to only show permissions visible to the admin's groups. Superusers see all permissions for all users. Requires permissions/groups system to be initialized (SQLite-based).
// @Tags Protected and Admin-Only Routes
// @Accept json
// @Produce json
// @Security SessionCookie
// @Security Bearer
// @Success 200 {object} models.SuccessResponse{data=models.ListUsersResponse} "List of users"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 403 {object} models.ErrorResponse "Forbidden - insufficient permissions"
// @Failure 500 {object} models.ErrorResponse "Internal server error or permissions system not loaded"
// @Router /users [get]
func (h *AuthHandler) ListUsers(c *gin.Context) {
	adminID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, models.NewErrorResponse(pkgerrors.ErrUnauthorized))
		return
	}

	users, err := h.authService.ListUsers(
		c.Request.Context(),
		adminID.(string),
		c.GetBool("is_superuser"),
		c.GetBool("is_admin"),
	)
	if err != nil {
		errStr := err.Error()
		if errStr == pkgerrors.ErrUnauthorized {
			c.JSON(http.StatusForbidden, models.NewErrorResponse(errStr))
			return
		}
		c.JSON(http.StatusInternalServerError, models.NewErrorResponse(errStr))
		return
	}

	c.JSON(http.StatusOK, models.NewSuccessResponse(models.ListUsersResponse{Users: users}))
}

// @Summary Get user details
// @Description Returns details for a specific user. Admins can only access users in their groups. Superuser can access all users. Requires permissions/groups system to be initialized (SQLite-based).
// @Tags Protected and Admin-Only Routes
// @Accept json
// @Produce json
// @Security SessionCookie
// @Security Bearer
// @Param user_id path string true "User ID"
// @Success 200 {object} models.SuccessResponse{data=models.UserResponse} "User information"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 403 {object} models.ErrorResponse "Forbidden - insufficient permissions"
// @Failure 404 {object} models.ErrorResponse "User not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error or permissions system not loaded"
// @Router /users/{user_id} [get]
func (h *AuthHandler) GetUser(c *gin.Context) {
	adminID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, models.NewErrorResponse(pkgerrors.ErrUnauthorized))
		return
	}

	userID := c.Param("user_id")
	user, err := h.authService.GetUser(
		c.Request.Context(),
		adminID.(string),
		userID,
		c.GetBool("is_superuser"),
		c.GetBool("is_admin"),
	)
	if err != nil {
		status := http.StatusUnauthorized
		if err.Error() == pkgerrors.ErrUserNotFound {
			status = http.StatusNotFound
		}
		c.JSON(status, models.NewErrorResponse(err.Error()))
		return
	}

	c.JSON(http.StatusOK, models.NewSuccessResponse(user))
}

// @Summary Request update for user information
// @Description User requests changes from an admin to their permissions or groups. Uses explicit add/remove lists to clearly indicate what changes are being requested. Visibility restrictions: Users can only request permissions visible to at least one of their groups. If a user tries to request a permission not visible to their groups, the request will fail. Users can only remove permissions they currently have. No mTLS required for this endpoint. Request format: permissions_add (array of permission names to add), permissions_remove (array of permission names to remove), groups_add (array of group names to add), groups_remove (array of group names to remove). At least one of these arrays must be non-empty.
// @Tags Protected Routes
// @Accept json
// @Produce json
// @Security SessionCookie
// @Security Bearer
// @Param request body models.RequestUpdateRequest true "Update request with permissions_add, permissions_remove, groups_add, groups_remove arrays"
// @Success 200 {object} models.SuccessResponse "Update request submitted successfully"
// @Failure 400 {object} models.ErrorResponse "Invalid request format or empty update request"
// @Failure 401 {object} models.ErrorResponse "Unauthorized or invalid session"
// @Failure 404 {object} models.ErrorResponse "User not found"
// @Failure 500 {object} models.ErrorResponse "Operation failed"
// @Router /users/request-update-from-admin [post]
func (h *AuthHandler) RequestUpdate(c *gin.Context) {
	// Extract user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, models.NewErrorResponse(pkgerrors.ErrUnauthorized))
		return
	}

	// Try both approaches - middleware validation and direct binding
	var req models.RequestUpdateRequest

	// Check if middleware validation worked
	validatedReq, validationExists := middleware.GetValidatedRequest[models.RequestUpdateRequest](c)
	if validationExists {
		req = validatedReq
	} else {
		// Direct binding
		if err := c.ShouldBindJSON(&req); err != nil {
			slog.Error("Direct binding failed", "error", err)
			c.JSON(http.StatusBadRequest, models.NewErrorResponse(pkgerrors.ErrInvalidRequest))
			return
		}

		// Validate request manually
		if len(req.Updates.PermissionsAdd) == 0 && len(req.Updates.PermissionsRemove) == 0 &&
			len(req.Updates.GroupsAdd) == 0 && len(req.Updates.GroupsRemove) == 0 {
			slog.Error("All permission and group lists are empty - invalid request")
			c.JSON(http.StatusBadRequest, models.NewErrorResponse(pkgerrors.ErrInvalidRequest))
			return
		}
	}

	// Call service
	if err := h.authService.RequestUpdate(c.Request.Context(), userID.(string), &req); err != nil {
		slog.Error("Service RequestUpdate returned error", "error", err)
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(pkgerrors.ErrInvalidRequest))
		return
	}

	// Return success response
	c.JSON(http.StatusOK, models.NewSuccessResponse("Update request submitted successfully"))
}

// @Summary List available permissions
// @Description Returns available permissions. Regular users and admins only see permissions visible to their groups. Superusers see all permissions. Permissions are managed via SQLite database.
// @Tags Protected Routes
// @Produce json
// @Security SessionCookie
// @Security Bearer
// @Success 200 {object} models.SuccessResponse{data=[]models.PermissionResponse} "List of permissions"
// @Router /permissions [get]
func (h *AuthHandler) ListPermissions(c *gin.Context) {
	// Check if permissions system is loaded
	if !service.IsPermissionsLoaded() {
		c.JSON(http.StatusInternalServerError, models.NewErrorResponse("permissions system not loaded"))
		return
	}

	// Get user's groups for visibility filtering
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, models.NewErrorResponse(pkgerrors.ErrUnauthorized))
		return
	}

	user, err := h.authService.GetCurrentUser(c.Request.Context(), userID.(string))
	if err != nil {
		errStr := err.Error()
		if errStr == pkgerrors.ErrUserNotFound {
			c.JSON(http.StatusNotFound, models.NewErrorResponse(errStr))
			return
		}
		c.JSON(http.StatusInternalServerError, models.NewErrorResponse(errStr))
		return
	}

	// Check if user is superuser - only superusers see all permissions
	isSuperuser := c.GetBool("is_superuser")

	var allPerms []models.Permission
	if isSuperuser {
		// Superusers see all permissions
		allPerms = service.GetAllPermissions()
	} else {
		// Regular users and admins only see permissions visible to their groups
		groupNames := service.GetUserGroupNames(user.Groups)
		allPerms = service.GetVisiblePermissions(groupNames)
	}

	// Ensure response is always a slice, not nil
	response := make([]models.PermissionResponse, 0, len(allPerms))
	for _, perm := range allPerms {
		info := service.GetPermissionInfo(perm)
		response = append(response, models.PermissionResponse{
			Key:         string(perm),
			Name:        info.Name,
			Description: info.Description,
		})
	}

	c.JSON(http.StatusOK, models.NewSuccessResponse(response))
}

// @Summary List available groups
// @Description Returns all available groups defined in the system. Groups are managed via SQLite database.
// @Tags Protected Routes
// @Produce json
// @Security SessionCookie
// @Security Bearer
// @Success 200 {object} models.SuccessResponse{data=[]models.GroupResponse} "List of groups"
// @Router /groups [get]
func (h *AuthHandler) ListGroups(c *gin.Context) {
	allGroups := service.GetAllUserGroups()

	response := make([]models.GroupResponse, 0, len(allGroups))
	for _, group := range allGroups {
		info := service.GetGroupInfo(group)
		response = append(response, models.GroupResponse{
			Key:         string(group),
			Name:        info.Name,
			Description: info.Description,
		})
	}

	c.JSON(http.StatusOK, models.NewSuccessResponse(response))
}

// Permission Management Handlers (Superuser Only)

// @Summary Create a new permission
// @Description Creates a new permission in the SQLite database. Only superuser can perform this operation.
// @Tags Superuser Routes
// @Accept json
// @Produce json
// @Security SessionCookie
// @Security Bearer
// @Param request body models.CreatePermissionRequest true "Permission details"
// @Success 201 {object} models.SuccessResponse{data=models.PermissionResponse} "Permission created"
// @Failure 400 {object} models.ErrorResponse "Invalid request format"
// @Failure 401 {object} models.ErrorResponse "Unauthorized - superuser access required"
// @Failure 409 {object} models.ErrorResponse "Permission already exists"
// @Router /admin/permissions [post]
func (h *AuthHandler) CreatePermission(c *gin.Context) {
	var req models.CreatePermissionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(pkgerrors.ErrInvalidRequest))
		return
	}

	permRepo, err := repository.GetPermissionRepository()
	if err != nil {
		slog.Error("Failed to get permission repository", "error", err)
		c.JSON(http.StatusInternalServerError, models.NewErrorResponse(pkgerrors.ErrOperationFailed))
		return
	}

	perm, err := permRepo.CreatePermission(c.Request.Context(), req.Name, req.Definition)
	if err != nil {
		// Check for unique constraint violation
		errStr := err.Error()
		if strings.Contains(errStr, "UNIQUE constraint failed") && strings.Contains(errStr, "permissions.name") {
			c.JSON(http.StatusConflict, models.NewErrorResponse("permission already exists"))
			return
		}
		slog.Error("Failed to create permission", "error", err)
		c.JSON(http.StatusInternalServerError, models.NewErrorResponse(pkgerrors.ErrOperationFailed))
		return
	}

	response := models.PermissionResponse{
		Key:         perm.Name,
		Name:        perm.Name,
		Description: perm.Definition,
	}

	c.JSON(http.StatusCreated, models.NewSuccessResponse(response))
}

// @Summary Update a permission
// @Description Updates a permission's definition. Only superuser can perform this operation.
// @Tags Superuser Routes
// @Accept json
// @Produce json
// @Security SessionCookie
// @Security Bearer
// @Param permission_name path string true "Permission name"
// @Param request body models.UpdatePermissionRequest true "Updated permission definition"
// @Success 200 {object} models.SuccessResponse{data=models.PermissionResponse} "Permission updated"
// @Failure 400 {object} models.ErrorResponse "Invalid request format"
// @Failure 401 {object} models.ErrorResponse "Unauthorized - superuser access required"
// @Failure 404 {object} models.ErrorResponse "Permission not found"
// @Router /admin/permissions/{permission_name} [put]
func (h *AuthHandler) UpdatePermission(c *gin.Context) {
	permissionName := c.Param("permission_name")
	if permissionName == "" {
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(pkgerrors.ErrInvalidRequest))
		return
	}

	var req models.UpdatePermissionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(pkgerrors.ErrInvalidRequest))
		return
	}

	permRepo, err := repository.GetPermissionRepository()
	if err != nil {
		slog.Error("Failed to get permission repository", "error", err)
		c.JSON(http.StatusInternalServerError, models.NewErrorResponse(pkgerrors.ErrOperationFailed))
		return
	}

	// Get permission by name to get ID
	perm, err := permRepo.GetPermissionByName(c.Request.Context(), permissionName)
	if err != nil {
		c.JSON(http.StatusNotFound, models.NewErrorResponse("permission not found"))
		return
	}

	// Update permission
	err = permRepo.UpdatePermission(c.Request.Context(), perm.ID, req.Definition)
	if err != nil {
		if err.Error() == "permission not found" {
			c.JSON(http.StatusNotFound, models.NewErrorResponse("permission not found"))
			return
		}
		slog.Error("Failed to update permission", "error", err)
		c.JSON(http.StatusInternalServerError, models.NewErrorResponse(pkgerrors.ErrOperationFailed))
		return
	}

	response := models.PermissionResponse{
		Key:         perm.Name,
		Name:        perm.Name,
		Description: req.Definition,
	}

	c.JSON(http.StatusOK, models.NewSuccessResponse(response))
}

// @Summary Delete a permission
// @Description Deletes a permission from the SQLite database. This will cascade delete all visibility mappings. Only superuser can perform this operation.
// @Tags Superuser Routes
// @Produce json
// @Security SessionCookie
// @Security Bearer
// @Param permission_name path string true "Permission name"
// @Success 200 {object} models.SuccessResponse{data=object} "Permission deleted"
// @Failure 401 {object} models.ErrorResponse "Unauthorized - superuser access required"
// @Failure 404 {object} models.ErrorResponse "Permission not found"
// @Router /admin/permissions/{permission_name} [delete]
func (h *AuthHandler) DeletePermission(c *gin.Context) {
	permissionName := c.Param("permission_name")
	if permissionName == "" {
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(pkgerrors.ErrInvalidRequest))
		return
	}

	permRepo, err := repository.GetPermissionRepository()
	if err != nil {
		slog.Error("Failed to get permission repository", "error", err)
		c.JSON(http.StatusInternalServerError, models.NewErrorResponse(pkgerrors.ErrOperationFailed))
		return
	}

	// Get permission by name to get ID
	perm, err := permRepo.GetPermissionByName(c.Request.Context(), permissionName)
	if err != nil {
		c.JSON(http.StatusNotFound, models.NewErrorResponse("permission not found"))
		return
	}

	// Delete permission
	err = permRepo.DeletePermission(c.Request.Context(), perm.ID)
	if err != nil {
		if err.Error() == "permission not found" {
			c.JSON(http.StatusNotFound, models.NewErrorResponse("permission not found"))
			return
		}
		slog.Error("Failed to delete permission", "error", err)
		c.JSON(http.StatusInternalServerError, models.NewErrorResponse(pkgerrors.ErrOperationFailed))
		return
	}

	c.JSON(http.StatusOK, models.NewSuccessResponse(map[string]string{"message": "permission deleted successfully"}))
}

// Group Management Handlers (Superuser Only)

// @Summary Create a new group
// @Description Creates a new group in the SQLite database. Only superuser can perform this operation.
// @Tags Superuser Routes
// @Accept json
// @Produce json
// @Security SessionCookie
// @Security Bearer
// @Param request body models.CreateGroupRequest true "Group details"
// @Success 201 {object} models.SuccessResponse{data=models.GroupResponse} "Group created"
// @Failure 400 {object} models.ErrorResponse "Invalid request format"
// @Failure 401 {object} models.ErrorResponse "Unauthorized - superuser access required"
// @Failure 409 {object} models.ErrorResponse "Group already exists"
// @Router /admin/groups [post]
func (h *AuthHandler) CreateGroup(c *gin.Context) {
	var req models.CreateGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(pkgerrors.ErrInvalidRequest))
		return
	}

	permRepo, err := repository.GetPermissionRepository()
	if err != nil {
		slog.Error("Failed to get permission repository", "error", err)
		c.JSON(http.StatusInternalServerError, models.NewErrorResponse(pkgerrors.ErrOperationFailed))
		return
	}

	group, err := permRepo.CreateGroup(c.Request.Context(), req.Name, req.Definition)
	if err != nil {
		// Check for unique constraint violation
		errStr := err.Error()
		if strings.Contains(errStr, "UNIQUE constraint failed") && strings.Contains(errStr, "groups.name") {
			c.JSON(http.StatusConflict, models.NewErrorResponse("group already exists"))
			return
		}
		slog.Error("Failed to create group", "error", err)
		c.JSON(http.StatusInternalServerError, models.NewErrorResponse(pkgerrors.ErrOperationFailed))
		return
	}

	response := models.GroupResponse{
		Key:         group.Name,
		Name:        group.Name,
		Description: group.Definition,
	}

	c.JSON(http.StatusCreated, models.NewSuccessResponse(response))
}

// @Summary Update a group
// @Description Updates a group's definition. Only superuser can perform this operation.
// @Tags Superuser Routes
// @Accept json
// @Produce json
// @Security SessionCookie
// @Security Bearer
// @Param group_name path string true "Group name"
// @Param request body models.UpdateGroupRequest true "Updated group definition"
// @Success 200 {object} models.SuccessResponse{data=models.GroupResponse} "Group updated"
// @Failure 400 {object} models.ErrorResponse "Invalid request format"
// @Failure 401 {object} models.ErrorResponse "Unauthorized - superuser access required"
// @Failure 404 {object} models.ErrorResponse "Group not found"
// @Router /admin/groups/{group_name} [put]
func (h *AuthHandler) UpdateGroup(c *gin.Context) {
	groupName := c.Param("group_name")
	if groupName == "" {
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(pkgerrors.ErrInvalidRequest))
		return
	}

	var req models.UpdateGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(pkgerrors.ErrInvalidRequest))
		return
	}

	permRepo, err := repository.GetPermissionRepository()
	if err != nil {
		slog.Error("Failed to get permission repository", "error", err)
		c.JSON(http.StatusInternalServerError, models.NewErrorResponse(pkgerrors.ErrOperationFailed))
		return
	}

	// Get group by name to get ID
	group, err := permRepo.GetGroupByName(c.Request.Context(), groupName)
	if err != nil {
		c.JSON(http.StatusNotFound, models.NewErrorResponse("group not found"))
		return
	}

	// Update group
	err = permRepo.UpdateGroup(c.Request.Context(), group.ID, req.Definition)
	if err != nil {
		if err.Error() == "group not found" {
			c.JSON(http.StatusNotFound, models.NewErrorResponse("group not found"))
			return
		}
		slog.Error("Failed to update group", "error", err)
		c.JSON(http.StatusInternalServerError, models.NewErrorResponse(pkgerrors.ErrOperationFailed))
		return
	}

	response := models.GroupResponse{
		Key:         group.Name,
		Name:        group.Name,
		Description: req.Definition,
	}

	c.JSON(http.StatusOK, models.NewSuccessResponse(response))
}

// @Summary Delete a group
// @Description Deletes a group from the SQLite database. This will cascade delete all visibility mappings. Only superuser can perform this operation.
// @Tags Superuser Routes
// @Produce json
// @Security SessionCookie
// @Security Bearer
// @Param group_name path string true "Group name"
// @Success 200 {object} models.SuccessResponse{data=object} "Group deleted"
// @Failure 401 {object} models.ErrorResponse "Unauthorized - superuser access required"
// @Failure 404 {object} models.ErrorResponse "Group not found"
// @Router /admin/groups/{group_name} [delete]
func (h *AuthHandler) DeleteGroup(c *gin.Context) {
	groupName := c.Param("group_name")
	if groupName == "" {
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(pkgerrors.ErrInvalidRequest))
		return
	}

	permRepo, err := repository.GetPermissionRepository()
	if err != nil {
		slog.Error("Failed to get permission repository", "error", err)
		c.JSON(http.StatusInternalServerError, models.NewErrorResponse(pkgerrors.ErrOperationFailed))
		return
	}

	// Get group by name to get ID
	group, err := permRepo.GetGroupByName(c.Request.Context(), groupName)
	if err != nil {
		c.JSON(http.StatusNotFound, models.NewErrorResponse("group not found"))
		return
	}

	// Delete group
	err = permRepo.DeleteGroup(c.Request.Context(), group.ID)
	if err != nil {
		if err.Error() == "group not found" {
			c.JSON(http.StatusNotFound, models.NewErrorResponse("group not found"))
			return
		}
		slog.Error("Failed to delete group", "error", err)
		c.JSON(http.StatusInternalServerError, models.NewErrorResponse(pkgerrors.ErrOperationFailed))
		return
	}

	c.JSON(http.StatusOK, models.NewSuccessResponse(map[string]string{"message": "group deleted successfully"}))
}

// Permission Visibility Management Handlers (Superuser Only)

// @Summary Add permission visibility to a group
// @Description Makes a permission visible to a specific group. Only superuser can perform this operation.
// @Tags Superuser Routes
// @Accept json
// @Produce json
// @Security SessionCookie
// @Security Bearer
// @Param request body models.AddPermissionVisibilityRequest true "Permission and group names"
// @Success 201 {object} models.SuccessResponse{data=object} "Visibility mapping added"
// @Failure 400 {object} models.ErrorResponse "Invalid request format"
// @Failure 401 {object} models.ErrorResponse "Unauthorized - superuser access required"
// @Failure 404 {object} models.ErrorResponse "Permission or group not found"
// @Failure 409 {object} models.ErrorResponse "Visibility mapping already exists"
// @Router /admin/permissions/visibility [post]
func (h *AuthHandler) AddPermissionVisibility(c *gin.Context) {
	var req models.AddPermissionVisibilityRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(pkgerrors.ErrInvalidRequest))
		return
	}

	permRepo, err := repository.GetPermissionRepository()
	if err != nil {
		slog.Error("Failed to get permission repository", "error", err)
		c.JSON(http.StatusInternalServerError, models.NewErrorResponse(pkgerrors.ErrOperationFailed))
		return
	}

	// Get permission by name
	perm, err := permRepo.GetPermissionByName(c.Request.Context(), req.PermissionName)
	if err != nil {
		c.JSON(http.StatusNotFound, models.NewErrorResponse("permission not found"))
		return
	}

	// Get group by name
	group, err := permRepo.GetGroupByName(c.Request.Context(), req.GroupName)
	if err != nil {
		c.JSON(http.StatusNotFound, models.NewErrorResponse("group not found"))
		return
	}

	// Add visibility mapping
	err = permRepo.AddPermissionVisibility(c.Request.Context(), perm.ID, group.ID)
	if err != nil {
		// Check for unique constraint violation
		errStr := err.Error()
		if strings.Contains(errStr, "UNIQUE constraint failed") && strings.Contains(errStr, "permission_visibility") {
			c.JSON(http.StatusConflict, models.NewErrorResponse("visibility mapping already exists"))
			return
		}
		slog.Error("Failed to add permission visibility", "error", err)
		c.JSON(http.StatusInternalServerError, models.NewErrorResponse(pkgerrors.ErrOperationFailed))
		return
	}

	c.JSON(http.StatusCreated, models.NewSuccessResponse(map[string]string{
		"message": "permission visibility added successfully",
	}))
}

// @Summary Remove permission visibility from a group
// @Description Removes a permission's visibility from a specific group. Only superuser can perform this operation.
// @Tags Superuser Routes
// @Accept json
// @Produce json
// @Security SessionCookie
// @Security Bearer
// @Param request body models.RemovePermissionVisibilityRequest true "Permission and group names"
// @Success 200 {object} models.SuccessResponse{data=object} "Visibility mapping removed"
// @Failure 400 {object} models.ErrorResponse "Invalid request format"
// @Failure 401 {object} models.ErrorResponse "Unauthorized - superuser access required"
// @Failure 404 {object} models.ErrorResponse "Permission, group, or visibility mapping not found"
// @Router /admin/permissions/visibility [delete]
func (h *AuthHandler) RemovePermissionVisibility(c *gin.Context) {
	var req models.RemovePermissionVisibilityRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(pkgerrors.ErrInvalidRequest))
		return
	}

	permRepo, err := repository.GetPermissionRepository()
	if err != nil {
		slog.Error("Failed to get permission repository", "error", err)
		c.JSON(http.StatusInternalServerError, models.NewErrorResponse(pkgerrors.ErrOperationFailed))
		return
	}

	// Get permission by name
	perm, err := permRepo.GetPermissionByName(c.Request.Context(), req.PermissionName)
	if err != nil {
		c.JSON(http.StatusNotFound, models.NewErrorResponse("permission not found"))
		return
	}

	// Get group by name
	group, err := permRepo.GetGroupByName(c.Request.Context(), req.GroupName)
	if err != nil {
		c.JSON(http.StatusNotFound, models.NewErrorResponse("group not found"))
		return
	}

	// Remove visibility mapping
	err = permRepo.RemovePermissionVisibility(c.Request.Context(), perm.ID, group.ID)
	if err != nil {
		if err.Error() == "permission visibility mapping not found" {
			c.JSON(http.StatusNotFound, models.NewErrorResponse("visibility mapping not found"))
			return
		}
		slog.Error("Failed to remove permission visibility", "error", err)
		c.JSON(http.StatusInternalServerError, models.NewErrorResponse(pkgerrors.ErrOperationFailed))
		return
	}

	c.JSON(http.StatusOK, models.NewSuccessResponse(map[string]string{
		"message": "permission visibility removed successfully",
	}))
}
