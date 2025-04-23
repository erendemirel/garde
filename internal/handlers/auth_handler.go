package handlers

import (
	"garde/internal/middleware"
	"garde/internal/models"
	"garde/internal/service"
	"garde/pkg/errors"
	"garde/pkg/session"
	"garde/pkg/validation"
	"log/slog"
	"net/http"
	"os"
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
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(errors.ErrInvalidRequest))
		return
	}

	resp, err := h.authService.Login(c.Request.Context(), &req, c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		c.JSON(http.StatusUnauthorized, models.NewErrorResponse(err.Error()))
		return
	}

	cookieDomain := os.Getenv("DOMAIN_NAME")

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
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(errors.ErrNoActiveSession))
		return
	}

	err = h.authService.Logout(c.Request.Context(), sessionID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.NewErrorResponse("Internal server error"))
		return
	}

	cookieDomain := os.Getenv("DOMAIN_NAME")

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
// @Success 200 {object} models.SuccessResponse{data=models.SessionValidationResponse} "Session validation result with user ID and expiry"
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
			c.JSON(http.StatusBadRequest, models.NewErrorResponse(errors.ErrInvalidRequest))
			return
		}

		if err := validation.ValidateSessionID(sessionID); err != nil {
			c.JSON(http.StatusBadRequest, models.NewErrorResponse(errors.ErrInvalidRequest))
			return
		}

		resp, err := h.authService.ValidateSession(
			c.Request.Context(),
			sessionID,
			c.ClientIP(),
			c.Request.UserAgent(),
		)
		if err != nil || resp == nil || !resp.Response.Valid {
			c.JSON(http.StatusUnauthorized, models.NewErrorResponse(errors.ErrSessionInvalid))
			return
		}

		c.JSON(http.StatusOK, models.NewSuccessResponse(resp))
		return
	}

	// Regular validation flow(for admin, without API key)
	sessionID, exists := c.Get("session_id")
	if !exists || sessionID == nil {
		c.JSON(http.StatusUnauthorized, models.NewErrorResponse(errors.ErrSessionInvalid))
		return
	}

	sessionIDStr, ok := sessionID.(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, models.NewErrorResponse(errors.ErrOperationFailed))
		return
	}

	resp, err := h.authService.ValidateSession(
		c.Request.Context(),
		sessionIDStr,
		c.ClientIP(),
		c.Request.UserAgent(),
	)
	if err != nil || resp == nil || !resp.Response.Valid {
		c.JSON(http.StatusUnauthorized, models.NewErrorResponse(errors.ErrSessionInvalid))
		return
	}

	c.JSON(http.StatusOK, models.NewSuccessResponse(resp))
}

// @Summary Setup MFA
// @Description Sets up Multi-Factor Authentication for a user. No mTLS required for this endpoint. Uses ConditionalAuthMiddleware to allow both authenticated and unauthenticated access.
// @Tags Conditional Routes (Public or Protected)
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
		c.JSON(http.StatusUnauthorized, models.NewErrorResponse(errors.ErrUnauthorized))
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
// @Description Verifies MFA code and enables MFA for the user. No mTLS required for this endpoint. Uses ConditionalAuthMiddleware to allow both authenticated and unauthenticated access.
// @Tags Conditional Routes (Public or Protected)
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
		c.JSON(http.StatusUnauthorized, models.NewErrorResponse(errors.ErrUnauthorized))
		return
	}

	// Get the validated request from the middleware context
	req, exists := middleware.GetValidatedRequest[models.MFAVerifyRequest](c)
	if !exists {
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(errors.ErrInvalidRequest))
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
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(errors.ErrInvalidRequest))
		return
	}

	resp, err := h.authService.CreateUser(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(err.Error()))
		return
	}

	c.JSON(http.StatusCreated, resp)
}

// @Summary Update user information
// @Description Update user details or process pending update requests. Requires admin privileges. Requires permissions.json and groups.json files to be present for permission checks (except for superuser).
// @Tags Protected and Admin-Only Routes
// @Accept json
// @Produce json
// @Security SessionCookie
// @Security Bearer
// @Param user_id path string true "Target User ID to update"
// @Param request body models.UpdateUserRequest true "Update details including approve/reject flags for pending requests"
// @Success 200 {object} models.SuccessResponse "User updated successfully"
// @Failure 400 {object} models.ErrorResponse "Invalid request"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 403 {object} models.ErrorResponse "Forbidden - insufficient permissions"
// @Failure 404 {object} models.ErrorResponse "User not found"
// @Failure 409 {object} models.ErrorResponse "User update in progress or concurrent update detected"
// @Failure 500 {object} models.ErrorResponse "Internal server error or permissions system not loaded"
// @Router /users/{user_id} [put]
func (h *AuthHandler) UpdateUser(c *gin.Context) {
	adminID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, models.NewErrorResponse(errors.ErrUnauthorized))
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
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(errors.ErrInvalidRequest))
		return
	}

	// Update user
	if err := h.authService.UpdateUser(
		c.Request.Context(),
		adminID.(string),
		userID,
		&req,
		c.GetBool("is_superuser"),
		c.GetBool("is_admin"),
	); err != nil {
		if err.Error() == "concurrent update detected" {
			c.JSON(http.StatusConflict, models.NewErrorResponse("User was modified by another request"))
			return
		}
		c.JSON(http.StatusUnauthorized, models.NewErrorResponse(err.Error()))
		return
	}

	c.JSON(http.StatusOK, models.NewSuccessResponse(nil))
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
		c.JSON(http.StatusUnauthorized, models.NewErrorResponse(errors.ErrUnauthorized))
		return
	}

	// Get the validated request from the middleware context
	req, exists := middleware.GetValidatedRequest[models.ChangePasswordRequest](c)
	if !exists {
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(errors.ErrInvalidRequest))
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
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(errors.ErrInvalidRequest))
		return
	}

	if err := h.authService.ResetPassword(c.Request.Context(), &req); err != nil {
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(err.Error()))
		return
	}

	c.JSON(http.StatusOK, models.NewSuccessResponse("Password reset successful. Waiting for admin approval."))
}

// @Summary Revoke user sessions
// @Description Revokes all active sessions for a user. Requires permissions.json and groups.json files to be present for permission checks (except for superuser).
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
		c.JSON(http.StatusUnauthorized, models.NewErrorResponse(errors.ErrUnauthorized))
		return
	}

	// Get the validated request from the middleware context
	req, exists := middleware.GetValidatedRequest[models.RevokeSessionRequest](c)
	if !exists {
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(errors.ErrInvalidRequest))
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
		c.JSON(http.StatusUnauthorized, models.NewErrorResponse(err.Error()))
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
		c.JSON(http.StatusUnauthorized, models.NewErrorResponse(errors.ErrUnauthorized))
		return
	}

	// Get the validated request from the middleware context
	req, exists := middleware.GetValidatedRequest[models.DisableMFARequest](c)
	if !exists {
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(errors.ErrInvalidRequest))
		return
	}

	err := h.authService.DisableMFA(c.Request.Context(), userID.(string), req.MFACode)
	if err != nil {
		statusCode := http.StatusBadRequest
		if err.Error() == errors.ErrUnauthorized {
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
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(errors.ErrInvalidRequest))
		return
	}

	if err := h.authService.SendOTP(c.Request.Context(), req.Email); err != nil {
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(err.Error()))
		return
	}

	c.JSON(http.StatusOK, models.NewSuccessResponse("If the email exists, an OTP has been sent"))
}

// @Summary Get current user information
// @Description Returns the authenticated user's information. No mTLS required for this endpoint.
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
		c.JSON(http.StatusUnauthorized, models.NewErrorResponse(errors.ErrUnauthorized))
		return
	}

	user, err := h.authService.GetCurrentUser(c.Request.Context(), userID.(string))
	if err != nil {
		c.JSON(http.StatusUnauthorized, models.NewErrorResponse(err.Error()))
		return
	}

	c.JSON(http.StatusOK, models.NewSuccessResponse(user))
}

// @Summary List users
// @Description Returns users with their details and pending requests. Admins see users in their groups, superusers see all. Requires permissions.json and groups.json files to be present for permission checks (except for superuser).
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
		c.JSON(http.StatusUnauthorized, models.NewErrorResponse(errors.ErrUnauthorized))
		return
	}

	users, err := h.authService.ListUsers(c.Request.Context(), adminID.(string))
	if err != nil {
		c.JSON(http.StatusUnauthorized, models.NewErrorResponse(err.Error()))
		return
	}

	c.JSON(http.StatusOK, models.NewSuccessResponse(models.ListUsersResponse{Users: users}))
}

// @Summary Get user details
// @Description Returns details for a specific user. Admins can only access users in their groups. Superuser can access all users. Requires permissions.json and groups.json files to be present for permission checks (except for superuser).
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
		c.JSON(http.StatusUnauthorized, models.NewErrorResponse(errors.ErrUnauthorized))
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
		if err.Error() == errors.ErrUserNotFound {
			status = http.StatusNotFound
		}
		c.JSON(status, models.NewErrorResponse(err.Error()))
		return
	}

	c.JSON(http.StatusOK, models.NewSuccessResponse(user))
}

// @Summary Request update for user information
// @Description User requests changes from an admin to their permissions or groups. No mTLS required for this endpoint.
// @Tags Protected Routes
// @Accept json
// @Produce json
// @Security SessionCookie
// @Security Bearer
// @Param request body models.RequestUpdateRequest true "Update request details (permissions/groups)"
// @Success 200 {object} models.SuccessResponse "Update request submitted successfully"
// @Failure 400 {object} models.ErrorResponse "Invalid request format or empty update request"
// @Failure 401 {object} models.ErrorResponse "Unauthorized or invalid session"
// @Failure 404 {object} models.ErrorResponse "User not found"
// @Failure 409 {object} models.ErrorResponse "Update request already pending"
// @Failure 500 {object} models.ErrorResponse "Operation failed"
// @Router /users/request-update-from-admin [post]
func (h *AuthHandler) RequestUpdate(c *gin.Context) {
	// Extract user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, models.NewErrorResponse(errors.ErrUnauthorized))
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
			c.JSON(http.StatusBadRequest, models.NewErrorResponse(errors.ErrInvalidRequest))
			return
		}

		// Validate request manually
		if req.Updates.Permissions == nil && req.Updates.Groups == nil {
			slog.Error("Both Permissions and Groups are nil - invalid request")
			c.JSON(http.StatusBadRequest, models.NewErrorResponse(errors.ErrInvalidRequest))
			return
		}
	}

	// Call service
	if err := h.authService.RequestUpdate(c.Request.Context(), userID.(string), &req); err != nil {
		slog.Error("Service RequestUpdate returned error", "error", err)
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(errors.ErrInvalidRequest))
		return
	}

	// Return success response
	c.JSON(http.StatusOK, models.NewSuccessResponse("Update request submitted successfully"))
}
