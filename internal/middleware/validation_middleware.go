package middleware

import (
	"bytes"
	"fmt"
	"garde/internal/models"
	"garde/internal/service"
	"garde/pkg/errors"
	"garde/pkg/validation"
	"io"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
)

const (
	ContextKeyValidatedRequest = "validatedRequest"
	ContextKeyValidationFailed = "validationFailed"
)

// Handles input validation and sanitization for all endpoints.
// Validated requests are stored in the context with key "validatedRequest" and can be retrieved
// in handlers using:
//
//	if req, exists := c.Get("validatedRequest"); exists {
//	    validatedReq := req.(models.SomeRequest)
//	    // Use validatedReq...
//	}
func ValidateRequestParameters() gin.HandlerFunc {
	return func(c *gin.Context) {

		// Validate context first
		if err := validateContext(c); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, models.NewErrorResponse(err.Error()))
			return
		}

		// Validate path parameters
		if err := validatePathParams(c); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, models.NewErrorResponse(err.Error()))
			return
		}

		// Then validate headers and query params
		if err := validateHeaders(c); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, models.NewErrorResponse(err.Error()))
			return
		}

		if err := validateQueryParams(c); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, models.NewErrorResponse(err.Error()))
			return
		}

		// Finally validate request body
		if c.Request.Body != nil {
			switch c.FullPath() {
			case "/login":
				handleRequestValidation(c, &models.LoginRequest{}, validateLoginRequest)
			case "/users":
				// Only attempt JSON binding for POST requests to /users
				if c.Request.Method == "POST" {
					handleRequestValidation(c, &models.CreateUserRequest{}, validateCreateUserRequest)
				}
			case "/users/mfa/verify":
				handleRequestValidation(c, &models.MFAVerifyRequest{}, validateMFARequest)
			case "/users/password/change":
				handleRequestValidation(c, &models.ChangePasswordRequest{}, validateChangePasswordRequest)
			case "/users/password/reset":
				handleRequestValidation(c, &models.PasswordResetRequest{}, validatePasswordResetRequest)
			case "/users/password/otp":
				handleRequestValidation(c, &models.RequestOTPRequest{}, validateOTPRequest)
			case "/users/mfa/setup":
				handleRequestValidation(c, &models.MFASetupRequest{}, validateMFASetupRequest)
			case "/users/mfa/disable":
				handleRequestValidation(c, &models.DisableMFARequest{}, validateDisableMFARequest)
			case "/sessions/revoke":
				handleRequestValidation(c, &models.RevokeSessionRequest{}, validateRevokeSessionRequest)
			case "/users/request-update-from-admin":
				slog.Debug("Validating request update from admin")
				handleRequestValidation(c, &models.RequestUpdateRequest{}, validateUpdateRequest)
			default:
				slog.Debug("Path not matched in validation middleware",
					"path", c.Request.URL.Path,
					"full_path", c.FullPath())

				// Special case for request-update-from-admin
				if c.Request.URL.Path == "/users/request-update-from-admin" {
					slog.Debug("Detected request-update-from-admin via URL path")
					handleRequestValidation(c, &models.RequestUpdateRequest{}, validateUpdateRequest)
				} else if c.Request.Method == "PUT" && c.Param("user_id") != "" {
					handleRequestValidation(c, &models.UpdateUserRequest{}, validateUpdateUserRequest)
				}
			}
		}

		c.Next()
	}
}

func handleRequestValidation[T any](c *gin.Context, req *T, validator func(*T) error) {

	bodyBytes, err := c.GetRawData()
	if err != nil {
		slog.Warn("Failed to read request body", "error", err, "path", c.Request.URL.Path)
		c.Set(ContextKeyValidationFailed, true)
		c.AbortWithStatusJSON(http.StatusBadRequest, models.NewErrorResponse(errors.ErrInvalidRequest))
		return
	}

	// Restore the body for binding
	c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	// Bind JSON
	if err := c.ShouldBindJSON(req); err != nil {
		slog.Debug("JSON binding failed", "path", c.Request.URL.Path, "error", err)
		c.Set(ContextKeyValidationFailed, true)
		c.AbortWithStatusJSON(http.StatusBadRequest, models.NewErrorResponse(errors.ErrInvalidRequest))
		return
	}

	if err := validator(req); err != nil {
		slog.Debug("Validation failed", "error", err, "path", c.Request.URL.Path)
		c.Set(ContextKeyValidationFailed, true)
		c.AbortWithStatusJSON(http.StatusBadRequest, models.NewErrorResponse(err.Error()))
		return
	}

	// Set the validated request in the context
	c.Set(ContextKeyValidatedRequest, *req)

	// Restore the body again for the handler
	c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
}

func validateLoginRequest(req *models.LoginRequest) error {
	if err := validation.ValidateEmail(req.Email); err != nil {
		return fmt.Errorf("email validation failed: %w", err)
	}
	if err := validation.ValidatePassword(req.Password); err != nil {
		return fmt.Errorf("password validation failed: %w", err)
	}
	if req.MFACode != "" {
		sanitized, err := validation.Sanitize(req.MFACode)
		if err != nil {
			slog.Debug("MFA code sanitization failed", "error", err)
			return err
		}
		req.MFACode = sanitized
	}
	return nil
}

func validateCreateUserRequest(req *models.CreateUserRequest) error {
	if err := validation.ValidateEmail(req.Email); err != nil {
		slog.Debug("Email validation failed", "error", err)
		return err
	}
	if err := validation.ValidatePassword(req.Password); err != nil {
		slog.Debug("Password validation failed", "error", err)
		return err
	}
	return nil
}

func validateMFARequest(req *models.MFAVerifyRequest) error {
	if req.Email != "" {
		if err := validation.ValidateEmail(req.Email); err != nil {
			return err
		}
	}
	sanitized, err := validation.Sanitize(req.Code)
	if err != nil {
		return err
	}
	req.Code = sanitized
	return nil
}

func validateChangePasswordRequest(req *models.ChangePasswordRequest) error {
	if err := validation.ValidatePassword(req.OldPassword); err != nil {
		return err
	}
	if err := validation.ValidatePassword(req.NewPassword); err != nil {
		return err
	}
	if req.MFACode != "" {
		if err := validation.ValidateMFACode(req.MFACode); err != nil {
			return err
		}
		sanitized, err := validation.Sanitize(req.MFACode)
		if err != nil {
			return err
		}
		req.MFACode = sanitized
	}
	return nil
}

func validatePasswordResetRequest(req *models.PasswordResetRequest) error {
	if err := validation.ValidateEmail(req.Email); err != nil {
		return err
	}
	if err := validation.ValidatePassword(req.NewPassword); err != nil {
		return err
	}
	sanitized, err := validation.Sanitize(req.OTP)
	if err != nil {
		return err
	}
	req.OTP = sanitized
	return nil
}

func validateOTPRequest(req *models.RequestOTPRequest) error {
	return validation.ValidateEmail(req.Email)
}

func validateMFASetupRequest(req *models.MFASetupRequest) error {
	if req.Email != "" {
		return validation.ValidateEmail(req.Email)
	}
	return nil
}

func validateDisableMFARequest(req *models.DisableMFARequest) error {
	sanitized, err := validation.Sanitize(req.MFACode)
	if err != nil {
		return err
	}
	req.MFACode = sanitized
	return nil
}

func validateRevokeSessionRequest(req *models.RevokeSessionRequest) error {
	userID, err := validation.Sanitize(req.UserID)
	if err != nil {
		return err
	}
	req.UserID = userID

	if req.MFACode != "" {
		if err := validation.ValidateMFACode(req.MFACode); err != nil {
			return err
		}
		sanitized, err := validation.Sanitize(req.MFACode)
		if err != nil {
			return err
		}
		req.MFACode = sanitized
	}
	return nil
}

func validateUpdateRequest(req *models.RequestUpdateRequest) error {

	// Check if at least one change is requested
	if len(req.Updates.PermissionsAdd) == 0 && len(req.Updates.PermissionsRemove) == 0 &&
		len(req.Updates.GroupsAdd) == 0 && len(req.Updates.GroupsRemove) == 0 {
		slog.Debug("All permission and group lists are empty - invalid request")
		return fmt.Errorf(errors.ErrInvalidRequest)
	}

	// Validate permissions if provided and permissions system is loaded
	if len(req.Updates.PermissionsAdd) > 0 || len(req.Updates.PermissionsRemove) > 0 {
		if !service.IsPermissionsLoaded() {
			slog.Debug("Permissions system is not loaded")
			return fmt.Errorf(errors.ErrPermissionsNotLoaded)
		}

		// Get all valid permissions
		validPermissions := service.GetAllPermissions()
		permissionSet := make(map[models.Permission]bool)
		for _, p := range validPermissions {
			permissionSet[p] = true
		}

		slog.Debug("Permissions system is loaded, checking permissions")
		// Validate permissions to add
		for _, permStr := range req.Updates.PermissionsAdd {
			perm := models.Permission(permStr)
			if !permissionSet[perm] {
				slog.Debug("Invalid permission requested to add", "permission", permStr)
				return fmt.Errorf(errors.ErrInvalidPermissionRequested + ": " + permStr)
			}
		}
		// Validate permissions to remove
		for _, permStr := range req.Updates.PermissionsRemove {
			perm := models.Permission(permStr)
			if !permissionSet[perm] {
				slog.Debug("Invalid permission requested to remove", "permission", permStr)
				return fmt.Errorf(errors.ErrInvalidPermissionRequested + ": " + permStr)
			}
		}
		slog.Debug("Permissions validation successful")
	} else {
		slog.Debug("No permissions provided in update request")
	}

	// Validate groups if provided and groups system is loaded
	if len(req.Updates.GroupsAdd) > 0 || len(req.Updates.GroupsRemove) > 0 {
		if !service.IsGroupsLoaded() {
			slog.Debug("Groups system is not loaded")
			return fmt.Errorf(errors.ErrGroupsNotLoaded)
		}

		// Get all valid groups
		validGroups := service.GetAllUserGroups()
		groupSet := make(map[models.UserGroup]bool)
		for _, g := range validGroups {
			groupSet[g] = true
		}

		slog.Debug("Groups system is loaded, checking group info")
		// Validate groups to add
		for _, groupStr := range req.Updates.GroupsAdd {
			group := models.UserGroup(groupStr)
			if !groupSet[group] {
				slog.Debug("Invalid group requested to add", "group", groupStr)
				return fmt.Errorf(errors.ErrInvalidGroupRequested + ": " + groupStr)
			}
		}
		// Validate groups to remove
		for _, groupStr := range req.Updates.GroupsRemove {
			group := models.UserGroup(groupStr)
			if !groupSet[group] {
				slog.Debug("Invalid group requested to remove", "group", groupStr)
				return fmt.Errorf(errors.ErrInvalidGroupRequested + ": " + groupStr)
			}
		}
		slog.Debug("Groups validation successful")
	} else {
		slog.Debug("No groups provided in update request")
	}

	return nil
}

func validateUpdateUserRequest(req *models.UpdateUserRequest) error {
	// Check if both Permissions and Groups are nil AND neither ApproveUpdate nor RejectUpdate is true
	if req.Permissions == nil && req.Groups == nil &&
		req.Status == nil && req.MFAEnforced == nil &&
		!req.ApproveUpdate && !req.RejectUpdate {
		slog.Debug("No update parameters provided - invalid request")
		return fmt.Errorf(errors.ErrInvalidRequest)
	}

	// Validate permissions if provided and permissions system is loaded
	if req.Permissions != nil && len(*req.Permissions) > 0 {
		slog.Debug("Validating permissions", "count", len(*req.Permissions))

		if !service.IsPermissionsLoaded() {
			slog.Debug("Permissions system is not loaded")
			return fmt.Errorf(errors.ErrPermissionsNotLoaded)
		}

		// Get all valid permissions
		validPermissions := service.GetAllPermissions()
		permissionSet := make(map[models.Permission]bool)
		for _, p := range validPermissions {
			permissionSet[p] = true
		}

		slog.Debug("Permissions system is loaded, checking permissions")
		for permStr := range *req.Permissions {
			perm := models.Permission(permStr)

			// Check if permission exists in our loaded permissions
			if !permissionSet[perm] {
				slog.Debug("Invalid permission requested", "permission", string(perm))
				return fmt.Errorf(errors.ErrInvalidPermissionRequested+": %s", string(perm))
			}
		}
		slog.Debug("Permissions validation successful")
	} else {
		slog.Debug("No permissions provided in update user request")
	}

	// Group existence validation happens here, but authorization checks
	// (e.g., whether user can assign groups) happen in the service layer
	if req.Groups != nil && len(*req.Groups) > 0 {
		slog.Debug("Validating groups", "count", len(*req.Groups))

		if !service.IsGroupsLoaded() {
			slog.Debug("Groups system is not loaded")
			return fmt.Errorf(errors.ErrGroupsNotLoaded)
		}

		// Get all valid groups
		validGroups := service.GetAllUserGroups()
		groupSet := make(map[models.UserGroup]bool)
		for _, g := range validGroups {
			groupSet[g] = true
		}

		for groupStr := range *req.Groups {
			group := models.UserGroup(groupStr)

			// Check if group exists in our loaded groups
			if !groupSet[group] {
				slog.Debug("Invalid group requested", "group", string(group))
				return fmt.Errorf(errors.ErrInvalidGroupRequested+": %s", string(group))
			}
		}
	} else {
		slog.Debug("No groups provided in update user request")
	}

	return nil
}

func GetValidatedRequest[T any](c *gin.Context) (T, bool) { // Safely retrieves and type-asserts the validated request from context
	val, exists := c.Get(ContextKeyValidatedRequest)
	if !exists {
		var zero T
		return zero, false
	}
	req, ok := val.(T)
	return req, ok
}

func validateContext(c *gin.Context) error {
	if c.Request == nil || c.Request.Context() == nil {
		return fmt.Errorf(errors.ErrInvalidRequest)
	}
	return nil
}

func validatePathParams(c *gin.Context) error {
	for i, param := range c.Params {
		sanitized, err := validation.Sanitize(param.Value)
		if err != nil {
			return fmt.Errorf("%s: %s", errors.ErrInvalidRequest, param.Key)
		}
		c.Params[i].Value = sanitized
	}
	return nil
}

func validateHeaders(c *gin.Context) error {
	headers := make(http.Header)
	for key, values := range c.Request.Header {
		sanitizedValues := make([]string, len(values))
		for i, value := range values {
			sanitized, err := validation.Sanitize(value)
			if err != nil {
				return err
			}
			sanitizedValues[i] = sanitized
		}
		headers[key] = sanitizedValues
	}
	c.Request.Header = headers
	return nil
}

func validateQueryParams(c *gin.Context) error {
	q := c.Request.URL.Query()
	for key, values := range q {
		for i, value := range values {
			sanitized, err := validation.Sanitize(value)
			if err != nil {
				return err
			}
			values[i] = sanitized
		}
		q[key] = values
	}
	c.Request.URL.RawQuery = q.Encode()
	return nil
}
