package middleware

import (
	"log/slog"
	"net/http"
	"slices"

	"garde/internal/models"
	"garde/pkg/errors"

	"github.com/gin-gonic/gin"
)

// Set by AuthMiddleware for an authenticated admin, from the operator-managed
// ADMIN_SCOPES_JSON secret. Unexported because nothing outside this package
// needs them yet; widening that is a one-line change if a response ever wants
// to report an admin's scopes.
const (
	contextAdminScopes         = "admin_scopes"
	contextAdminScopesEnforced = "admin_scopes_enforced"
)

// RequireAdminScope gates one route on one scope.
//
// It is mounted per route rather than on the admin group, because the point is
// to tell the routes in that group apart: read, update, delete and session
// revocation are one bundle today, and an admin who may do any of them may do
// all of them.
//
// The gate is additive. AdminMiddleware still decides who is an admin at all,
// and the is_admin flag still drives the filtering decisions inside the
// handlers, which answer a different question — this one answers whether the
// operation is available, not which records it may touch.
func RequireAdminScope(scope string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// The superuser holds every scope. Restricting the single account
		// that provisions admins in the first place would only ever be
		// theatre.
		if c.GetBool("is_superuser") {
			c.Next()
			return
		}

		// AdminMiddleware has already run on every route this is mounted on.
		// Repeating the check means the scope gate cannot be mounted
		// somewhere it would silently wave a non-admin through.
		if !c.GetBool("is_admin") {
			userID, _ := c.Get("user_id")
			slog.Info("Scoped admin route reached by a non-admin", "user_id", userID, "path", c.Request.URL.Path)
			c.AbortWithStatusJSON(http.StatusUnauthorized, models.NewErrorResponse(errors.ErrUnauthorized))
			return
		}

		// No entry in ADMIN_SCOPES_JSON means no restriction, which is the
		// access this admin had before scopes existed. Restricting is opt-in
		// per admin so that introducing the secret cannot lock out everyone
		// who is not listed in it yet.
		if !c.GetBool(contextAdminScopesEnforced) {
			c.Next()
			return
		}

		held, _ := c.Get(contextAdminScopes)
		scopes, _ := held.([]string)
		if !slices.Contains(scopes, scope) {
			userID, _ := c.Get("user_id")
			slog.Warn("Admin lacks the scope this route requires",
				"user_id", userID, "path", c.Request.URL.Path, "required_scope", scope)
			c.AbortWithStatusJSON(http.StatusForbidden, models.NewErrorResponse(errors.ErrAdminScopeNotPermitted))
			return
		}

		c.Next()
	}
}
