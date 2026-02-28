package middleware

import (
	"garde/internal/models"
	pkgerrors "garde/pkg/errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func LimitBodySize(maxSize int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Reject up front when Content-Length exceeds limit so we always return 413 with a clear message
		if c.Request.ContentLength > maxSize {
			slog.Warn("Request body too large (Content-Length)", "path", c.Request.URL.Path, "ip", c.ClientIP(), "content_length", c.Request.ContentLength, "max_size", maxSize)
			c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge,
				models.NewErrorResponse(pkgerrors.ErrRequestTooLarge))
			return
		}

		if c.Request.ContentLength > 0 {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxSize)
		}

		c.Next()

		// If body was read and exceeded limit during read (e.g. chunked request), Close may return the error
		if c.Request.Body != nil {
			if err := c.Request.Body.Close(); err != nil {
				if strings.Contains(err.Error(), pkgerrors.ErrHTTPRequestBodyTooLarge) {
					slog.Warn("Request body too large (during read)", "path", c.Request.URL.Path, "ip", c.ClientIP(), "max_size", maxSize)
					if !c.Writer.Written() {
						c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge,
							models.NewErrorResponse(pkgerrors.ErrRequestTooLarge))
					}
					return
				}
				slog.Error("Error closing request body", "path", c.Request.URL.Path, "error", err)
			}
		}
	}
}
