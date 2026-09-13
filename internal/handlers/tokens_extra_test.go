package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// Second-wave API-key/PAT handler coverage: list filtering, single revoke,
// create-validation branches, PAT quota and unknown revoke.
func apiKeyFullRouter(t *testing.T, h *APIKeyHandler) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", "root-1")
		c.Next()
	})
	router.POST("/admin/api-keys", h.CreateAPIKey)
	router.GET("/admin/api-keys", h.ListAPIKeys)
	router.DELETE("/admin/api-keys/:key_id", h.RevokeAPIKey)
	return router
}

func createServiceKey(t *testing.T, router *gin.Engine, tenant, name string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"tenant_id": tenant, "name": name, "scopes": []string{"validate"},
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/api-keys", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create %s/%s: status = %d: %s", tenant, name, rec.Code, rec.Body.String())
	}
	var envelope struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	return envelope.Data.ID
}

func TestAPIKeyListAndRevoke(t *testing.T) {
	h := newAPIKeyTestHandler(t)
	router := apiKeyFullRouter(t, h)

	id1 := createServiceKey(t, router, "acme", "acme-prod")
	createServiceKey(t, router, "globex", "globex-prod")

	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec
	}
	var listed struct {
		Data struct {
			Total int `json:"total"`
		} `json:"data"`
	}
	rec := get("/admin/api-keys")
	if rec.Code != http.StatusOK {
		t.Fatalf("list: status = %d", rec.Code)
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &listed)
	if listed.Data.Total != 2 {
		t.Fatalf("total = %d, want 2", listed.Data.Total)
	}
	rec = get("/admin/api-keys?tenant_id=acme")
	_ = json.Unmarshal(rec.Body.Bytes(), &listed)
	if rec.Code != http.StatusOK || listed.Data.Total != 1 {
		t.Fatalf("tenant filter: status = %d total = %d", rec.Code, listed.Data.Total)
	}
	rec = get("/admin/api-keys?tenant_id=bad+id%21")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad tenant: status = %d", rec.Code)
	}

	del := func(id string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/admin/api-keys/"+id, nil))
		return rec
	}
	if rec := del("does-not-exist"); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown revoke: status = %d", rec.Code)
	}
	if rec := del(id1); rec.Code != http.StatusOK {
		t.Fatalf("revoke: status = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := del(id1); rec.Code != http.StatusOK {
		t.Fatalf("re-revoke idempotency: status = %d", rec.Code)
	}
}

func TestCreateAPIKeyValidationBranches(t *testing.T) {
	h := newAPIKeyTestHandler(t)
	router := apiKeyFullRouter(t, h)
	post := func(body map[string]any) *httptest.ResponseRecorder {
		payload, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/admin/api-keys", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}
	cases := []struct {
		name string
		body map[string]any
	}{
		{"missing scopes", map[string]any{"tenant_id": "acme", "name": "k"}},
		{"unknown scope", map[string]any{"tenant_id": "acme", "name": "k", "scopes": []string{"admin"}}},
		{"expiry conflict", map[string]any{"tenant_id": "acme", "name": "k", "scopes": []string{"validate"}, "expires_in": "24h", "never_expires": true}},
		{"expiry too long", map[string]any{"tenant_id": "acme", "name": "k", "scopes": []string{"validate"}, "expires_in": "9000h"}},
		{"negative rate", map[string]any{"tenant_id": "acme", "name": "k", "scopes": []string{"validate"}, "rate_limit": -1}},
		{"bad name", map[string]any{"tenant_id": "acme", "name": "bad name!", "scopes": []string{"validate"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if rec := post(tc.body); rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestPATQuotaAndUnknownRevoke(t *testing.T) {
	h := newPATTestHandler(t)
	router := patRouter(h, true)
	post := func(name string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{"name": name})
		req := httptest.NewRequest(http.MethodPost, "/users/me/tokens", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}
	var ids []string
	for i := 0; i < 25; i++ {
		rec := post(fmt.Sprintf("token-%d", i))
		if rec.Code != http.StatusCreated {
			t.Fatalf("fill %d: status = %d: %s", i, rec.Code, rec.Body.String())
		}
		var created struct {
			Data struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, created.Data.ID)
	}
	rec := post("one-too-many")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("quota: status = %d", rec.Code)
	}
	if msg := errorMessage(t, rec); msg == "" {
		t.Fatal("quota error has no message")
	}

	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/users/me/tokens/does-not-exist", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown revoke: status = %d", rec.Code)
	}

	// Invalid names and expiry shapes are 400, not 500. Free one slot first
	// so the quota gate is not what answers.
	del := httptest.NewRecorder()
	router.ServeHTTP(del, httptest.NewRequest(http.MethodDelete, "/users/me/tokens/"+ids[0], nil))
	if del.Code != http.StatusOK {
		t.Fatalf("freeing a slot: status = %d", del.Code)
	}
	for name, payload := range map[string]string{
		"bad name":       `{"name":"bad name!"}`,
		"expiry clash":   `{"name":"k","expires_in":"24h","never_expires":true}`,
		"expiry too big": `{"name":"k","expires_in":"9000h"}`,
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/users/me/tokens", bytes.NewReader([]byte(payload)))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
			}
		})
	}
}
