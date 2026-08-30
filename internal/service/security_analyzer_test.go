package service

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"garde/internal/models"
	"garde/internal/repository"
	"garde/pkg/config"
	"garde/pkg/session"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
)

func initConfigForUATests(t *testing.T, disableUA bool) {
	t.Helper()
	dir := t.TempDir()
	val := "false"
	if disableUA {
		val = "true"
	}
	if err := os.WriteFile(filepath.Join(dir, "disable_user_agent_check"), []byte(val), 0o600); err != nil {
		t.Fatal(err)
	}
	// Keep multiple-IP check off for analyzer tests that don't seed sessions
	if err := os.WriteFile(filepath.Join(dir, "disable_multiple_ip_check"), []byte("true"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := config.Init(dir); err != nil {
		t.Fatal(err)
	}
}

func newAnalyzerWithMiniRedis(t *testing.T) (*SecurityAnalyzer, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mr.Close)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return NewSecurityAnalyzer(repository.NewRedisRepositoryFromClient(client)), mr
}

func TestIsUnusualUserAgent(t *testing.T) {
	initConfigForUATests(t, false)
	a := &SecurityAnalyzer{}

	cases := []struct {
		ua   string
		want bool
	}{
		{"", false},
		{"curl/8.0", false},
		{"python-requests/2.28", false},
		{"MyService/1.0", false},
		{"Mozilla/5.0 Chrome/120", false},
		{"Googlebot/2.1", true},
		{"HeadlessChrome", true},
		{"selenium/webdriver", true},
		{"puppeteer", true},
	}
	for _, tc := range cases {
		if got := a.isUnusualUserAgent(tc.ua); got != tc.want {
			t.Errorf("isUnusualUserAgent(%q)=%v want %v", tc.ua, got, tc.want)
		}
	}
}

func TestIsUnusualUserAgentDisabled(t *testing.T) {
	initConfigForUATests(t, true)
	a := &SecurityAnalyzer{}
	if a.isUnusualUserAgent("Googlebot") {
		t.Fatal("expected check disabled")
	}
}

func TestDetectSuspiciousPatternsRoleAwareThreshold(t *testing.T) {
	initConfigForUATests(t, true)
	a, _ := newAnalyzerWithMiniRedis(t)
	ctx := context.Background()
	userID := "role-user"

	prev := session.RapidRequestThreshold
	prevTimeout := session.AutomatedRequestTimeout
	session.RapidRequestThreshold = 3
	session.AutomatedRequestTimeout = 0 // avoid automated_behavior when Detect follows Track immediately
	t.Cleanup(func() {
		session.RapidRequestThreshold = prev
		session.AutomatedRequestTimeout = prevTimeout
	})

	// 4 requests in the window — exceeds regular threshold (3) but not admin (9)
	for i := 0; i < 4; i++ {
		if err := a.TrackRequest(ctx, userID); err != nil {
			t.Fatalf("track %d: %v", i, err)
		}
	}

	regular := a.DetectSuspiciousPatternsWithRole(ctx, userID, "1.1.1.1", "curl", false, false)
	if !containsPattern(regular, session.ActivityRapidRequests) {
		t.Fatalf("regular user should trip rapid_requests, got %v", regular)
	}

	admin := a.DetectSuspiciousPatternsWithRole(ctx, userID, "1.1.1.1", "curl", true, false)
	if containsPattern(admin, session.ActivityRapidRequests) {
		t.Fatalf("admin should not trip at count=4 with threshold*3, got %v", admin)
	}
}

func TestTrackRequestSlidingMinuteWindow(t *testing.T) {
	initConfigForUATests(t, true)
	a, mr := newAnalyzerWithMiniRedis(t)
	ctx := context.Background()
	userID := "window-user"

	prev := session.RapidRequestThreshold
	prevTimeout := session.AutomatedRequestTimeout
	session.RapidRequestThreshold = 2
	session.AutomatedRequestTimeout = 0
	t.Cleanup(func() {
		session.RapidRequestThreshold = prev
		session.AutomatedRequestTimeout = prevTimeout
	})

	if err := a.TrackRequest(ctx, userID); err != nil {
		t.Fatal(err)
	}
	if err := a.TrackRequest(ctx, userID); err != nil {
		t.Fatal(err)
	}
	if err := a.TrackRequest(ctx, userID); err != nil {
		t.Fatal(err)
	}

	patterns := a.DetectSuspiciousPatternsWithRole(ctx, userID, "1.1.1.1", "ok", false, false)
	if !containsPattern(patterns, session.ActivityRapidRequests) {
		t.Fatalf("expected rapid_requests before window expiry, got %v", patterns)
	}

	mr.FastForward(session.RapidRequestWindow + time.Second)
	patterns = a.DetectSuspiciousPatternsWithRole(ctx, userID, "1.1.1.1", "ok", false, false)
	if containsPattern(patterns, session.ActivityRapidRequests) {
		t.Fatalf("expected no rapid_requests after window, got %v", patterns)
	}
}

func TestFilterPendingUpdatesGroupsOnly(t *testing.T) {
	pending := &models.UserUpdateRequest{
		RequestedAt: time.Now(),
		Fields: models.UserUpdateFields{
			GroupsAdd: []models.UserGroup{"alpha", "beta"},
			GroupsRemove: []models.UserGroup{
				"gamma",
			},
			PermissionsAdd: []models.Permission{"secret_perm"},
		},
	}
	adminGroups := models.UserGroups{"alpha": true}

	filtered := filterPendingUpdatesForAdmin(pending, adminGroups)
	if filtered == nil {
		t.Fatal("expected filtered result")
	}
	if len(filtered.Fields.GroupsAdd) != 1 || filtered.Fields.GroupsAdd[0] != "alpha" {
		t.Fatalf("groups add = %v", filtered.Fields.GroupsAdd)
	}
	if len(filtered.Fields.GroupsRemove) != 1 || filtered.Fields.GroupsRemove[0] != "gamma" {
		t.Fatalf("groups remove = %v", filtered.Fields.GroupsRemove)
	}
	// Permission adds filtered out when permRepo is nil (not visible)
	if len(filtered.Fields.PermissionsAdd) != 0 {
		t.Fatalf("unexpected permission adds: %v", filtered.Fields.PermissionsAdd)
	}
}

func TestFilterPendingUpdatesNilWhenEmpty(t *testing.T) {
	pending := &models.UserUpdateRequest{
		Fields: models.UserUpdateFields{
			GroupsAdd: []models.UserGroup{"other"},
		},
	}
	filtered := filterPendingUpdatesForAdmin(pending, models.UserGroups{"mine": true})
	if filtered != nil {
		t.Fatalf("expected nil, got %#v", filtered)
	}
}

func containsPattern(patterns []string, want string) bool {
	for _, p := range patterns {
		if p == want {
			return true
		}
	}
	return false
}
