package handlers

import (
	"net/http/httptest"
	"testing"

	"garde/internal/models"

	"github.com/gin-gonic/gin"
)

// applyUserListQuery is pure (filter/sort/paginate in memory), so it is
// tested directly through gin contexts instead of a live admin session.
func queryContext(t *testing.T, rawQuery string) *gin.Context {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/users?"+rawQuery, nil)
	return c
}

func fixtureUsers() []models.UserResponse {
	pending := &models.UserUpdateRequest{}
	return []models.UserResponse{
		{Email: "c@example.com", Status: models.UserStatusOk, MFAEnabled: true},
		{Email: "a@example.com", Status: models.UserStatusLockedByAdmin, PendingUpdates: pending},
		{Email: "b@example.com", Status: models.UserStatusOk, MFAEnforced: true},
	}
}

func emails(out []models.UserResponse) []string {
	got := make([]string, len(out))
	for i, u := range out {
		got[i] = u.Email
	}
	return got
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestUserListQueryDefaultSortAndFullList(t *testing.T) {
	resp := applyUserListQuery(fixtureUsers(), queryContext(t, ""))
	if resp.Total != 3 || len(resp.Users) != 3 {
		t.Fatalf("total=%d users=%d, want 3/3", resp.Total, len(resp.Users))
	}
	if want := []string{"a@example.com", "b@example.com", "c@example.com"}; !equalStrings(emails(resp.Users), want) {
		t.Fatalf("order = %v, want %v", emails(resp.Users), want)
	}
}

func TestUserListQuerySearch(t *testing.T) {
	resp := applyUserListQuery(fixtureUsers(), queryContext(t, "q=B@EXAMPLE"))
	if resp.Total != 1 || resp.Users[0].Email != "b@example.com" {
		t.Fatalf("search = %+v", resp.Users)
	}
}

func TestUserListQuerySortStatusDesc(t *testing.T) {
	resp := applyUserListQuery(fixtureUsers(), queryContext(t, "sort=status&order=desc"))
	if len(resp.Users) != 3 {
		t.Fatalf("users = %d, want 3", len(resp.Users))
	}
	// "ok" > "locked by admin": desc puts oks first, stable within ties.
	if want := []string{"c@example.com", "b@example.com", "a@example.com"}; !equalStrings(emails(resp.Users), want) {
		t.Fatalf("order = %v, want %v", emails(resp.Users), want)
	}
}

func TestUserListQuerySortPending(t *testing.T) {
	resp := applyUserListQuery(fixtureUsers(), queryContext(t, "sort=pending&order=desc"))
	if resp.Users[0].Email != "a@example.com" {
		t.Fatalf("pending user should sort first desc, got %v", emails(resp.Users))
	}
}

func TestUserListQueryPagination(t *testing.T) {
	resp := applyUserListQuery(fixtureUsers(), queryContext(t, "page=2&limit=2"))
	if resp.Total != 3 || len(resp.Users) != 1 || resp.Users[0].Email != "c@example.com" {
		t.Fatalf("page2 = %+v total=%d", emails(resp.Users), resp.Total)
	}
	if resp.Page != 2 || resp.Limit != 2 {
		t.Fatalf("page=%d limit=%d, want 2/2", resp.Page, resp.Limit)
	}
}

func TestUserListQueryOutOfRangeAndInvalid(t *testing.T) {
	resp := applyUserListQuery(fixtureUsers(), queryContext(t, "page=9&limit=2"))
	if len(resp.Users) != 0 || resp.Total != 3 {
		t.Fatalf("oob = %+v total=%d", emails(resp.Users), resp.Total)
	}
	// Garbage numbers are treated as omitted: full list, deterministic order.
	resp = applyUserListQuery(fixtureUsers(), queryContext(t, "page=abc&limit=-5"))
	if len(resp.Users) != 3 {
		t.Fatalf("invalid = %+v", emails(resp.Users))
	}
	// Unknown sort field falls back to email.
	resp = applyUserListQuery(fixtureUsers(), queryContext(t, "sort=bogus"))
	if want := []string{"a@example.com", "b@example.com", "c@example.com"}; !equalStrings(emails(resp.Users), want) {
		t.Fatalf("order = %v, want %v", emails(resp.Users), want)
	}
}

func TestUserListQueryLimitCap(t *testing.T) {
	resp := applyUserListQuery(fixtureUsers(), queryContext(t, "limit=500"))
	if resp.Limit != 100 {
		t.Fatalf("limit = %d, want capped 100", resp.Limit)
	}
}

func TestMfaSortKey(t *testing.T) {
	a := models.UserResponse{MFAEnabled: true, MFAEnforced: true}
	b := models.UserResponse{}
	if mfaSortKey(a) <= mfaSortKey(b) {
		t.Fatal("enabled+enforced should sort after disabled")
	}
}
