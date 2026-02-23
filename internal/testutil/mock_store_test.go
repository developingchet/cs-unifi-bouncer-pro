package testutil_test

import (
	"errors"
	"testing"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
)

// TestMockStore_BanOperations covers BanRecord, BanExists, BanDelete, BanList.
func TestMockStore_BanOperations(t *testing.T) {
	t.Run("exists returns false for unknown IP", func(t *testing.T) {
		s := testutil.NewMockStore()
		ok, err := s.BanExists("1.2.3.4")
		if err != nil || ok {
			t.Fatalf("expected false, nil; got %v, %v", ok, err)
		}
	})

	t.Run("record then exists", func(t *testing.T) {
		s := testutil.NewMockStore()
		if err := s.BanRecord("1.2.3.4", time.Time{}, false); err != nil {
			t.Fatalf("BanRecord: %v", err)
		}
		ok, err := s.BanExists("1.2.3.4")
		if err != nil || !ok {
			t.Fatalf("expected true, nil after record; got %v, %v", ok, err)
		}
	})

	t.Run("delete removes ban", func(t *testing.T) {
		s := testutil.NewMockStore()
		_ = s.BanRecord("1.2.3.4", time.Time{}, false)
		if err := s.BanDelete("1.2.3.4"); err != nil {
			t.Fatalf("BanDelete: %v", err)
		}
		ok, _ := s.BanExists("1.2.3.4")
		if ok {
			t.Fatal("expected ban to be absent after delete")
		}
	})

	t.Run("delete unknown IP is a no-op", func(t *testing.T) {
		s := testutil.NewMockStore()
		if err := s.BanDelete("99.99.99.99"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("list returns all recorded bans", func(t *testing.T) {
		s := testutil.NewMockStore()
		_ = s.BanRecord("1.2.3.4", time.Time{}, false)
		_ = s.BanRecord("::1", time.Time{}, true)
		bans, err := s.BanList()
		if err != nil {
			t.Fatalf("BanList: %v", err)
		}
		if len(bans) != 2 {
			t.Fatalf("expected 2 bans, got %d", len(bans))
		}
		if !bans["::1"].IPv6 {
			t.Fatal("expected IPv6=true for ::1")
		}
	})

	t.Run("list returns a copy not an alias", func(t *testing.T) {
		s := testutil.NewMockStore()
		_ = s.BanRecord("1.2.3.4", time.Time{}, false)
		bans, _ := s.BanList()
		delete(bans, "1.2.3.4")
		bans2, _ := s.BanList()
		if len(bans2) != 1 {
			t.Fatal("BanList returned an alias of the internal map")
		}
	})

	t.Run("IPv6 flag is stored correctly", func(t *testing.T) {
		s := testutil.NewMockStore()
		_ = s.BanRecord("::1", time.Time{}, true)
		bans, _ := s.BanList()
		if !bans["::1"].IPv6 {
			t.Fatal("expected IPv6=true")
		}
	})
}

// TestMockStore_PruneExpiredBans verifies janitor behaviour for ban entries.
func TestMockStore_PruneExpiredBans(t *testing.T) {
	t.Run("removes expired, keeps live and permanent", func(t *testing.T) {
		s := testutil.NewMockStore()
		past := time.Now().Add(-time.Hour)
		future := time.Now().Add(time.Hour)
		_ = s.BanRecord("expired", past, false)
		_ = s.BanRecord("live", future, false)
		_ = s.BanRecord("permanent", time.Time{}, false) // zero = never expires

		pruned, err := s.PruneExpiredBans()
		if err != nil {
			t.Fatalf("PruneExpiredBans: %v", err)
		}
		if pruned != 1 {
			t.Fatalf("expected 1 pruned, got %d", pruned)
		}
		bans, _ := s.BanList()
		if _, ok := bans["expired"]; ok {
			t.Fatal("expired ban was not removed")
		}
		if _, ok := bans["live"]; !ok {
			t.Fatal("live ban was incorrectly removed")
		}
		if _, ok := bans["permanent"]; !ok {
			t.Fatal("permanent ban was incorrectly removed")
		}
	})

	t.Run("empty store returns zero", func(t *testing.T) {
		s := testutil.NewMockStore()
		pruned, err := s.PruneExpiredBans()
		if err != nil || pruned != 0 {
			t.Fatalf("expected 0, nil; got %d, %v", pruned, err)
		}
	})
}

// TestMockStore_GroupCache covers GetGroup, SetGroup, DeleteGroup, ListGroups.
func TestMockStore_GroupCache(t *testing.T) {
	t.Run("get missing returns nil without error", func(t *testing.T) {
		s := testutil.NewMockStore()
		rec, err := s.GetGroup("g1")
		if err != nil || rec != nil {
			t.Fatalf("expected nil, nil; got %v, %v", rec, err)
		}
	})

	t.Run("set then get", func(t *testing.T) {
		s := testutil.NewMockStore()
		grp := storage.GroupRecord{UnifiID: "u1", Site: "default"}
		if err := s.SetGroup("g1", grp); err != nil {
			t.Fatalf("SetGroup: %v", err)
		}
		rec, err := s.GetGroup("g1")
		if err != nil {
			t.Fatalf("GetGroup: %v", err)
		}
		if rec == nil || rec.UnifiID != "u1" {
			t.Fatalf("unexpected record: %+v", rec)
		}
	})

	t.Run("get returns a copy not a pointer to internal state", func(t *testing.T) {
		s := testutil.NewMockStore()
		_ = s.SetGroup("g1", storage.GroupRecord{UnifiID: "u1"})
		rec, _ := s.GetGroup("g1")
		rec.UnifiID = "mutated"
		rec2, _ := s.GetGroup("g1")
		if rec2.UnifiID != "u1" {
			t.Fatal("GetGroup returned an alias of the internal record")
		}
	})

	t.Run("delete removes group", func(t *testing.T) {
		s := testutil.NewMockStore()
		_ = s.SetGroup("g1", storage.GroupRecord{})
		if err := s.DeleteGroup("g1"); err != nil {
			t.Fatalf("DeleteGroup: %v", err)
		}
		rec, _ := s.GetGroup("g1")
		if rec != nil {
			t.Fatal("expected nil after delete")
		}
	})

	t.Run("list returns all groups", func(t *testing.T) {
		s := testutil.NewMockStore()
		_ = s.SetGroup("g1", storage.GroupRecord{UnifiID: "u1"})
		_ = s.SetGroup("g2", storage.GroupRecord{UnifiID: "u2"})
		groups, err := s.ListGroups()
		if err != nil {
			t.Fatalf("ListGroups: %v", err)
		}
		if len(groups) != 2 {
			t.Fatalf("expected 2 groups, got %d", len(groups))
		}
	})

	t.Run("list returns a copy", func(t *testing.T) {
		s := testutil.NewMockStore()
		_ = s.SetGroup("g1", storage.GroupRecord{UnifiID: "u1"})
		groups, _ := s.ListGroups()
		delete(groups, "g1")
		groups2, _ := s.ListGroups()
		if len(groups2) != 1 {
			t.Fatal("ListGroups returned an alias of the internal map")
		}
	})
}

// TestMockStore_PolicyCache covers GetPolicy, SetPolicy, DeletePolicy, ListPolicies.
func TestMockStore_PolicyCache(t *testing.T) {
	t.Run("get missing returns nil without error", func(t *testing.T) {
		s := testutil.NewMockStore()
		rec, err := s.GetPolicy("p1")
		if err != nil || rec != nil {
			t.Fatalf("expected nil, nil; got %v, %v", rec, err)
		}
	})

	t.Run("set then get", func(t *testing.T) {
		s := testutil.NewMockStore()
		pol := storage.PolicyRecord{UnifiID: "u1", Site: "default", Mode: "zone"}
		if err := s.SetPolicy("p1", pol); err != nil {
			t.Fatalf("SetPolicy: %v", err)
		}
		rec, err := s.GetPolicy("p1")
		if err != nil {
			t.Fatalf("GetPolicy: %v", err)
		}
		if rec == nil || rec.UnifiID != "u1" {
			t.Fatalf("unexpected record: %+v", rec)
		}
	})

	t.Run("delete removes policy", func(t *testing.T) {
		s := testutil.NewMockStore()
		_ = s.SetPolicy("p1", storage.PolicyRecord{})
		if err := s.DeletePolicy("p1"); err != nil {
			t.Fatalf("DeletePolicy: %v", err)
		}
		rec, _ := s.GetPolicy("p1")
		if rec != nil {
			t.Fatal("expected nil after delete")
		}
	})

	t.Run("list returns all policies", func(t *testing.T) {
		s := testutil.NewMockStore()
		_ = s.SetPolicy("p1", storage.PolicyRecord{Mode: "zone"})
		_ = s.SetPolicy("p2", storage.PolicyRecord{Mode: "legacy"})
		pols, err := s.ListPolicies()
		if err != nil {
			t.Fatalf("ListPolicies: %v", err)
		}
		if len(pols) != 2 {
			t.Fatalf("expected 2 policies, got %d", len(pols))
		}
	})
}

// TestMockStore_SizeBytes verifies the configurable SizeBytes field.
func TestMockStore_SizeBytes(t *testing.T) {
	s := testutil.NewMockStore()
	s.Size = 8192
	n, err := s.SizeBytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 8192 {
		t.Fatalf("expected 8192, got %d", n)
	}
}

// TestMockStore_Close verifies Close always returns nil.
func TestMockStore_Close(t *testing.T) {
	if err := testutil.NewMockStore().Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestMockStore_ErrorInjection verifies that SetError returns the error once
// and that the second call succeeds (error consumed).
func TestMockStore_ErrorInjection(t *testing.T) {
	sentinel := errors.New("injected")

	cases := []struct {
		method string
		call   func(s *testutil.MockStore) error
	}{
		{
			"BanExists",
			func(s *testutil.MockStore) error { _, err := s.BanExists("ip"); return err },
		},
		{
			"BanRecord",
			func(s *testutil.MockStore) error { return s.BanRecord("ip", time.Time{}, false) },
		},
		{
			"BanDelete",
			func(s *testutil.MockStore) error { return s.BanDelete("ip") },
		},
		{
			"BanList",
			func(s *testutil.MockStore) error { _, err := s.BanList(); return err },
		},
		{
			"PruneExpiredBans",
			func(s *testutil.MockStore) error { _, err := s.PruneExpiredBans(); return err },
		},
		{
			"GetGroup",
			func(s *testutil.MockStore) error { _, err := s.GetGroup("g"); return err },
		},
		{
			"SetGroup",
			func(s *testutil.MockStore) error { return s.SetGroup("g", storage.GroupRecord{}) },
		},
		{
			"DeleteGroup",
			func(s *testutil.MockStore) error { return s.DeleteGroup("g") },
		},
		{
			"ListGroups",
			func(s *testutil.MockStore) error { _, err := s.ListGroups(); return err },
		},
		{
			"GetPolicy",
			func(s *testutil.MockStore) error { _, err := s.GetPolicy("p"); return err },
		},
		{
			"SetPolicy",
			func(s *testutil.MockStore) error { return s.SetPolicy("p", storage.PolicyRecord{}) },
		},
		{
			"DeletePolicy",
			func(s *testutil.MockStore) error { return s.DeletePolicy("p") },
		},
		{
			"ListPolicies",
			func(s *testutil.MockStore) error { _, err := s.ListPolicies(); return err },
		},
		{
			"SizeBytes",
			func(s *testutil.MockStore) error { _, err := s.SizeBytes(); return err },
		},
	}

	for _, tc := range cases {
		t.Run(tc.method, func(t *testing.T) {
			s := testutil.NewMockStore()
			s.SetError(tc.method, sentinel)

			// First call must return the injected error.
			if err := tc.call(s); !errors.Is(err, sentinel) {
				t.Fatalf("expected sentinel error, got: %v", err)
			}
			// Error is consumed; second call must succeed.
			if err := tc.call(s); err != nil {
				t.Fatalf("expected no error on second call, got: %v", err)
			}
		})
	}
}
