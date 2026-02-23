package firewall

import (
	"testing"
)

func TestIPSet_AddRemove(t *testing.T) {
	s := NewIPSet()

	if added := s.Add("1.2.3.4"); !added {
		t.Fatal("expected Add to return true for new IP")
	}
	if added := s.Add("1.2.3.4"); added {
		t.Fatal("expected Add to return false for duplicate IP")
	}
	if s.Len() != 1 {
		t.Fatalf("expected Len=1, got %d", s.Len())
	}
	if !s.IsDirty() {
		t.Fatal("expected dirty after Add")
	}

	s.MarkClean()
	if s.IsDirty() {
		t.Fatal("expected clean after MarkClean")
	}

	if removed := s.Remove("1.2.3.4"); !removed {
		t.Fatal("expected Remove to return true for existing IP")
	}
	if removed := s.Remove("1.2.3.4"); removed {
		t.Fatal("expected Remove to return false for absent IP")
	}
	if s.Len() != 0 {
		t.Fatalf("expected Len=0, got %d", s.Len())
	}
	if !s.IsDirty() {
		t.Fatal("expected dirty after Remove")
	}
}

func TestIPSet_PeekDirtyCommitClean(t *testing.T) {
	s := NewIPSet()
	s.Add("1.1.1.1")
	s.Add("2.2.2.2")

	ips, dirty := s.PeekDirty()
	if !dirty {
		t.Fatal("expected dirty")
	}
	if len(ips) != 2 {
		t.Fatalf("expected 2 IPs, got %d", len(ips))
	}
	// Dirty flag still set after peek
	if !s.IsDirty() {
		t.Fatal("PeekDirty must not clear dirty flag")
	}

	s.CommitClean()
	_, dirty = s.PeekDirty()
	if dirty {
		t.Fatal("expected clean after CommitClean")
	}
}

func TestIPSet_Replace(t *testing.T) {
	s := NewIPSet()
	s.Add("1.1.1.1")
	s.MarkClean()

	s.Replace([]string{"2.2.2.2", "3.3.3.3"})
	if s.Contains("1.1.1.1") {
		t.Fatal("old IP should be gone after Replace")
	}
	if !s.Contains("2.2.2.2") || !s.Contains("3.3.3.3") {
		t.Fatal("new IPs should be present after Replace")
	}
	if !s.IsDirty() {
		t.Fatal("Replace must mark dirty")
	}
}

func TestIPSet_Capacity(t *testing.T) {
	s := NewIPSet()
	s.Add("1.1.1.1")
	s.Add("2.2.2.2")
	// Limit = 10, 2 used, capacity = 8
	if cap := s.Capacity(10); cap != 8 {
		t.Fatalf("expected capacity 8, got %d", cap)
	}
}

func TestIPSet_Members(t *testing.T) {
	s := NewIPSet()
	s.Add("1.1.1.1")
	s.Add("2.2.2.2")
	s.MarkClean()

	members := s.Members()
	if len(members) != 2 {
		t.Fatalf("expected 2 members, got %d", len(members))
	}
	// Members() must not affect dirty state
	if s.IsDirty() {
		t.Fatal("Members() must not dirty the set")
	}
}
