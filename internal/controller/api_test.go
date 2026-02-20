package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// makeAPIResp encodes items as the data array of an apiResponse JSON payload.
// Pass zero items for an empty data array.
func makeAPIResp(items ...interface{}) []byte {
	data := make([]json.RawMessage, 0, len(items))
	for _, item := range items {
		b, err := json.Marshal(item)
		if err != nil {
			panic(fmt.Sprintf("makeAPIResp: marshal failed: %v", err))
		}
		data = append(data, json.RawMessage(b))
	}
	resp := struct {
		Data []json.RawMessage `json:"data"`
		Meta struct {
			RC  string `json:"rc"`
			Msg string `json:"msg"`
		} `json:"meta"`
	}{
		Data: data,
	}
	resp.Meta.RC = "ok"
	b, err := json.Marshal(resp)
	if err != nil {
		panic(fmt.Sprintf("makeAPIResp: marshal envelope failed: %v", err))
	}
	return b
}

// ---- Firewall Groups -------------------------------------------------------

func TestListFirewallGroups(t *testing.T) {
	const site = "default"
	expectedPath := fmt.Sprintf("/proxy/network/api/s/%s/rest/firewallgroup", site)

	cases := []struct {
		name      string
		respItems []interface{}
		wantCount int
	}{
		{
			name:      "zero groups",
			respItems: nil,
			wantCount: 0,
		},
		{
			name: "one group",
			respItems: []interface{}{
				apiGroup{ID: "g1", Name: "blocklist", GroupType: "address-group", GroupMembers: []string{"1.2.3.4"}},
			},
			wantCount: 1,
		},
		{
			name: "five groups",
			respItems: []interface{}{
				apiGroup{ID: "g1", Name: "grp1", GroupType: "address-group", GroupMembers: []string{"1.1.1.1"}},
				apiGroup{ID: "g2", Name: "grp2", GroupType: "address-group", GroupMembers: []string{"2.2.2.2"}},
				apiGroup{ID: "g3", Name: "grp3", GroupType: "address-group", GroupMembers: []string{"3.3.3.3"}},
				apiGroup{ID: "g4", Name: "grp4", GroupType: "address-group", GroupMembers: []string{"4.4.4.4"}},
				apiGroup{ID: "g5", Name: "grp5", GroupType: "address-group", GroupMembers: []string{"5.5.5.5"}},
			},
			wantCount: 5,
		},
		{
			name: "malformed JSON item skipped",
			// One well-formed item plus one that cannot be unmarshalled into apiGroup
			// (a raw non-object scalar). The bad item is silently skipped.
			respItems: []interface{}{
				apiGroup{ID: "g1", Name: "good", GroupType: "address-group"},
			},
			// We inject the bad item manually below, so this case has its own server.
			wantCount: -1, // sentinel: handled separately
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.wantCount == -1 {
				// Malformed JSON case: manually craft a response with one good
				// item and one unparseable item.
				badResp := []byte(`{"data":[{"_id":"g1","name":"good","group_type":"address-group","group_members":null},42],"meta":{"rc":"ok"}}`)
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodGet || r.URL.Path != expectedPath {
						http.Error(w, "unexpected request", http.StatusBadRequest)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write(badResp)
				}))
				defer srv.Close()

				c := newTestClient(srv.URL, "api-key")
				groups, err := listFirewallGroups(context.Background(), c, site)
				if err != nil {
					t.Fatalf("expected no error, got: %v", err)
				}
				// The malformed item (42) is skipped; only the valid one is returned.
				if len(groups) != 1 {
					t.Errorf("expected 1 group (bad item skipped), got %d", len(groups))
				}
				return
			}

			respBody := makeAPIResp(tc.respItems...)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != expectedPath {
					http.Error(w, "unexpected request", http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(respBody)
			}))
			defer srv.Close()

			c := newTestClient(srv.URL, "api-key")
			groups, err := listFirewallGroups(context.Background(), c, site)
			if err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}
			if len(groups) != tc.wantCount {
				t.Errorf("expected %d groups, got %d", tc.wantCount, len(groups))
			}
		})
	}
}

func TestCreateFirewallGroup(t *testing.T) {
	const site = "default"
	expectedPath := fmt.Sprintf("/proxy/network/api/s/%s/rest/firewallgroup", site)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != expectedPath {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		created := apiGroup{ID: "new-id-123", Name: "blocklist", GroupType: "address-group", GroupMembers: []string{"10.0.0.1"}}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(makeAPIResp(created))
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "api-key")
	input := FirewallGroup{Name: "blocklist", GroupType: "address-group", GroupMembers: []string{"10.0.0.1"}}

	got, err := createFirewallGroup(context.Background(), c, site, input)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if got.ID != "new-id-123" {
		t.Errorf("expected ID=new-id-123, got %q", got.ID)
	}
	if got.Name != "blocklist" {
		t.Errorf("expected Name=blocklist, got %q", got.Name)
	}
}

func TestUpdateFirewallGroup(t *testing.T) {
	const site = "default"
	const groupID = "grp-456"
	expectedPath := fmt.Sprintf("/proxy/network/api/s/%s/rest/firewallgroup/%s", site, groupID)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != expectedPath {
			http.Error(w, fmt.Sprintf("unexpected %s %s", r.Method, r.URL.Path), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(makeAPIResp())
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "api-key")
	g := FirewallGroup{ID: groupID, Name: "updated", GroupType: "address-group", GroupMembers: []string{"192.168.1.1"}}

	if err := updateFirewallGroup(context.Background(), c, site, g); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestDeleteFirewallGroup(t *testing.T) {
	const site = "default"
	const groupID = "grp-789"
	expectedPath := fmt.Sprintf("/proxy/network/api/s/%s/rest/firewallgroup/%s", site, groupID)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != expectedPath {
			http.Error(w, fmt.Sprintf("unexpected %s %s", r.Method, r.URL.Path), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(makeAPIResp())
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "api-key")

	if err := deleteFirewallGroup(context.Background(), c, site, groupID); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

// ---- Firewall Rules --------------------------------------------------------

func TestListFirewallRules(t *testing.T) {
	const site = "default"
	expectedPath := fmt.Sprintf("/proxy/network/api/s/%s/rest/firewallrule", site)

	respBody := makeAPIResp(
		apiRule{ID: "r1", Name: "block-bad-ips", Enabled: true, RuleIndex: 2000, Action: "drop", Ruleset: "WAN_IN"},
		apiRule{ID: "r2", Name: "block-bad-ips-v6", Enabled: true, RuleIndex: 2001, Action: "drop", Ruleset: "WANv6_IN"},
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != expectedPath {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respBody)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "api-key")
	rules, err := listFirewallRules(context.Background(), c, site)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(rules))
	}
	if rules[0].ID != "r1" {
		t.Errorf("expected first rule ID=r1, got %q", rules[0].ID)
	}
}

func TestCreateFirewallRule(t *testing.T) {
	const site = "default"
	expectedPath := fmt.Sprintf("/proxy/network/api/s/%s/rest/firewallrule", site)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != expectedPath {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		created := apiRule{ID: "rule-new-999", Name: "block-bad", Action: "drop", Ruleset: "WAN_IN", RuleIndex: 3000}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(makeAPIResp(created))
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "api-key")
	input := FirewallRule{Name: "block-bad", Action: "drop", Ruleset: "WAN_IN", RuleIndex: 3000}

	got, err := createFirewallRule(context.Background(), c, site, input)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if got.ID != "rule-new-999" {
		t.Errorf("expected ID=rule-new-999, got %q", got.ID)
	}
}

// ---- Zone Policies ---------------------------------------------------------

func TestListZonePolicies(t *testing.T) {
	const site = "default"
	expectedPath := fmt.Sprintf("/proxy/network/api/s/%s/rest/firewall-policy", site)

	respBody := makeAPIResp(
		apiPolicy{
			ID:        "p1",
			Name:      "block-wan-in",
			Enabled:   true,
			Action:    "BLOCK",
			SrcZone:   "wan",
			DstZone:   "internal",
			IPVersion: "IPV4",
			MatchIPs:  []apiMatch{{FirewallGroupID: "grp1", Negate: false}},
			Priority:  100,
		},
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != expectedPath {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respBody)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "api-key")
	policies, err := listZonePolicies(context.Background(), c, site)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(policies))
	}
	p := policies[0]
	if p.ID != "p1" {
		t.Errorf("expected ID=p1, got %q", p.ID)
	}
	if p.SrcZone != "wan" {
		t.Errorf("expected SrcZone=wan, got %q", p.SrcZone)
	}
	if len(p.MatchIPs) != 1 || p.MatchIPs[0].FirewallGroupID != "grp1" {
		t.Errorf("unexpected MatchIPs: %+v", p.MatchIPs)
	}
}

func TestCreateZonePolicy(t *testing.T) {
	const site = "default"
	expectedPath := fmt.Sprintf("/proxy/network/api/s/%s/rest/firewall-policy", site)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != expectedPath {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		created := apiPolicy{ID: "policy-abc", Name: "block-wan", SrcZone: "wan", DstZone: "internal"}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(makeAPIResp(created))
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "api-key")
	input := ZonePolicy{Name: "block-wan", Action: "BLOCK", SrcZone: "wan", DstZone: "internal", IPVersion: "IPV4"}

	got, err := createZonePolicy(context.Background(), c, site, input)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if got.ID != "policy-abc" {
		t.Errorf("expected ID=policy-abc, got %q", got.ID)
	}
	if got.SrcZone != "wan" {
		t.Errorf("expected SrcZone=wan, got %q", got.SrcZone)
	}
}

func TestReorderZonePolicies(t *testing.T) {
	const site = "default"
	expectedPath := fmt.Sprintf("/proxy/network/api/s/%s/rest/firewall-policy/order", site)
	orderedIDs := []string{"p3", "p1", "p2"}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != expectedPath {
			http.Error(w, fmt.Sprintf("unexpected %s %s", r.Method, r.URL.Path), http.StatusBadRequest)
			return
		}

		// Verify the body contains the correct IDs in order.
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		idsRaw, ok := body["ids"]
		if !ok {
			http.Error(w, "missing ids field", http.StatusBadRequest)
			return
		}
		// JSON numbers unmarshal as []interface{} with string elements.
		idsSlice, ok := idsRaw.([]interface{})
		if !ok {
			http.Error(w, "ids is not an array", http.StatusBadRequest)
			return
		}
		if len(idsSlice) != len(orderedIDs) {
			http.Error(w, fmt.Sprintf("expected %d ids, got %d", len(orderedIDs), len(idsSlice)), http.StatusBadRequest)
			return
		}
		for i, id := range idsSlice {
			if s, ok := id.(string); !ok || s != orderedIDs[i] {
				http.Error(w, fmt.Sprintf("ids[%d]: expected %q, got %v", i, orderedIDs[i], id), http.StatusBadRequest)
				return
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(makeAPIResp())
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "api-key")

	if err := reorderZonePolicies(context.Background(), c, site, orderedIDs); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

// ---- Additional edge-case coverage ----------------------------------------

// TestListFirewallGroups_VerifiesFields checks that group fields are mapped correctly.
func TestListFirewallGroups_VerifiesFields(t *testing.T) {
	const site = "default"
	expectedPath := fmt.Sprintf("/proxy/network/api/s/%s/rest/firewallgroup", site)

	respBody := makeAPIResp(
		apiGroup{
			ID:           "grp-field-check",
			Name:         "my-group",
			GroupType:    "ipv6-address-group",
			GroupMembers: []string{"2001:db8::1", "2001:db8::2"},
		},
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != expectedPath {
			http.Error(w, "unexpected path", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respBody)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "api-key")
	groups, err := listFirewallGroups(context.Background(), c, site)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}
	g := groups[0]
	if g.ID != "grp-field-check" {
		t.Errorf("ID: got %q, want %q", g.ID, "grp-field-check")
	}
	if g.GroupType != "ipv6-address-group" {
		t.Errorf("GroupType: got %q, want %q", g.GroupType, "ipv6-address-group")
	}
	if len(g.GroupMembers) != 2 {
		t.Errorf("GroupMembers: got %d, want 2", len(g.GroupMembers))
	}
	if !strings.Contains(g.GroupMembers[0], "2001:db8") {
		t.Errorf("GroupMembers[0]: got %q, want IPv6 address", g.GroupMembers[0])
	}
}
