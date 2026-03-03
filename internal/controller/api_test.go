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

// makeBareObject encodes an item as a bare JSON object (for v2 API single-object responses).
func makeBareObject(item interface{}) []byte {
	b, err := json.Marshal(item)
	if err != nil {
		panic(fmt.Sprintf("makeBareObject: marshal failed: %v", err))
	}
	return b
}

// makeV1Page encodes items in the integration v1 page envelope.
func makeV1Page(items ...interface{}) []byte {
	data := make([]json.RawMessage, 0, len(items))
	for _, item := range items {
		b, err := json.Marshal(item)
		if err != nil {
			panic(fmt.Sprintf("makeV1Page: marshal failed: %v", err))
		}
		data = append(data, json.RawMessage(b))
	}
	page := struct {
		Offset     int               `json:"offset"`
		Limit      int               `json:"limit"`
		Count      int               `json:"count"`
		TotalCount int               `json:"totalCount"`
		Data       []json.RawMessage `json:"data"`
	}{
		Count:      len(data),
		TotalCount: len(data),
		Data:       data,
	}
	b, err := json.Marshal(page)
	if err != nil {
		panic(fmt.Sprintf("makeV1Page: marshal page failed: %v", err))
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

// ---- Zone Policies (integration v1) ----------------------------------------

func TestListZonePolicies(t *testing.T) {
	const siteID = testSiteUUID
	expectedPath := fmt.Sprintf("/proxy/network/integration/v1/sites/%s/firewall/policies", siteID)

	tmlID := "dddddddd-0000-4000-8000-dddddddddddd"
	respBody := makeV1Page(
		apiV1Policy{
			ID:      "p1",
			Enabled: true,
			Name:    "block-wan-in",
			Action:  apiV1PolicyAction{Type: "BLOCK"},
			Source: apiV1PolicySrc{
				ZoneID: testZoneExternal,
				TrafficFilter: &apiV1TrafficFilter{
					Type: "IP_ADDRESS",
					IPAddressFilter: &apiV1IPAddressFilter{
						Type:                  "TRAFFIC_MATCHING_LIST",
						TrafficMatchingListID: tmlID,
					},
				},
			},
			Destination:     apiV1PolicyDst{ZoneID: testZoneInternal},
			IPProtocolScope: apiV1IPScope{IPVersion: "IPV4"},
			ConnectionStateFilter: []string{"NEW", "INVALID"},
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
	policies, err := listZonePoliciesV1(context.Background(), c, siteID)
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
	if p.SrcZone != testZoneExternal {
		t.Errorf("expected SrcZone=%q, got %q", testZoneExternal, p.SrcZone)
	}
	if p.DstZone != testZoneInternal {
		t.Errorf("expected DstZone=%q, got %q", testZoneInternal, p.DstZone)
	}
	if len(p.TrafficMatchingListIDs) != 1 || p.TrafficMatchingListIDs[0] != tmlID {
		t.Errorf("unexpected TrafficMatchingListIDs: %+v", p.TrafficMatchingListIDs)
	}
}

func TestCreateZonePolicy(t *testing.T) {
	const siteID = testSiteUUID
	expectedPath := fmt.Sprintf("/proxy/network/integration/v1/sites/%s/firewall/policies", siteID)

	tmlID := "dddddddd-0000-4000-8000-dddddddddddd"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != expectedPath {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		if body["name"] != "block-wan" {
			http.Error(w, "missing policy name", http.StatusBadRequest)
			return
		}
		created := apiV1Policy{
			ID:      "policy-abc",
			Enabled: true,
			Name:    "block-wan",
			Action:  apiV1PolicyAction{Type: "BLOCK"},
			Source: apiV1PolicySrc{
				ZoneID: testZoneExternal,
				TrafficFilter: &apiV1TrafficFilter{
					Type: "IP_ADDRESS",
					IPAddressFilter: &apiV1IPAddressFilter{
						Type:                  "TRAFFIC_MATCHING_LIST",
						TrafficMatchingListID: tmlID,
					},
				},
			},
			Destination:     apiV1PolicyDst{ZoneID: testZoneInternal},
			IPProtocolScope: apiV1IPScope{IPVersion: "IPV4"},
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(makeBareObject(created))
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "api-key")
	input := ZonePolicy{
		Name:                   "block-wan",
		Enabled:                true,
		Action:                 "BLOCK",
		SrcZone:                testZoneExternal,
		DstZone:                testZoneInternal,
		IPVersion:              "IPV4",
		TrafficMatchingListIDs: []string{tmlID},
	}

	got, err := createZonePolicyV1(context.Background(), c, siteID, input)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if got.ID != "policy-abc" {
		t.Errorf("expected ID=policy-abc, got %q", got.ID)
	}
	if got.SrcZone != testZoneExternal {
		t.Errorf("expected SrcZone=%q, got %q", testZoneExternal, got.SrcZone)
	}
	if got.DstZone != testZoneInternal {
		t.Errorf("expected DstZone=%q, got %q", testZoneInternal, got.DstZone)
	}
}

// ---- Site ID Resolution (integration v1) ------------------------------------

func TestGetSiteID_Found(t *testing.T) {
	const siteName = "default"
	expectedPath := "/proxy/network/integration/v1/sites"

	respBody := makeV1Page(
		apiSiteV1{ID: testSiteUUID, InternalReference: siteName, Name: "Default"},
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
	got, err := getSiteID(context.Background(), c, siteName)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if got != testSiteUUID {
		t.Errorf("expected siteID=%q, got %q", testSiteUUID, got)
	}
}

func TestGetSiteID_NotFound(t *testing.T) {
	respBody := makeV1Page() // empty list — site not found

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respBody)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "api-key")
	_, err := getSiteID(context.Background(), c, "nonexistent")
	if err == nil {
		t.Fatal("expected error when site is not in list, got nil")
	}
}

// ---- Traffic Matching Lists (integration v1) --------------------------------

func TestListTMLs(t *testing.T) {
	const siteID = testSiteUUID
	expectedPath := fmt.Sprintf("/proxy/network/integration/v1/sites/%s/traffic-matching-lists", siteID)

	tmlID := "dddddddd-0000-4000-8000-dddddddddddd"
	respBody := makeV1Page(
		apiTMLV1{
			ID:    tmlID,
			Type:  "IPV4_ADDRESSES",
			Name:  "crowdsec-block-v4-0",
			Items: []apiTMLItemV1{{Type: "IP_ADDRESS", Value: "1.2.3.4"}},
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
	tmls, err := listTMLs(context.Background(), c, siteID)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(tmls) != 1 {
		t.Fatalf("expected 1 TML, got %d", len(tmls))
	}
	if tmls[0].ID != tmlID {
		t.Errorf("expected ID=%q, got %q", tmlID, tmls[0].ID)
	}
	if tmls[0].Name != "crowdsec-block-v4-0" {
		t.Errorf("expected Name=crowdsec-block-v4-0, got %q", tmls[0].Name)
	}
	if len(tmls[0].Items) != 1 || tmls[0].Items[0].Value != "1.2.3.4" {
		t.Errorf("unexpected items: %+v", tmls[0].Items)
	}
}

func TestCreateTML(t *testing.T) {
	const siteID = testSiteUUID
	expectedPath := fmt.Sprintf("/proxy/network/integration/v1/sites/%s/traffic-matching-lists", siteID)

	tmlID := "dddddddd-0000-4000-8000-dddddddddddd"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != expectedPath {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		created := apiTMLV1{
			ID:    tmlID,
			Type:  "IPV4_ADDRESSES",
			Name:  "crowdsec-block-v4-0",
			Items: []apiTMLItemV1{},
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(makeBareObject(created))
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "api-key")
	input := TrafficMatchingList{
		Type: "IPV4_ADDRESSES",
		Name: "crowdsec-block-v4-0",
	}

	got, err := createTML(context.Background(), c, siteID, input)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if got.ID != tmlID {
		t.Errorf("expected ID=%q, got %q", tmlID, got.ID)
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
