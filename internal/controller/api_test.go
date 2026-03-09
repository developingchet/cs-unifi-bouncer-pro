package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
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

// --- modelToV1Policy / v1PolicyToModel round-trip ---------------------------

// TestV1PolicyRoundTrip_DstIPTMLID verifies that DstIPTMLID survives a
// modelToV1Policy → v1PolicyToModel round-trip.
func TestV1PolicyRoundTrip_DstIPTMLID(t *testing.T) {
	const dstIPTMLID = "aaaa0000-0000-4000-8000-aaaaaaaaaaaa"
	const srcTMLID = "bbbb0000-0000-4000-8000-bbbbbbbbbbbb"

	input := ZonePolicy{
		ID:                     "pol-1",
		Name:                   "block-test",
		Enabled:                true,
		Action:                 "BLOCK",
		SrcZone:                testZoneExternal,
		DstZone:                testZoneInternal,
		IPVersion:              "IPV4",
		TrafficMatchingListIDs: []string{srcTMLID},
		DstIPTMLID:             dstIPTMLID,
	}

	wire := modelToV1Policy(input)

	// Destination TrafficFilter must carry the IP address filter.
	if wire.Destination.TrafficFilter == nil {
		t.Fatal("expected Destination.TrafficFilter to be set")
	}
	if wire.Destination.TrafficFilter.IPAddressFilter == nil {
		t.Fatal("expected Destination.TrafficFilter.IPAddressFilter to be set")
	}
	if got := wire.Destination.TrafficFilter.IPAddressFilter.TrafficMatchingListID; got != dstIPTMLID {
		t.Errorf("wire IPAddressFilter.TrafficMatchingListID = %q, want %q", got, dstIPTMLID)
	}

	// Round-trip back to model.
	model := v1PolicyToModel(wire)
	if model.DstIPTMLID != dstIPTMLID {
		t.Errorf("model.DstIPTMLID = %q, want %q", model.DstIPTMLID, dstIPTMLID)
	}
	if len(model.TrafficMatchingListIDs) != 1 || model.TrafficMatchingListIDs[0] != srcTMLID {
		t.Errorf("model.TrafficMatchingListIDs = %v, want [%s]", model.TrafficMatchingListIDs, srcTMLID)
	}
}

// TestV1PolicyRoundTrip_DstIPAndPort verifies that both DstIPTMLID and
// DstPortTMLID survive a modelToV1Policy → v1PolicyToModel round-trip.
func TestV1PolicyRoundTrip_DstIPAndPort(t *testing.T) {
	const dstIPTMLID = "aaaa0000-0000-4000-8000-aaaaaaaaaaaa"
	const dstPortTMLID = "cccc0000-0000-4000-8000-cccccccccccc"
	const srcTMLID = "bbbb0000-0000-4000-8000-bbbbbbbbbbbb"

	input := ZonePolicy{
		ID:                     "pol-2",
		Name:                   "block-test-2",
		Enabled:                true,
		Action:                 "BLOCK",
		SrcZone:                testZoneExternal,
		DstZone:                testZoneInternal,
		IPVersion:              "IPV4",
		TrafficMatchingListIDs: []string{srcTMLID},
		DstIPTMLID:             dstIPTMLID,
		DstPortTMLID:           dstPortTMLID,
	}

	wire := modelToV1Policy(input)

	// Destination TrafficFilter must carry both IP address and port filters.
	if wire.Destination.TrafficFilter == nil {
		t.Fatal("expected Destination.TrafficFilter to be set")
	}
	if wire.Destination.TrafficFilter.IPAddressFilter == nil {
		t.Fatal("expected Destination.TrafficFilter.IPAddressFilter to be set")
	}
	if wire.Destination.TrafficFilter.PortFilter == nil {
		t.Fatal("expected Destination.TrafficFilter.PortFilter to be set")
	}
	if got := wire.Destination.TrafficFilter.IPAddressFilter.TrafficMatchingListID; got != dstIPTMLID {
		t.Errorf("IPAddressFilter TML ID = %q, want %q", got, dstIPTMLID)
	}
	if got := wire.Destination.TrafficFilter.PortFilter.TrafficMatchingListID; got != dstPortTMLID {
		t.Errorf("PortFilter TML ID = %q, want %q", got, dstPortTMLID)
	}

	model := v1PolicyToModel(wire)
	if model.DstIPTMLID != dstIPTMLID {
		t.Errorf("model.DstIPTMLID = %q, want %q", model.DstIPTMLID, dstIPTMLID)
	}
	if model.DstPortTMLID != dstPortTMLID {
		t.Errorf("model.DstPortTMLID = %q, want %q", model.DstPortTMLID, dstPortTMLID)
	}
}

// --- ignoreNotFound -----------------------------------------------------------

func TestIgnoreNotFound(t *testing.T) {
	tests := []struct {
		name    string
		input   error
		wantNil bool
	}{
		{"nil input", nil, true},
		{"ErrNotFound direct", &ErrNotFound{URL: "/api/foo"}, true},
		{"ErrNotFound no URL", &ErrNotFound{}, true},
		{"wrapped ErrNotFound", fmt.Errorf("wrap: %w", &ErrNotFound{URL: "/bar"}), true},
		{"other error", fmt.Errorf("something else"), false},
		{"ErrConflict", &ErrConflict{Msg: "409"}, false},
		{"ErrRateLimit", &ErrRateLimit{RetryAfter: 0}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ignoreNotFound(tt.input)
			if tt.wantNil && got != nil {
				t.Errorf("ignoreNotFound(%v) = %v, want nil", tt.input, got)
			}
			if !tt.wantNil && got == nil {
				t.Errorf("ignoreNotFound(%v) = nil, want non-nil error", tt.input)
			}
			if !tt.wantNil && got != nil && got != tt.input {
				t.Errorf("ignoreNotFound(%v) = %v, want same error back", tt.input, got)
			}
		})
	}
}

// ---- Additional endpoint coverage ------------------------------------------

func TestUpdateFirewallRule(t *testing.T) {
	const site = "default"
	const ruleID = "rule-upd-1"
	expectedPath := fmt.Sprintf("/proxy/network/api/s/%s/rest/firewallrule/%s", site, ruleID)

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
	r := FirewallRule{ID: ruleID, Name: "updated", Action: "drop", Ruleset: "WAN_IN"}
	if err := updateFirewallRule(context.Background(), c, site, r); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestDeleteFirewallRule(t *testing.T) {
	const site = "default"
	const ruleID = "rule-del-1"
	expectedPath := fmt.Sprintf("/proxy/network/api/s/%s/rest/firewallrule/%s", site, ruleID)

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
	if err := deleteFirewallRule(context.Background(), c, site, ruleID); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestUpdateZonePolicy(t *testing.T) {
	const siteID = testSiteUUID
	const policyID = "pol-upd-1"
	expectedPath := fmt.Sprintf("/proxy/network/integration/v1/sites/%s/firewall/policies/%s", siteID, policyID)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != expectedPath {
			http.Error(w, fmt.Sprintf("unexpected %s %s", r.Method, r.URL.Path), http.StatusBadRequest)
			return
		}
		// Verify "id" is absent from PUT body.
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		if _, ok := body["id"]; ok {
			t.Errorf("PUT policy body must not contain 'id' field")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "api-key")
	p := ZonePolicy{ID: policyID, Name: "updated", Action: "BLOCK", SrcZone: testZoneExternal, DstZone: testZoneInternal}
	if err := updateZonePolicyV1(context.Background(), c, siteID, p); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestDeleteZonePolicy(t *testing.T) {
	const siteID = testSiteUUID
	const policyID = "pol-del-1"
	expectedPath := fmt.Sprintf("/proxy/network/integration/v1/sites/%s/firewall/policies/%s", siteID, policyID)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != expectedPath {
			http.Error(w, fmt.Sprintf("unexpected %s %s", r.Method, r.URL.Path), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "api-key")
	if err := deleteZonePolicyV1(context.Background(), c, siteID, policyID); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestUpdateTML(t *testing.T) {
	const siteID = testSiteUUID
	const tmlID = "tml-upd-1"
	expectedPath := fmt.Sprintf("/proxy/network/integration/v1/sites/%s/traffic-matching-lists/%s", siteID, tmlID)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != expectedPath {
			http.Error(w, fmt.Sprintf("unexpected %s %s", r.Method, r.URL.Path), http.StatusBadRequest)
			return
		}
		// Verify "id" is absent from PUT body.
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		if _, ok := body["id"]; ok {
			t.Errorf("PUT TML body must not contain 'id' field")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "api-key")
	list := TrafficMatchingList{ID: tmlID, Type: "IPV4_ADDRESSES", Name: "updated-list"}
	if err := updateTML(context.Background(), c, siteID, list); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestDeleteTML(t *testing.T) {
	const siteID = testSiteUUID
	const tmlID = "tml-del-1"
	expectedPath := fmt.Sprintf("/proxy/network/integration/v1/sites/%s/traffic-matching-lists/%s", siteID, tmlID)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != expectedPath {
			http.Error(w, fmt.Sprintf("unexpected %s %s", r.Method, r.URL.Path), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "api-key")
	if err := deleteTML(context.Background(), c, siteID, tmlID); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestGetPolicyOrdering(t *testing.T) {
	const siteID = testSiteUUID
	const srcZone = testZoneExternal
	const dstZone = testZoneInternal
	expectedPath := fmt.Sprintf("/proxy/network/integration/v1/sites/%s/firewall/policies/ordering", siteID)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != expectedPath {
			http.Error(w, fmt.Sprintf("unexpected %s %s", r.Method, r.URL.Path), http.StatusBadRequest)
			return
		}
		// Verify zone query params are present.
		if got := r.URL.Query().Get("sourceFirewallZoneId"); got != srcZone {
			t.Errorf("sourceFirewallZoneId = %q, want %q", got, srcZone)
		}
		if got := r.URL.Query().Get("destinationFirewallZoneId"); got != dstZone {
			t.Errorf("destinationFirewallZoneId = %q, want %q", got, dstZone)
		}
		resp := apiOrderingBody{
			OrderedFirewallPolicyIDs: apiOrderedPolicyIDs{
				BeforeSystemDefined: []string{"pol-1"},
				AfterSystemDefined:  []string{"pol-2"},
			},
		}
		b, _ := json.Marshal(resp)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(b)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "api-key")
	got, err := getPolicyOrderingV1(context.Background(), c, siteID, srcZone, dstZone)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(got.BeforeSystemDefined) != 1 || got.BeforeSystemDefined[0] != "pol-1" {
		t.Errorf("BeforeSystemDefined = %v, want [pol-1]", got.BeforeSystemDefined)
	}
}

func TestSetPolicyOrdering(t *testing.T) {
	const siteID = testSiteUUID
	const srcZone = testZoneExternal
	const dstZone = testZoneInternal
	expectedPath := fmt.Sprintf("/proxy/network/integration/v1/sites/%s/firewall/policies/ordering", siteID)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != expectedPath {
			http.Error(w, fmt.Sprintf("unexpected %s %s", r.Method, r.URL.Path), http.StatusBadRequest)
			return
		}
		if got := r.URL.Query().Get("sourceFirewallZoneId"); got != srcZone {
			t.Errorf("sourceFirewallZoneId = %q, want %q", got, srcZone)
		}
		if got := r.URL.Query().Get("destinationFirewallZoneId"); got != dstZone {
			t.Errorf("destinationFirewallZoneId = %q, want %q", got, dstZone)
		}
		var body apiOrderingBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		if len(body.OrderedFirewallPolicyIDs.BeforeSystemDefined) != 2 {
			t.Errorf("BeforeSystemDefined: got %v, want 2 items", body.OrderedFirewallPolicyIDs.BeforeSystemDefined)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "api-key")
	ordering := PolicyOrdering{BeforeSystemDefined: []string{"pol-1", "pol-2"}}
	if err := setPolicyOrderingV1(context.Background(), c, siteID, srcZone, dstZone, ordering); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestDiscoverSites(t *testing.T) {
	expectedPath := "/proxy/network/integration/v1/sites"

	respBody := makeV1Page(
		apiSiteV1{ID: testSiteUUID, InternalReference: "default", Name: "Default"},
		apiSiteV1{ID: "uuid-b", InternalReference: "site-b", Name: "Site B"},
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
	sites, err := discoverSites(context.Background(), c)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(sites) != 2 {
		t.Fatalf("expected 2 sites, got %d: %v", len(sites), sites)
	}
}

func TestDiscoverZones(t *testing.T) {
	const siteID = testSiteUUID
	expectedPath := fmt.Sprintf("/proxy/network/integration/v1/sites/%s/firewall/zones", siteID)

	respBody := makeV1Page(
		apiFirewallZoneV1{ID: testZoneExternal, Name: "WAN"},
		apiFirewallZoneV1{ID: testZoneInternal, Name: "LAN"},
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != expectedPath {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respBody)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "api-key")
	zones, err := listFirewallZones(context.Background(), c, siteID)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(zones) != 2 {
		t.Fatalf("expected 2 zones, got %d", len(zones))
	}
	if zones[0].ID != testZoneExternal {
		t.Errorf("zones[0].ID = %q, want %q", zones[0].ID, testZoneExternal)
	}
}

func TestListZonePolicies_Pagination(t *testing.T) {
	const siteID = testSiteUUID
	expectedPath := fmt.Sprintf("/proxy/network/integration/v1/sites/%s/firewall/policies", siteID)

	// Server returns page1 (3 items) then page2 (2 items) based on offset.
	makePolicy := func(id string) apiV1Policy {
		return apiV1Policy{
			ID: id, Enabled: true, Name: id, Action: apiV1PolicyAction{Type: "BLOCK"},
			Source:          apiV1PolicySrc{ZoneID: testZoneExternal},
			Destination:     apiV1PolicyDst{ZoneID: testZoneInternal},
			IPProtocolScope: apiV1IPScope{IPVersion: "IPV4"},
		}
	}
	allPolicies := []apiV1Policy{
		makePolicy("p1"), makePolicy("p2"), makePolicy("p3"),
		makePolicy("p4"), makePolicy("p5"),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != expectedPath {
			http.Error(w, "unexpected path", http.StatusBadRequest)
			return
		}
		offsetStr := r.URL.Query().Get("offset")
		limitStr := r.URL.Query().Get("limit")
		offset, _ := strconv.Atoi(offsetStr)
		limit, _ := strconv.Atoi(limitStr)
		if limit == 0 {
			limit = 3
		}

		end := offset + limit
		if end > len(allPolicies) {
			end = len(allPolicies)
		}
		page := allPolicies[offset:end]
		items := make([]json.RawMessage, len(page))
		for i, p := range page {
			items[i], _ = json.Marshal(p)
		}
		resp := struct {
			Offset     int               `json:"offset"`
			Limit      int               `json:"limit"`
			Count      int               `json:"count"`
			TotalCount int               `json:"totalCount"`
			Data       []json.RawMessage `json:"data"`
		}{
			Offset:     offset,
			Limit:      limit,
			Count:      len(page),
			TotalCount: len(allPolicies),
			Data:       items,
		}
		b, _ := json.Marshal(resp)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(b)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "api-key")
	policies, err := listZonePoliciesV1(context.Background(), c, siteID)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(policies) != 5 {
		t.Errorf("expected 5 policies via pagination, got %d", len(policies))
	}
}

func TestListTMLs_Pagination(t *testing.T) {
	const siteID = testSiteUUID
	expectedPath := fmt.Sprintf("/proxy/network/integration/v1/sites/%s/traffic-matching-lists", siteID)

	allTMLs := make([]apiTMLV1, 5)
	for i := range allTMLs {
		allTMLs[i] = apiTMLV1{ID: fmt.Sprintf("tml-%d", i), Type: "IPV4_ADDRESSES", Name: fmt.Sprintf("list-%d", i)}
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != expectedPath {
			http.Error(w, "unexpected path", http.StatusBadRequest)
			return
		}
		offsetStr := r.URL.Query().Get("offset")
		limitStr := r.URL.Query().Get("limit")
		offset, _ := strconv.Atoi(offsetStr)
		limit, _ := strconv.Atoi(limitStr)
		if limit == 0 {
			limit = 3
		}

		end := offset + limit
		if end > len(allTMLs) {
			end = len(allTMLs)
		}
		page := allTMLs[offset:end]
		items := make([]json.RawMessage, len(page))
		for i, t := range page {
			items[i], _ = json.Marshal(t)
		}
		resp := struct {
			Offset     int               `json:"offset"`
			Limit      int               `json:"limit"`
			Count      int               `json:"count"`
			TotalCount int               `json:"totalCount"`
			Data       []json.RawMessage `json:"data"`
		}{
			Offset:     offset,
			Limit:      limit,
			Count:      len(page),
			TotalCount: len(allTMLs),
			Data:       items,
		}
		b, _ := json.Marshal(resp)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(b)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "api-key")
	tmls, err := listTMLs(context.Background(), c, siteID)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(tmls) != 5 {
		t.Errorf("expected 5 TMLs via pagination, got %d", len(tmls))
	}
}

// --- Wire struct unit tests -------------------------------------------------

// TestTMLWireUpdate_ExcludesID verifies that tmlToWireUpdate produces JSON
// without an "id" field — the primary regression guard for TML PUT requests.
func TestTMLWireUpdate_ExcludesID(t *testing.T) {
	tml := TrafficMatchingList{ID: "some-id", Type: "IPV4_ADDRESSES", Name: "test"}
	wire := tmlToWireUpdate(tml)
	b, err := json.Marshal(wire)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := m["id"]; ok {
		t.Error("tmlToWireUpdate must not produce an 'id' field in JSON output")
	}
	// Verify expected fields are present.
	if _, ok := m["type"]; !ok {
		t.Error("tmlToWireUpdate must include 'type' field")
	}
	if _, ok := m["name"]; !ok {
		t.Error("tmlToWireUpdate must include 'name' field")
	}
}

// TestPolicyWireUpdate_ExcludesID verifies that modelToV1PolicyUpdate produces
// JSON without an "id" field — regression guard for policy PUT requests.
func TestPolicyWireUpdate_ExcludesID(t *testing.T) {
	p := ZonePolicy{
		ID:      "some-policy-id",
		Name:    "test-policy",
		Enabled: true,
		Action:  "BLOCK",
		SrcZone: testZoneExternal,
		DstZone: testZoneInternal,
	}
	wire := modelToV1PolicyUpdate(p)
	b, err := json.Marshal(wire)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := m["id"]; ok {
		t.Error("modelToV1PolicyUpdate must not produce an 'id' field in JSON output")
	}
	if _, ok := m["name"]; !ok {
		t.Error("modelToV1PolicyUpdate must include 'name' field")
	}
}
