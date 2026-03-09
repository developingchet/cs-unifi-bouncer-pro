package testutil

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
)

// --- Exported helper types --------------------------------------------------

// FakeTMLItem is an item used with AddTML.
type FakeTMLItem struct {
	Type  string
	Value interface{}
}

// FakePolicy is used with AddPolicy.
type FakePolicy struct {
	ID      string
	Enabled bool
	Name    string
	Action  string
	SrcZone string
	DstZone string
}

// FakeRequest captures one HTTP request for assertion.
type FakeRequest struct {
	Method string
	Path   string
	Body   []byte
	Query  map[string][]string
}

// --- Internal wire types ----------------------------------------------------

type fakeSite struct {
	ID           string `json:"id"`
	InternalRef  string `json:"internalReference"`
	Name         string `json:"name"`
}

type fakeZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Meta struct {
		Origin string `json:"origin"`
	} `json:"metadata"`
}

type fakeGroup struct {
	ID           string   `json:"_id,omitempty"`
	Name         string   `json:"name"`
	GroupType    string   `json:"group_type"`
	GroupMembers []string `json:"group_members"`
}

type fakeRule struct {
	ID                  string   `json:"_id,omitempty"`
	Name                string   `json:"name"`
	Enabled             bool     `json:"enabled"`
	RuleIndex           int      `json:"rule_index"`
	Action              string   `json:"action"`
	Ruleset             string   `json:"ruleset"`
	Description         string   `json:"description"`
	Logging             bool     `json:"logging"`
	Protocol            string   `json:"protocol"`
	SrcFirewallGroupIDs []string `json:"src_firewallgroup_ids"`
}

type fakeTMLItem struct {
	Type  string      `json:"type"`
	Value interface{} `json:"value"`
}

type fakeTML struct {
	ID    string        `json:"id,omitempty"`
	Type  string        `json:"type"`
	Name  string        `json:"name"`
	Items []fakeTMLItem `json:"items"`
}

type fakePolicy struct {
	ID      string `json:"id,omitempty"`
	Enabled bool   `json:"enabled"`
	Name    string `json:"name"`
	Action  struct {
		Type string `json:"type"`
	} `json:"action"`
	Source struct {
		ZoneID string `json:"zoneId"`
	} `json:"source"`
	Destination struct {
		ZoneID string `json:"zoneId"`
	} `json:"destination"`
	IPProtocolScope struct {
		IPVersion string `json:"ipVersion"`
	} `json:"ipProtocolScope"`
}

type fakeOrdering struct {
	OrderedFirewallPolicyIDs struct {
		BeforeSystemDefined []string `json:"beforeSystemDefined"`
		AfterSystemDefined  []string `json:"afterSystemDefined"`
	} `json:"orderedFirewallPolicyIds"`
}

// --- FakeUnifiServer --------------------------------------------------------

// FakeUnifiServer is a stateful HTTP server emulating the UniFi Network API.
// All exported methods are safe for concurrent use.
type FakeUnifiServer struct {
	srv *httptest.Server
	mu  sync.Mutex

	// Auth
	validAPIKey string
	username    string
	password    string
	sessions    map[string]bool
	csrfToken   string

	// State — legacy REST (keyed by site internalReference)
	groups map[string][]fakeGroup
	rules  map[string][]fakeRule

	// State — integration v1 (keyed by site UUID)
	sites    []fakeSite
	zones    map[string][]fakeZone
	policies map[string][]fakePolicy
	tmls     map[string][]fakeTML
	ordering map[string]fakeOrdering // "siteID:srcZone:dstZone" -> ordering

	// Request capture
	requests []FakeRequest

	// Fault injection: "METHOD pathPrefix" -> statusCode (consumed on first match)
	faults map[string]int

	nextID int
}

func newFakeServer(apiKey, username, password string) *FakeUnifiServer {
	s := &FakeUnifiServer{
		validAPIKey: apiKey,
		username:    username,
		password:    password,
		sessions:    make(map[string]bool),
		csrfToken:   "fake-csrf-token-abc123",
		groups:      make(map[string][]fakeGroup),
		rules:       make(map[string][]fakeRule),
		zones:       make(map[string][]fakeZone),
		policies:    make(map[string][]fakePolicy),
		tmls:        make(map[string][]fakeTML),
		ordering:    make(map[string]fakeOrdering),
		faults:      make(map[string]int),
	}
	s.srv = httptest.NewTLSServer(s)
	return s
}

// NewFakeUnifiServer creates a fake server with a fixed API key.
func NewFakeUnifiServer() *FakeUnifiServer {
	return newFakeServer("fake-api-key-test", "", "")
}

// NewFakeUnifiServerWithAuth creates a fake server requiring username/password login.
// API key auth is disabled (empty key).
func NewFakeUnifiServerWithAuth(username, password string) *FakeUnifiServer {
	return newFakeServer("", username, password)
}

// URL returns the base URL of the fake server.
func (s *FakeUnifiServer) URL() string { return s.srv.URL }

// APIKey returns the valid API key for this server.
func (s *FakeUnifiServer) APIKey() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.validAPIKey
}

// Close shuts down the server.
func (s *FakeUnifiServer) Close() { s.srv.Close() }

// --- State pre-population helpers -------------------------------------------

// AddSite adds a site. internalRef is the "default" style name; id is the UUID.
func (s *FakeUnifiServer) AddSite(internalRef, id, displayName string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sites = append(s.sites, fakeSite{ID: id, InternalRef: internalRef, Name: displayName})
}

// AddZone adds a zone to a site (keyed by site UUID).
func (s *FakeUnifiServer) AddZone(siteID, id, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	z := fakeZone{ID: id, Name: name}
	z.Meta.Origin = "USER_DEFINED"
	s.zones[siteID] = append(s.zones[siteID], z)
}

// AddGroup adds a legacy firewall group (keyed by site internalReference).
func (s *FakeUnifiServer) AddGroup(siteRef, id, name, groupType string, members []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.groups[siteRef] = append(s.groups[siteRef], fakeGroup{ID: id, Name: name, GroupType: groupType, GroupMembers: members})
}

// AddRule adds a legacy firewall rule (keyed by site internalReference).
func (s *FakeUnifiServer) AddRule(siteRef, id, name string, enabled bool, ruleset, action string, index int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules[siteRef] = append(s.rules[siteRef], fakeRule{
		ID: id, Name: name, Enabled: enabled,
		Ruleset: ruleset, Action: action, RuleIndex: index,
	})
}

// AddTML adds a TML to a site (keyed by site UUID).
func (s *FakeUnifiServer) AddTML(siteID, id, tmlType, name string, items []FakeTMLItem) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fi := make([]fakeTMLItem, len(items))
	for i, it := range items {
		fi[i] = fakeTMLItem{Type: it.Type, Value: it.Value}
	}
	s.tmls[siteID] = append(s.tmls[siteID], fakeTML{ID: id, Type: tmlType, Name: name, Items: fi})
}

// AddPolicy adds a zone policy to a site (keyed by site UUID).
func (s *FakeUnifiServer) AddPolicy(siteID string, p FakePolicy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fp := fakePolicy{ID: p.ID, Enabled: p.Enabled, Name: p.Name}
	fp.Action.Type = p.Action
	fp.Source.ZoneID = p.SrcZone
	fp.Destination.ZoneID = p.DstZone
	fp.IPProtocolScope.IPVersion = "IPV4"
	s.policies[siteID] = append(s.policies[siteID], fp)
}

// --- Fault injection --------------------------------------------------------

// InjectFault registers a one-shot fault: the first request whose
// "METHOD /path" has pathPrefix as a prefix will receive statusCode.
func (s *FakeUnifiServer) InjectFault(method, pathPrefix string, statusCode int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.faults[method+" "+pathPrefix] = statusCode
}

// --- Request capture --------------------------------------------------------

// Requests returns a copy of all captured requests.
func (s *FakeUnifiServer) Requests() []FakeRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]FakeRequest, len(s.requests))
	copy(out, s.requests)
	return out
}

// RequestsMatching returns captured requests whose method and path match.
func (s *FakeUnifiServer) RequestsMatching(method, pathPrefix string) []FakeRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []FakeRequest
	for _, r := range s.requests {
		if r.Method == method && strings.HasPrefix(r.Path, pathPrefix) {
			out = append(out, r)
		}
	}
	return out
}

// LastBody returns the body of the last request matching method+pathPrefix.
func (s *FakeUnifiServer) LastBody(method, pathPrefix string) []byte {
	reqs := s.RequestsMatching(method, pathPrefix)
	if len(reqs) == 0 {
		return nil
	}
	return reqs[len(reqs)-1].Body
}

// --- ServeHTTP --------------------------------------------------------------

func (s *FakeUnifiServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Read and buffer the request body so handlers can re-read it.
	body, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(body))

	// Capture request.
	s.mu.Lock()
	s.requests = append(s.requests, FakeRequest{
		Method: r.Method,
		Path:   r.URL.Path,
		Body:   body,
		Query:  map[string][]string(r.URL.Query()),
	})

	// Fault injection: check for matching fault (first match wins, consumed).
	faultKey := ""
	faultCode := 0
	for k, code := range s.faults {
		parts := strings.SplitN(k, " ", 2)
		if len(parts) == 2 && parts[0] == r.Method && strings.HasPrefix(r.URL.Path, parts[1]) {
			faultKey = k
			faultCode = code
			break
		}
	}
	if faultKey != "" {
		delete(s.faults, faultKey)
	}
	s.mu.Unlock()

	if faultCode != 0 {
		if faultCode == http.StatusTooManyRequests {
			w.Header().Set("Retry-After", "10")
		}
		http.Error(w, fmt.Sprintf("injected fault %d", faultCode), faultCode)
		return
	}

	path := r.URL.Path
	switch {
	case path == "/api/auth/login" && r.Method == http.MethodPost:
		s.handleLogin(w, r)
	case path == "/api/self":
		if !s.checkAuth(w, r) {
			return
		}
		s.handleSelf(w, r)
	case strings.HasPrefix(path, "/proxy/network/api/s/"):
		if !s.checkAuth(w, r) {
			return
		}
		s.routeLegacy(w, r, body)
	case strings.HasPrefix(path, "/proxy/network/integration/v1/"):
		if !s.checkAuth(w, r) {
			return
		}
		s.routeV1(w, r, body)
	default:
		http.NotFound(w, r)
	}
}

// --- Auth -------------------------------------------------------------------

func (s *FakeUnifiServer) checkAuth(w http.ResponseWriter, r *http.Request) bool {
	s.mu.Lock()
	apiKey := s.validAPIKey
	validCookie := false
	if cookie, err := r.Cookie("TOKEN"); err == nil {
		validCookie = s.sessions[cookie.Value]
	}
	s.mu.Unlock()

	if apiKey != "" && r.Header.Get("X-Api-Key") == apiKey {
		return true
	}
	if validCookie {
		return true
	}
	http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
	return false
}

func (s *FakeUnifiServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	ok := creds.Username == s.username && creds.Password == s.password && s.username != ""
	csrf := s.csrfToken
	s.mu.Unlock()

	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	s.mu.Lock()
	token := fmt.Sprintf("session-%d", s.nextID)
	s.nextID++
	s.sessions[token] = true
	s.mu.Unlock()

	http.SetCookie(w, &http.Cookie{Name: "TOKEN", Value: token, Path: "/", HttpOnly: true, Secure: true})
	w.Header().Set("X-Csrf-Token", csrf)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"data":"ok"}`))
}

func (s *FakeUnifiServer) handleSelf(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": map[string]string{"username": "admin"}})
}

// --- Legacy REST router -----------------------------------------------------

// path: /proxy/network/api/s/{site}/rest/{resource}[/{id}]
func (s *FakeUnifiServer) routeLegacy(w http.ResponseWriter, r *http.Request, body []byte) {
	// Strip prefix and split
	p := strings.TrimPrefix(r.URL.Path, "/proxy/network/api/s/")
	parts := strings.SplitN(p, "/", 4) // [site, "rest", resource, id?]
	if len(parts) < 3 {
		http.NotFound(w, r)
		return
	}
	site := parts[0]
	resource := parts[2]
	id := ""
	if len(parts) == 4 {
		id = parts[3]
	}

	switch resource {
	case "firewallgroup":
		s.handleGroups(w, r, body, site, id)
	case "firewallrule":
		s.handleRules(w, r, body, site, id)
	default:
		http.NotFound(w, r)
	}
}

func (s *FakeUnifiServer) handleGroups(w http.ResponseWriter, r *http.Request, body []byte, site, id string) {
	switch r.Method {
	case http.MethodGet:
		s.mu.Lock()
		groups := append([]fakeGroup{}, s.groups[site]...)
		s.mu.Unlock()
		items := make([]interface{}, len(groups))
		for i, g := range groups {
			items[i] = g
		}
		writeLegacyResp(w, items...)

	case http.MethodPost:
		var g fakeGroup
		if err := json.Unmarshal(body, &g); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		g.ID = s.newID()
		s.groups[site] = append(s.groups[site], g)
		s.mu.Unlock()
		writeLegacyResp(w, g)

	case http.MethodPut:
		if id == "" {
			http.Error(w, "missing id", http.StatusBadRequest)
			return
		}
		var g fakeGroup
		if err := json.Unmarshal(body, &g); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		g.ID = id
		s.mu.Lock()
		for i, existing := range s.groups[site] {
			if existing.ID == id {
				s.groups[site][i] = g
				break
			}
		}
		s.mu.Unlock()
		writeLegacyResp(w)

	case http.MethodDelete:
		if id == "" {
			http.Error(w, "missing id", http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		found := false
		ng := s.groups[site][:0]
		for _, g := range s.groups[site] {
			if g.ID == id {
				found = true
			} else {
				ng = append(ng, g)
			}
		}
		s.groups[site] = ng
		s.mu.Unlock()
		if !found {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		writeLegacyResp(w)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *FakeUnifiServer) handleRules(w http.ResponseWriter, r *http.Request, body []byte, site, id string) {
	switch r.Method {
	case http.MethodGet:
		s.mu.Lock()
		rules := append([]fakeRule{}, s.rules[site]...)
		s.mu.Unlock()
		items := make([]interface{}, len(rules))
		for i, ru := range rules {
			items[i] = ru
		}
		writeLegacyResp(w, items...)

	case http.MethodPost:
		var ru fakeRule
		if err := json.Unmarshal(body, &ru); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		ru.ID = s.newID()
		s.rules[site] = append(s.rules[site], ru)
		s.mu.Unlock()
		writeLegacyResp(w, ru)

	case http.MethodPut:
		if id == "" {
			http.Error(w, "missing id", http.StatusBadRequest)
			return
		}
		var ru fakeRule
		if err := json.Unmarshal(body, &ru); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		ru.ID = id
		s.mu.Lock()
		for i, existing := range s.rules[site] {
			if existing.ID == id {
				s.rules[site][i] = ru
				break
			}
		}
		s.mu.Unlock()
		writeLegacyResp(w)

	case http.MethodDelete:
		if id == "" {
			http.Error(w, "missing id", http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		found := false
		nr := s.rules[site][:0]
		for _, ru := range s.rules[site] {
			if ru.ID == id {
				found = true
			} else {
				nr = append(nr, ru)
			}
		}
		s.rules[site] = nr
		s.mu.Unlock()
		if !found {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		writeLegacyResp(w)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// --- Integration v1 router --------------------------------------------------

// path: /proxy/network/integration/v1/sites[/{siteID}/...]
func (s *FakeUnifiServer) routeV1(w http.ResponseWriter, r *http.Request, body []byte) {
	p := strings.TrimPrefix(r.URL.Path, "/proxy/network/integration/v1/")
	// p is now: "sites" or "sites/{id}/firewall/zones" etc.
	parts := strings.Split(p, "/")

	if parts[0] != "sites" {
		http.NotFound(w, r)
		return
	}

	// GET /proxy/network/integration/v1/sites
	if len(parts) == 1 {
		s.handleListSites(w, r)
		return
	}

	siteID := parts[1]

	if len(parts) < 3 {
		http.NotFound(w, r)
		return
	}

	switch parts[2] {
	case "firewall":
		if len(parts) < 4 {
			http.NotFound(w, r)
			return
		}
		switch parts[3] {
		case "zones":
			s.handleZones(w, r, siteID)
		case "policies":
			if len(parts) == 4 {
				s.handlePolicies(w, r, body, siteID, "")
			} else if len(parts) == 5 && parts[4] == "ordering" {
				s.handleOrdering(w, r, body, siteID)
			} else if len(parts) == 5 {
				s.handlePolicies(w, r, body, siteID, parts[4])
			} else {
				http.NotFound(w, r)
			}
		default:
			http.NotFound(w, r)
		}
	case "traffic-matching-lists":
		tmlID := ""
		if len(parts) == 4 {
			tmlID = parts[3]
		}
		s.handleTMLs(w, r, body, siteID, tmlID)
	default:
		http.NotFound(w, r)
	}
}

func (s *FakeUnifiServer) handleListSites(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	sites := append([]fakeSite{}, s.sites...)
	s.mu.Unlock()

	items := make([]json.RawMessage, len(sites))
	for i, site := range sites {
		b, _ := json.Marshal(site)
		items[i] = b
	}
	writeV1Page(w, r, items)
}

func (s *FakeUnifiServer) handleZones(w http.ResponseWriter, r *http.Request, siteID string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	zones := append([]fakeZone{}, s.zones[siteID]...)
	s.mu.Unlock()

	items := make([]json.RawMessage, len(zones))
	for i, z := range zones {
		b, _ := json.Marshal(z)
		items[i] = b
	}
	writeV1Page(w, r, items)
}

func (s *FakeUnifiServer) handleTMLs(w http.ResponseWriter, r *http.Request, body []byte, siteID, tmlID string) {
	switch r.Method {
	case http.MethodGet:
		s.mu.Lock()
		tmls := append([]fakeTML{}, s.tmls[siteID]...)
		s.mu.Unlock()
		items := make([]json.RawMessage, len(tmls))
		for i, t := range tmls {
			b, _ := json.Marshal(t)
			items[i] = b
		}
		writeV1Page(w, r, items)

	case http.MethodPost:
		var t fakeTML
		if err := json.Unmarshal(body, &t); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		t.ID = s.newID()
		s.tmls[siteID] = append(s.tmls[siteID], t)
		s.mu.Unlock()
		writeJSON(w, http.StatusCreated, t)

	case http.MethodPut:
		if tmlID == "" {
			http.Error(w, "missing id", http.StatusBadRequest)
			return
		}
		// CRITICAL: reject PUT body that contains "id" field.
		var check map[string]json.RawMessage
		if err := json.Unmarshal(body, &check); err == nil {
			if _, hasID := check["id"]; hasID {
				writeJSON(w, http.StatusBadRequest, map[string]string{
					"errorCode": "INVALID_BODY",
					"message":   "id must not be in PUT body",
				})
				return
			}
		}
		var t fakeTML
		if err := json.Unmarshal(body, &t); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		t.ID = tmlID
		s.mu.Lock()
		for i, existing := range s.tmls[siteID] {
			if existing.ID == tmlID {
				s.tmls[siteID][i] = t
				break
			}
		}
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, t)

	case http.MethodDelete:
		if tmlID == "" {
			http.Error(w, "missing id", http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		found := false
		nt := s.tmls[siteID][:0]
		for _, t := range s.tmls[siteID] {
			if t.ID == tmlID {
				found = true
			} else {
				nt = append(nt, t)
			}
		}
		s.tmls[siteID] = nt
		s.mu.Unlock()
		if !found {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *FakeUnifiServer) handlePolicies(w http.ResponseWriter, r *http.Request, body []byte, siteID, policyID string) {
	switch r.Method {
	case http.MethodGet:
		s.mu.Lock()
		pols := append([]fakePolicy{}, s.policies[siteID]...)
		s.mu.Unlock()
		items := make([]json.RawMessage, len(pols))
		for i, p := range pols {
			b, _ := json.Marshal(p)
			items[i] = b
		}
		writeV1Page(w, r, items)

	case http.MethodPost:
		var p fakePolicy
		if err := json.Unmarshal(body, &p); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		p.ID = s.newID()
		s.policies[siteID] = append(s.policies[siteID], p)
		s.mu.Unlock()
		writeJSON(w, http.StatusCreated, p)

	case http.MethodPut:
		if policyID == "" {
			http.Error(w, "missing id", http.StatusBadRequest)
			return
		}
		// CRITICAL: reject PUT body that contains "id" field.
		var check map[string]json.RawMessage
		if err := json.Unmarshal(body, &check); err == nil {
			if _, hasID := check["id"]; hasID {
				writeJSON(w, http.StatusBadRequest, map[string]string{
					"errorCode": "INVALID_BODY",
					"message":   "id must not be in PUT body",
				})
				return
			}
		}
		var p fakePolicy
		if err := json.Unmarshal(body, &p); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		p.ID = policyID
		s.mu.Lock()
		for i, existing := range s.policies[siteID] {
			if existing.ID == policyID {
				s.policies[siteID][i] = p
				break
			}
		}
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, p)

	case http.MethodDelete:
		if policyID == "" {
			http.Error(w, "missing id", http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		found := false
		np := s.policies[siteID][:0]
		for _, p := range s.policies[siteID] {
			if p.ID == policyID {
				found = true
			} else {
				np = append(np, p)
			}
		}
		s.policies[siteID] = np
		s.mu.Unlock()
		if !found {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *FakeUnifiServer) handleOrdering(w http.ResponseWriter, r *http.Request, body []byte, siteID string) {
	srcZone := r.URL.Query().Get("sourceFirewallZoneId")
	dstZone := r.URL.Query().Get("destinationFirewallZoneId")
	key := siteID + ":" + srcZone + ":" + dstZone

	switch r.Method {
	case http.MethodGet:
		s.mu.Lock()
		ord := s.ordering[key]
		s.mu.Unlock()
		if ord.OrderedFirewallPolicyIDs.BeforeSystemDefined == nil {
			ord.OrderedFirewallPolicyIDs.BeforeSystemDefined = []string{}
		}
		if ord.OrderedFirewallPolicyIDs.AfterSystemDefined == nil {
			ord.OrderedFirewallPolicyIDs.AfterSystemDefined = []string{}
		}
		writeJSON(w, http.StatusOK, ord)

	case http.MethodPut:
		var ord fakeOrdering
		if err := json.Unmarshal(body, &ord); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		s.ordering[key] = ord
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, ord)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// --- Response helpers -------------------------------------------------------

func writeLegacyResp(w http.ResponseWriter, items ...interface{}) {
	data := make([]json.RawMessage, 0, len(items))
	for _, item := range items {
		b, _ := json.Marshal(item)
		data = append(data, b)
	}
	resp := struct {
		Data []json.RawMessage `json:"data"`
		Meta struct {
			RC string `json:"rc"`
		} `json:"meta"`
	}{Data: data}
	resp.Meta.RC = "ok"
	writeJSON(w, http.StatusOK, resp)
}

// writeV1Page writes a paginated integration v1 response, applying offset/limit
// query parameters from the request.
func writeV1Page(w http.ResponseWriter, r *http.Request, all []json.RawMessage) {
	offsetStr := r.URL.Query().Get("offset")
	limitStr := r.URL.Query().Get("limit")
	offset, _ := strconv.Atoi(offsetStr)
	limit, _ := strconv.Atoi(limitStr)
	if limit <= 0 {
		limit = len(all)
		if limit == 0 {
			limit = 200
		}
	}

	total := len(all)
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	page := all[offset:end]

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
		TotalCount: total,
		Data:       page,
	}
	if resp.Data == nil {
		resp.Data = []json.RawMessage{}
	}
	writeJSON(w, http.StatusOK, resp)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	b, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

// --- Internal helpers -------------------------------------------------------

func (s *FakeUnifiServer) newID() string {
	s.nextID++
	return fmt.Sprintf("fake-%d", s.nextID)
}
