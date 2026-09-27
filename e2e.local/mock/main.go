// Command mock serves a blocklist and records webhook deliveries for the
// local end-to-end suite.
//
//	GET  /blocklist.txt   current blocklist body (requires ?token=e2e-feed-token)
//	PUT  /_blocklist      replace the blocklist body
//	PUT  /_feedstatus     answer /blocklist.txt with this HTTP status ("0" restores it)
//	POST /webhook         record a webhook delivery
//	POST /webhook/fail    answer 500 (counted)
//	POST /webhook/slow    answer after a minute (counted)
//	GET  /_hookattempts   counts of /webhook/fail and /webhook/slow requests
//	GET  /_webhooks       recorded deliveries as a JSON array
//	GET  /_fetches        number of blocklist fetches
package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const feedToken = "e2e-feed-token"

type state struct {
	mu          sync.Mutex
	blocklist   []byte
	failWith    int
	fetches     int
	failedHooks int
	slowHooks   int
	webhooks    []json.RawMessage
}

func main() {
	s := &state{blocklist: []byte("# e2e blocklist\n198.51.100.200\n198.51.100.201\n")}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /blocklist.txt", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != feedToken {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		s.fetches++
		if s.failWith != 0 {
			http.Error(w, "feed unavailable", s.failWith)
			return
		}
		_, _ = w.Write(s.blocklist)
	})
	mux.HandleFunc("PUT /_feedstatus", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 16))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		code, err := strconv.Atoi(strings.TrimSpace(string(body)))
		if err != nil || (code != 0 && (code < 400 || code > 599)) {
			http.Error(w, "want 0 or a 4xx/5xx status", http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		s.failWith = code
		s.mu.Unlock()
	})
	mux.HandleFunc("PUT /_blocklist", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		s.blocklist = body
		s.mu.Unlock()
	})
	mux.HandleFunc("POST /webhook", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil || !json.Valid(body) {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		s.webhooks = append(s.webhooks, body)
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /webhook/fail", func(w http.ResponseWriter, _ *http.Request) {
		s.mu.Lock()
		s.failedHooks++
		s.mu.Unlock()
		http.Error(w, "receiver down", http.StatusInternalServerError)
	})
	mux.HandleFunc("POST /webhook/slow", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.slowHooks++
		s.mu.Unlock()
		select {
		case <-time.After(time.Minute):
		case <-r.Context().Done():
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /_hookattempts", func(w http.ResponseWriter, _ *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]int{"fail": s.failedHooks, "slow": s.slowHooks})
	})
	mux.HandleFunc("GET /_webhooks", func(w http.ResponseWriter, _ *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if s.webhooks == nil {
			_, _ = w.Write([]byte("[]"))
			return
		}
		_ = json.NewEncoder(w).Encode(s.webhooks)
	})
	mux.HandleFunc("GET /_fetches", func(w http.ResponseWriter, _ *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		_ = json.NewEncoder(w).Encode(s.fetches)
	})
	log.Fatal(http.ListenAndServe(":8080", mux))
}
