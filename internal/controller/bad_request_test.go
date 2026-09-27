package controller

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestResponseStatusError_BadRequestNamesRejectedMember(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantArg string
	}{
		{"classic invalid member", `{"meta":{"rc":"error","args":"203.0.113.77/32","msg":"api.err.FirewallGroupInvalidArgs"},"data":[]}`, "203.0.113.77/32"},
		{"args not a string", `{"meta":{"rc":"error","args":["a","b"],"msg":"api.err.Invalid"}}`, ""},
		{"not json", `bad input`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{StatusCode: http.StatusBadRequest, Body: io.NopCloser(strings.NewReader(tt.body))}
			req, _ := http.NewRequest(http.MethodPut, "https://unifi.test/api/s/default/rest/firewallgroup/1", nil)
			err := responseStatusError(resp, req)
			var bad *ErrBadRequest
			if !errors.As(err, &bad) {
				t.Fatalf("err = %T %v, want *ErrBadRequest", err, err)
			}
			if bad.Arg != tt.wantArg || !strings.Contains(err.Error(), "bad request: ") {
				t.Fatalf("Arg = %q (err %q), want %q", bad.Arg, err, tt.wantArg)
			}
		})
	}
}
