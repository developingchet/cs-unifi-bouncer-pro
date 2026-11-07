package controller

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestListedTMLItemValues(t *testing.T) {
	raw := `{"id":"t1","type":"PORTS","name":"ports","items":[
		{"type":"IP_ADDRESS","value":"198.51.100.7"},
		{"type":"SUBNET","value":"2001:db8::/32"},
		{"type":"PORT_NUMBER","value":443},
		{"type":"PORT_NUMBER","value":8080.0},
		{"type":"IP_ADDRESS","value":"escaped"},
		{"type":"IP_ADDRESS","value":null}
	]}`
	var listed apiTMLV1Listed
	if err := json.Unmarshal([]byte(raw), &listed); err != nil {
		t.Fatal(err)
	}
	got := listed.model()
	want := []string{"198.51.100.7", "2001:db8::/32", "443", "8080", "escaped", ""}
	if got.ID != "t1" || got.Type != "PORTS" || got.Name != "ports" || len(got.Items) != len(want) {
		t.Fatalf("decoded %+v", got)
	}
	for i, item := range got.Items {
		if item.Value != want[i] {
			t.Errorf("item %d value = %q, want %q", i, item.Value, want[i])
		}
	}
	if got.Items[2].Type != "PORT_NUMBER" {
		t.Errorf("item 2 type = %q", got.Items[2].Type)
	}
}

// BenchmarkListedTMLDecode decodes a shard list of 10k addresses, the size a
// full shard reaches.
func BenchmarkListedTMLDecode(b *testing.B) {
	var sb strings.Builder
	sb.WriteString(`{"id":"t1","type":"IPV4_ADDRESSES","name":"crowdsec-block-v4-0","items":[`)
	for i := range 10000 {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, `{"type":"IP_ADDRESS","value":"10.%d.%d.%d"}`, i>>16&255, i>>8&255, i&255)
	}
	sb.WriteString(`]}`)
	raw := []byte(sb.String())
	b.ReportAllocs()
	for b.Loop() {
		var listed apiTMLV1Listed
		if err := json.Unmarshal(raw, &listed); err != nil {
			b.Fatal(err)
		}
		_ = listed.model()
	}
}
