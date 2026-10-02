package main

import "testing"

func TestPrintable(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain text", "ssh-bruteforce", "ssh-bruteforce"},
		{"empty", "", ""},
		{"non-ASCII letters", "crowdsec/héllo-日本", "crowdsec/héllo-日本"},
		{"ANSI escape", "\x1b[2J\x1b[31mowned", `\x1b[2J\x1b[31mowned`},
		{"carriage return", "ok\rfake", `ok\rfake`},
		{"newline and tab", "a\nb\tc", `a\nb\tc`},
		{"NUL and DEL", "a\x00b\x7f", `a\x00b\x7f`},
		{"C1 control", "a\u009bb", "a\\u009bb"},
		{"bidi override", "evil\u202egpj.exe", "evil\\u202egpj.exe"},
		{"invalid UTF-8", "a\xffb", `a\xffb`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := printable(tt.in); got != tt.want {
				t.Fatalf("printable(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
