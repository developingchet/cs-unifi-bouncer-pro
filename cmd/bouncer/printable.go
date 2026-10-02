package main

import (
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// printable returns s with every character a terminal could interpret
// replaced by a visible escape: control characters (including ESC, which
// starts ANSI sequences, and tab and newline, which break table layout),
// bidirectional overrides, and invalid UTF-8. Values read from the ban
// database or supplied by a controller are otherwise printed verbatim, so a
// crafted scenario or origin name could redraw the operator's terminal.
func printable(s string) string {
	if strings.IndexFunc(s, func(r rune) bool { return !unicode.IsPrint(r) }) < 0 && utf8.ValidString(s) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			b.WriteString(`\x` + strconv.FormatUint(uint64(s[i])|0x100, 16)[1:])
		case unicode.IsPrint(r):
			b.WriteRune(r)
		default:
			quoted := strconv.QuoteRuneToASCII(r)
			b.WriteString(quoted[1 : len(quoted)-1])
		}
		i += size
	}
	return b.String()
}
