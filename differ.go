package main

import (
	"github.com/pmezard/go-difflib/difflib"
)

// UnifiedDiff returns a unified-format diff string between before and after.
// Returns ("", false) if there's no textual difference.
// If output exceeds maxBytes, it is truncated and truncated=true.
func UnifiedDiff(before, after []byte, contextLines, maxBytes int) (diff string, truncated bool) {
	ud := difflib.UnifiedDiff{
		A:        difflib.SplitLines(string(before)),
		B:        difflib.SplitLines(string(after)),
		FromFile: "before",
		ToFile:   "after",
		Context:  contextLines,
	}
	s, err := difflib.GetUnifiedDiffString(ud)
	if err != nil || s == "" {
		return "", false
	}
	if maxBytes > 0 && len(s) > maxBytes {
		return s[:maxBytes] + "\n... [diff truncated]\n", true
	}
	return s, false
}
