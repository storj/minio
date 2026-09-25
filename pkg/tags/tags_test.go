// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package tags

import (
	"strings"
	"testing"
)

func TestParseObjectTags(t *testing.T) {
	for _, tc := range []struct {
		tags string
		ok   bool
	}{
		{"key=value", true},
		{"project=%C3%A9t%C3%A9&owner=J%C3%BCrgen", true}, // UTF-8 letters
		{"a=b%21%2A%2C%28%29", true},                      // !*,()
		{"a=", true},
		{"=value", false},
		{"a=b%26c", false}, // & in value
		{"a=" + strings.Repeat("v", 257), false},
	} {
		_, err := ParseObjectTags(tc.tags)
		if (err == nil) != tc.ok {
			t.Errorf("ParseObjectTags(%q): got err %v, want ok %v", tc.tags, err, tc.ok)
		}
	}
}
