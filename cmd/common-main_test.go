// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package cmd

import (
	"strings"
	"testing"
)

func TestIsDomainName(t *testing.T) {
	label63 := strings.Repeat("a", 63)
	for _, tc := range []struct {
		name string
		ok   bool
	}{
		{"", false},
		{".", true},
		{"gateway.storjshare.io", true},
		{"gateway.storjshare.io.", true},
		{"localhost", true},
		{"under_score.example", true},
		{".example.com", false},
		{"example..com", false},
		{label63 + ".com", true},
		{label63 + "a.com", false},
		// 4 labels of 63 octets are 257 octets in wire format.
		{strings.Repeat(label63+".", 3) + strings.Repeat("a", 61), true},
		{strings.Repeat(label63+".", 4), false},
	} {
		if got := isDomainName(tc.name); got != tc.ok {
			t.Errorf("isDomainName(%q) = %v, want %v", tc.name, got, tc.ok)
		}
	}
}
