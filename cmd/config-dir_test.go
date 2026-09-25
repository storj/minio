// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package cmd

import (
	"os/user"
	"runtime"
	"testing"
)

func TestUserHomeDir(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "plan9" {
		t.Skip("home directory isn't read from $HOME")
	}

	t.Setenv("HOME", "/custom/home")
	if dir, err := userHomeDir(); err != nil || dir != "/custom/home" {
		t.Fatalf("with $HOME: got %q, %v", dir, err)
	}

	u, err := user.Current()
	if err != nil || u.HomeDir == "" {
		t.Skipf("user database has no home directory: %v", err)
	}
	t.Setenv("HOME", "")
	if dir, err := userHomeDir(); err != nil || dir != u.HomeDir {
		t.Fatalf("without $HOME: got %q, %v, want %q", dir, err, u.HomeDir)
	}
}
