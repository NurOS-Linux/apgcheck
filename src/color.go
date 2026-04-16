// SPDX-FileCopyrightText: m1lkydev, AnmiTaliDev
// SPDX-License-Identifier: GPL-3.0-or-later

package checker

import "os"

type Colors struct {
	Green, Red, Yellow, Blue, Bold, Reset string
}

func NewColors(noColor bool) Colors {
	if noColor || !terminalSupportsColor() {
		return Colors{}
	}
	return Colors{
		Green:  "\033[92m",
		Red:    "\033[91m",
		Yellow: "\033[93m",
		Blue:   "\033[94m",
		Bold:   "\033[1m",
		Reset:  "\033[0m",
	}
}

func terminalSupportsColor() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	term := os.Getenv("TERM")
	if term == "" || term == "dumb" {
		return false
	}
	if !isatty(os.Stdout.Fd()) || !isatty(os.Stderr.Fd()) {
		return false
	}
	return true
}

func isatty(fd uintptr) bool {
	stat, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) != 0
}
