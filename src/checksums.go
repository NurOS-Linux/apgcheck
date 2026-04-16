// SPDX-FileCopyrightText: m1lkydev, AnmiTaliDev
// SPDX-License-Identifier: GPL-3.0-or-later

package checker

import (
	"crypto/md5"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
)

func verifyHashes(dir, sumsFile, algo string, c *Checker) error {
	filePath := filepath.Join(dir, sumsFile)
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", sumsFile, err)
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		relPath := parts[0]
		expectedHash := parts[1]
		targetFile := filepath.Join(dir, "data", relPath)

		c.log(fmt.Sprintf("Checking %s for %s...", algo, relPath))

		fileData, err := os.ReadFile(targetFile)
		if err != nil {
			return fmt.Errorf("file missing or unreadable: %s (checked at %s)", relPath, targetFile)
		}

		var actualHash string
		if algo == "MD5" {
			actualHash = fmt.Sprintf("%x", md5.Sum(fileData))
		} else if algo == "CRC32" {
			table := crc32.MakeTable(crc32.IEEE)
			actualHash = fmt.Sprintf("%08x", crc32.Checksum(fileData, table))
		}

		if strings.ToLower(actualHash) != strings.ToLower(expectedHash) {
			return fmt.Errorf("%s mismatch for %s, expected: %s, got: %s", algo, relPath, expectedHash, actualHash)
		}
	}
	return nil
}
