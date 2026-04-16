// SPDX-FileCopyrightText: m1lkydev, AnmiTaliDev
// SPDX-License-Identifier: GPL-3.0-or-later

package checker

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Checker struct {
	Verbose       bool
	SkipChecksums bool
	Colors        Colors
	MaxSizeMB     int64
}

func New(verbose, skipChecksums bool, colors Colors, maxSizeMB int64) *Checker {
	return &Checker{
		Verbose:       verbose,
		SkipChecksums: skipChecksums,
		Colors:        colors,
		MaxSizeMB:     maxSizeMB,
	}
}

func (c *Checker) log(detail string) {
	if !c.Verbose {
		return
	}
	fmt.Fprintf(os.Stderr, "%s[*] %s %s\n", c.Colors.Blue, detail, c.Colors.Reset)
}

func (c *Checker) CheckV1(dir string) (error, error, string) {
	c.log("Checking the archive structure...")
	required := []string{"data", "md5sums", "metadata.json"}
	for _, name := range required {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return fmt.Errorf("required file or directory missing: '%s'", name), nil, "bad"
		}
	}

	if !c.SkipChecksums {
		c.log("Verifying MD5 checksums...")
		if err := verifyHashes(dir, "md5sums", "MD5", c); err != nil {
			return err, nil, "bad"
		}
	} else {
		c.log("Skipping checksum verification.")
	}

	c.log("Reading the metadata...")
	metadataPath := filepath.Join(dir, "metadata.json")
	fileData, err := os.ReadFile(metadataPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read metadata: %w", err), "bad"
	}

	var meta MetadataV1
	if err := json.Unmarshal(fileData, &meta); err != nil {
		return nil, fmt.Errorf("metadata invalid JSON: %w", err), "bad"
	}

	c.log("Checking the metadata...")
	var missingFields []string
	if meta.Name == "" {
		c.log("'name' not found!")
		missingFields = append(missingFields, "name")
	}
	if meta.Version == "" {
		c.log("'version' not found!")
		missingFields = append(missingFields, "version")
	}
	if meta.Description == "" {
		c.log("'description' not found!")
		missingFields = append(missingFields, "description")
	}
	if meta.Maintainer == "" {
		c.log("'maintainer' not found!")
		missingFields = append(missingFields, "maintainer")
	}
	if meta.Homepage == "" {
		c.log("'homepage' not found!")
		missingFields = append(missingFields, "homepage")
	}
	if meta.Dependencies == nil {
		c.log("'dependencies' not found!")
		missingFields = append(missingFields, "dependencies")
	}
	if meta.Conflicts == nil {
		c.log("'conflicts' not found!")
		missingFields = append(missingFields, "conflicts")
	}
	if meta.Provides == nil {
		c.log("'provides' not found!")
		missingFields = append(missingFields, "provides")
	}
	if meta.Replaces == nil {
		c.log("'replaces' not found!")
		missingFields = append(missingFields, "replaces")
	}

	if len(missingFields) > 0 {
		return nil, fmt.Errorf("missing or empty required metadata fields: %v", missingFields), "bad"
	}
	return nil, nil, "good"
}

func (c *Checker) CheckV2(dir string) (error, error, string) {
	c.log("Checking the archive structure...")
	required := []string{"data", "md5sums", "crc32sums", "metadata.json"}
	for _, name := range required {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return fmt.Errorf("required file or directory missing: '%s'", name), nil, "bad"
		}
	}

	if !c.SkipChecksums {
		c.log("Verifying MD5 checksums...")
		if err := verifyHashes(dir, "md5sums", "MD5", c); err != nil {
			return err, nil, "bad"
		}
		c.log("Verifying CRC32 checksums...")
		if err := verifyHashes(dir, "crc32sums", "CRC32", c); err != nil {
			return err, nil, "bad"
		}
	} else {
		c.log("Skipping checksum verification.")
	}

	c.log("Reading the metadata...")
	metadataPath := filepath.Join(dir, "metadata.json")
	fileData, err := os.ReadFile(metadataPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read metadata: %w", err), "bad"
	}

	var meta MetadataV2
	if err := json.Unmarshal(fileData, &meta); err != nil {
		return nil, fmt.Errorf("metadata invalid JSON: %w", err), "bad"
	}

	c.log("Checking the metadata...")
	var missingFields []string
	if meta.Name == "" {
		c.log("'name' not found!")
		missingFields = append(missingFields, "name")
	}
	if meta.Version == "" {
		c.log("'version' not found!")
		missingFields = append(missingFields, "version")
	}
	if meta.Type == "" {
		c.log("'type' not found!")
		missingFields = append(missingFields, "type")
	}
	if meta.Description == "" {
		c.log("'description' not found!")
		missingFields = append(missingFields, "description")
	}
	if meta.Maintainer == "" {
		c.log("'maintainer' not found!")
		missingFields = append(missingFields, "maintainer")
	}
	if meta.Homepage == "" {
		c.log("'homepage' not found!")
		missingFields = append(missingFields, "homepage")
	}
	if meta.Tags == nil {
		c.log("'tags' not found!")
		missingFields = append(missingFields, "tags")
	}
	if meta.Dependencies == nil {
		c.log("'dependencies' not found!")
		missingFields = append(missingFields, "dependencies")
	}
	if meta.Conflicts == nil {
		c.log("'conflicts' not found!")
		missingFields = append(missingFields, "conflicts")
	}
	if meta.Provides == nil {
		c.log("'provides' not found!")
		missingFields = append(missingFields, "provides")
	}
	if meta.Replaces == nil {
		c.log("'replaces' not found!")
		missingFields = append(missingFields, "replaces")
	}
	if meta.Conf == nil {
		c.log("'conf' not found!")
		missingFields = append(missingFields, "conf")
	}

	if len(missingFields) > 0 {
		return nil, fmt.Errorf("missing or empty required metadata fields: %v", missingFields), "bad"
	}
	return nil, nil, "good"
}
