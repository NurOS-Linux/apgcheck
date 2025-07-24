// apgcheck - APG file validator for NurOS
// Licensed under GPL 3.0
// Authors: TheMomer (main), AnmiTaliDev (security patch)

package main

import (
	"archive/tar"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/pflag"
	"github.com/ulikunitz/xz"
)

type Metadata struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Architecture *string  `json:"architecture"`
	Description  string   `json:"description"`
	Maintainer   string   `json:"maintainer"`
	License      *string  `json:"license"`
	Homepage     string   `json:"homepage"`
	Dependencies []string `json:"dependencies"`
	Conflicts    []string `json:"conflicts"`
	Provides     []string `json:"provides"`
	Replaces     []string `json:"replaces"`
}

const (
	// Main
	Version string = "0.1.0"

	// Colors
	ColorGreen string = "\033[92m"
	ColorRed   string = "\033[91m"
	Reset      string = "\033[0m"
)

func extractTarXz(src, dest string) error {
	f, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("Cannot open archive: %w", err)
	}
	defer f.Close()

	xzr, err := xz.NewReader(f)
	if err != nil {
		return fmt.Errorf("Cannot create the XZ-reader: %w", err)
	}

	tr := tar.NewReader(xzr)

	absDest, err := filepath.Abs(dest)
	if err != nil {
		return fmt.Errorf("Cannot get absolute path of destination: %w", err)
	}

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("Error during reading archive: %w", err)
		}

		cleanPath := filepath.Clean(header.Name)
		
		if filepath.IsAbs(cleanPath) {
			return fmt.Errorf("Archive contains absolute path: %s", header.Name)
		}
		
		if strings.HasPrefix(cleanPath, ".."+string(filepath.Separator)) || 
		   strings.Contains(cleanPath, string(filepath.Separator)+".."+string(filepath.Separator)) ||
		   strings.HasSuffix(cleanPath, "..") ||
		   cleanPath == ".." {
			return fmt.Errorf("Archive contains path traversal attempt: %s", header.Name)
		}

		target := filepath.Join(absDest, cleanPath)
		
		absTarget, err := filepath.Abs(target)
		if err != nil {
			return fmt.Errorf("Cannot get absolute path of target: %w", err)
		}
		
		if !strings.HasPrefix(absTarget, absDest+string(filepath.Separator)) && absTarget != absDest {
			return fmt.Errorf("Path traversal detected, target path outside destination: %s", header.Name)
		}

		if len(cleanPath) > 255 {
			return fmt.Errorf("Path too long: %s", header.Name)
		}
		
		if strings.ContainsAny(cleanPath, "\x00") {
			return fmt.Errorf("Path contains null byte: %s", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			err = os.MkdirAll(target, os.FileMode(header.Mode)&0755)
			if err != nil {
				return fmt.Errorf("Failed to create folder: %w", err)
			}
		case tar.TypeReg:
			const maxFileSize = 500 * 1024 * 1024
			if header.Size > maxFileSize {
				return fmt.Errorf("File too large: %s (%d bytes)", header.Name, header.Size)
			}
			
			err = os.MkdirAll(filepath.Dir(target), 0755)
			if err != nil {
				return fmt.Errorf("Failed to create a file path: %w", err)
			}
			
			outFile, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
			if err != nil {
				return fmt.Errorf("Failed to create file: %w", err)
			}
			
			_, err = io.CopyN(outFile, tr, header.Size)
			outFile.Close()
			if err != nil && err != io.EOF {
				return fmt.Errorf("Failed to write file: %w", err)
			}
		case tar.TypeSymlink, tar.TypeLink:
			return fmt.Errorf("Symbolic/hard links not allowed in archive: %s", header.Name)
		default:
			fmt.Printf("Skipping unknown type: %v\n", header.Typeflag)
		}
	}
	return nil
}

func generateRandomNumber() string {
	rand.Seed(time.Now().UnixNano())

	num := ""
	for i := 0; i < 8; i++ {
		digit := rand.Intn(10)
		num += fmt.Sprint(digit)
	}

	return num
}

// Function that checks whether a value is empty.
func IsEmpty[T comparable](value T) bool {
	var zero T
	return value == zero
}

func checkApgFile(dir string) (error, error, string) {
	// Required files/folders
	required := []string{
		"data",
		"md5sums",
		"metadata.json",
	}

	// Checking mandatory files
	for _, name := range required {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return fmt.Errorf("a required file or folder is missing: %s", name), nil, "bad"
		}
	}

	// Checking metadata.json
	metadataPath := filepath.Join(dir, "metadata.json")
	fileData, err := os.ReadFile(metadataPath)
	if err != nil {
		return nil, fmt.Errorf("Failed to reading metadata: %w", err), "bad"
	}

	var meta Metadata
	if err := json.Unmarshal(fileData, &meta); err != nil {
		return nil, fmt.Errorf("Metadata invalid JSON: %w", err), "bad"
	}

	// Checking fields that should NOT be empty
	var missingFields []string
	if meta.Name == "" {
		missingFields = append(missingFields, "name")
	}
	if meta.Version == "" {
		missingFields = append(missingFields, "version")
	}
	if meta.Description == "" {
		missingFields = append(missingFields, "description")
	}
	if meta.Maintainer == "" {
		missingFields = append(missingFields, "maintainer")
	}
	if meta.Homepage == "" {
		missingFields = append(missingFields, "homepage")
	}
	if meta.Dependencies == nil {
		missingFields = append(missingFields, "dependencies")
	}
	if meta.Conflicts == nil {
		missingFields = append(missingFields, "conflicts")
	}
	if meta.Provides == nil {
		missingFields = append(missingFields, "provides")
	}
	if meta.Replaces == nil {
		missingFields = append(missingFields, "replaces")
	}

	if len(missingFields) > 0 {
		return nil, fmt.Errorf("Missing or empty fields in metadata: %v", missingFields), "bad"
	}

	// All okay
	return nil, nil, "good"
}

func main() {
	// Arguments
	apgFile := pflag.StringP("apgfile", "a", "", "path to apg file")
	pflag.Parse()

	if IsEmpty(*apgFile) {
		fmt.Println("No apg file specified in the parameter. Interrupt...")
		os.Exit(0)
	}

	pathToFolderTMP := "/tmp/apgcheck-" + generateRandomNumber()

	extractErr := extractTarXz(*apgFile, pathToFolderTMP)
	if extractErr != nil {
		fmt.Println(ColorRed + extractErr.Error() + Reset)
		os.RemoveAll(pathToFolderTMP)
		os.Exit(1)
	}

	fileErr, jsonErr, status := checkApgFile(pathToFolderTMP)

	if fileErr != nil {
		fmt.Println(ColorRed + "File error:", fileErr.Error() + Reset)
		os.RemoveAll(pathToFolderTMP)
		os.Exit(1)
	}
	if jsonErr != nil {
		fmt.Println(ColorRed + "JSON error:", jsonErr.Error() + Reset)
		os.RemoveAll(pathToFolderTMP)
		os.Exit(1)
	}
	if status == "good" {
		fmt.Println(ColorGreen + "The file specified is the correct apg" + Reset)
	}

	err := os.RemoveAll(pathToFolderTMP)
	if err != nil {
		fmt.Println(ColorRed + "Failed to delete temp folder:", err.Error() + Reset)
	}
}