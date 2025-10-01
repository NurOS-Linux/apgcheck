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

type MetadataV1 struct {
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

type MetadataV2 struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Type         string   `json:"type"`
	Architecture *string  `json:"architecture"`
	Description  string   `json:"description"`
	Maintainer   string   `json:"maintainer"`
	License      *string  `json:"license"`
	Tags         []string `json:"tags"`
	Homepage     string   `json:"homepage"`
	Dependencies []string `json:"dependencies"`
	Conflicts    []string `json:"conflicts"`
	Provides     []string `json:"provides"`
	Replaces     []string `json:"replaces"`
	Conf         []string `json:"conf"`
}

const (
	// Main
	Version string = "0.2.0"
)

// Color support variables
var (
	ColorGreen  string
	ColorRed    string
	ColorYellow string
	ColorBlue   string
	ColorBold   string
	Reset       string
)

// initColors initializes color codes based on terminal capabilities
func initColors() {
	if isTerminalSupportsColor() {
		ColorGreen = "\033[92m"
		ColorRed = "\033[91m"
		ColorYellow = "\033[93m"
		ColorBlue = "\033[94m"
		ColorBold = "\033[1m"
		Reset = "\033[0m"
	} else {
		// No color support - leave empty
		ColorGreen = ""
		ColorRed = ""
		ColorYellow = ""
		ColorBlue = ""
		ColorBold = ""
		Reset = ""
	}
}

// isTerminalSupportsColor checks if terminal supports colors
func isTerminalSupportsColor() bool {
	// Check NO_COLOR environment variable
	if os.Getenv("NO_COLOR") != "" {
		return false
	}

	// Check TERM environment variable
	term := os.Getenv("TERM")
	if term == "" || term == "dumb" {
		return false
	}

	// Check if output is redirected
	if !isatty(os.Stdout.Fd()) || !isatty(os.Stderr.Fd()) {
		return false
	}

	return true
}

// isatty checks if file descriptor is a terminal
func isatty(fd uintptr) bool {
	// Simple check for Unix-like systems
	// On Windows this would need different implementation
	stat, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) != 0
}

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
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	num := ""
	for i := 0; i < 8; i++ {
		digit := r.Intn(10)
		num += fmt.Sprint(digit)
	}

	return num
}

// Function that checks whether a value is empty.
func IsEmpty[T comparable](value T) bool {
	var zero T
	return value == zero
}

func checkApgFileV1(dir string) (error, error, string) {
	required := []string{"data", "md5sums", "metadata.json"}
	for _, name := range required {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return fmt.Errorf("required file or directory missing: '%s'", name), nil, "bad"
		}
	}

	metadataPath := filepath.Join(dir, "metadata.json")
	fileData, err := os.ReadFile(metadataPath)
	if err != nil {
		return nil, fmt.Errorf("Failed to reading metadata: %w", err), "bad"
	}

	var meta MetadataV1
	if err := json.Unmarshal(fileData, &meta); err != nil {
		return nil, fmt.Errorf("Metadata invalid JSON: %w", err), "bad"
	}

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
		return nil, fmt.Errorf("missing or empty required metadata fields: %v", missingFields), "bad"
	}
	return nil, nil, "good"
}

func checkApgFileV2(dir string) (error, error, string) {
	required := []string{"data", "md5sums", "metadata.json"}
	for _, name := range required {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return fmt.Errorf("required file or directory missing: '%s'", name), nil, "bad"
		}
	}

	metadataPath := filepath.Join(dir, "metadata.json")
	fileData, err := os.ReadFile(metadataPath)
	if err != nil {
		return nil, fmt.Errorf("Failed to reading metadata: %w", err), "bad"
	}

	var meta MetadataV2
	if err := json.Unmarshal(fileData, &meta); err != nil {
		return nil, fmt.Errorf("Metadata invalid JSON: %w", err), "bad"
	}

	var missingFields []string
	if meta.Name == "" {
		missingFields = append(missingFields, "name")
	}
	if meta.Version == "" {
		missingFields = append(missingFields, "version")
	}
	if meta.Type == "" {
		missingFields = append(missingFields, "type")
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
	if meta.Tags == nil {
		missingFields = append(missingFields, "tags")
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
	if meta.Conf == nil {
		missingFields = append(missingFields, "conf")
	}

	if len(missingFields) > 0 {
		return nil, fmt.Errorf("missing or empty required metadata fields: %v", missingFields), "bad"
	}
	return nil, nil, "good"
}

func main() {
	initColors()

	apgFile := pflag.StringP("apgfile", "a", "", "path to APG file to validate")
	apgVersion := pflag.IntP("apg-version", "A", 1, "APG format version (1 or 2)")
	version := pflag.BoolP("version", "v", false, "show version information")
	help := pflag.BoolP("help", "h", false, "show this help message")
	noColor := pflag.Bool("no-color", false, "disable colored output")

	pflag.Parse()

	if *help {
		pflag.Usage()
		os.Exit(0)
	}

	if *noColor {
		ColorGreen = ""
		ColorRed = ""
		ColorYellow = ""
		ColorBlue = ""
		ColorBold = ""
		Reset = ""
	}

	if *version {
		fmt.Printf("%sapgcheck v%s%s\n", ColorBold, Version, Reset)
		fmt.Printf("%sAPG file validator for NurOS%s\n", ColorBlue, Reset)
		fmt.Println("Licensed under GPL 3.0")
		os.Exit(0)
	}

	if IsEmpty(*apgFile) {
		fmt.Fprintf(os.Stderr, "%sError: No APG file specified%s\n", ColorRed, Reset)
		os.Exit(1)
	}

	pathToFolderTMP := "/tmp/apgcheck-" + generateRandomNumber()
	if err := extractTarXz(*apgFile, pathToFolderTMP); err != nil {
		fmt.Fprintf(os.Stderr, "%sExtraction Error: %v%s\n", ColorRed, err, Reset)
		os.RemoveAll(pathToFolderTMP)
		os.Exit(1)
	}

	var fileErr, jsonErr error
	var status string

	if *apgVersion == 2 {
		fileErr, jsonErr, status = checkApgFileV2(pathToFolderTMP)
	} else {
		fileErr, jsonErr, status = checkApgFileV1(pathToFolderTMP)
	}

	if fileErr != nil {
		fmt.Fprintf(os.Stderr, "%sValidation Error: %v%s\n", ColorRed, fileErr, Reset)
		os.Exit(1)
	}
	if jsonErr != nil {
		fmt.Fprintf(os.Stderr, "%sMetadata Error: %v%s\n", ColorRed, jsonErr, Reset)
		os.Exit(1)
	}
	if status == "good" {
		fmt.Printf("%s✓ APG v%d file validation successful%s\n", ColorGreen, *apgVersion, Reset)
		fmt.Printf("File: %s\n", *apgFile)
	}

	os.RemoveAll(pathToFolderTMP)
}
