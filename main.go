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
			return fmt.Errorf("required file or directory missing: '%s'", name), nil, "bad"
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
		return nil, fmt.Errorf("missing or empty required metadata fields: %v", missingFields), "bad"
	}

	// All okay
	return nil, nil, "good"
}

func main() {
	// Initialize colors first
	initColors()
	
	// Arguments
	apgFile := pflag.StringP("apgfile", "a", "", "path to APG file to validate")
	version := pflag.BoolP("version", "v", false, "show version information")
	help := pflag.BoolP("help", "h", false, "show this help message")
	noColor := pflag.Bool("no-color", false, "disable colored output")
	
	pflag.Usage = func() {
		fmt.Printf("%sapgcheck v%s%s - APG file validator for NurOS\n\n", ColorBold, Version, Reset)
		fmt.Println("Usage:")
		fmt.Printf("  %s [options]\n\n", os.Args[0])
		fmt.Println("Options:")
		pflag.PrintDefaults()
		fmt.Println("\nExample:")
		fmt.Printf("  %s -a package.apg\n", os.Args[0])
	}
	
	pflag.Parse()
	
	// Handle --no-color flag
	if *noColor {
		ColorGreen = ""
		ColorRed = ""
		ColorYellow = ""
		ColorBlue = ""
		ColorBold = ""
		Reset = ""
	}
	
	if *help {
		pflag.Usage()
		os.Exit(0)
	}

	if *version {
		fmt.Printf("%sapgcheck v%s%s\n", ColorBold, Version, Reset)
		fmt.Printf("%sAPG file validator for NurOS%s\n", ColorBlue, Reset)
		fmt.Println("Licensed under GPL 3.0")
		fmt.Println("Copyright © 2024 NurOS Contributors")
		os.Exit(0)
	}

	if IsEmpty(*apgFile) {
		fmt.Fprintf(os.Stderr, "%sError: No APG file specified%s\n", ColorRed, Reset)
		fmt.Fprintf(os.Stderr, "Use --help for usage information\n")
		os.Exit(1)
	}

	pathToFolderTMP := "/tmp/apgcheck-" + generateRandomNumber()

	extractErr := extractTarXz(*apgFile, pathToFolderTMP)
	if extractErr != nil {
		fmt.Fprintf(os.Stderr, "%sExtraction Error: %v%s\n", ColorRed, extractErr, Reset)
		fmt.Fprintf(os.Stderr, "Failed to extract APG file: %s\n", *apgFile)
		os.RemoveAll(pathToFolderTMP)
		os.Exit(1)
	}

	fileErr, jsonErr, status := checkApgFile(pathToFolderTMP)

	if fileErr != nil {
		fmt.Fprintf(os.Stderr, "%sValidation Error: %v%s\n", ColorRed, fileErr, Reset)
		fmt.Fprintf(os.Stderr, "APG file structure is invalid\n")
		os.RemoveAll(pathToFolderTMP)
		os.Exit(1)
	}
	if jsonErr != nil {
		fmt.Fprintf(os.Stderr, "%sMetadata Error: %v%s\n", ColorRed, jsonErr, Reset)
		fmt.Fprintf(os.Stderr, "APG metadata is invalid or corrupted\n")
		os.RemoveAll(pathToFolderTMP)
		os.Exit(1)
	}
	if status == "good" {
		fmt.Printf("%s✓ APG file validation successful%s\n", ColorGreen, Reset)
		fmt.Printf("File: %s\n", *apgFile)
	}

	err := os.RemoveAll(pathToFolderTMP)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%sWarning: Failed to cleanup temporary files: %v%s\n", ColorYellow, err, Reset)
	}
}