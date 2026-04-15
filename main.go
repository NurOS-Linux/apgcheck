// apgcheck - APG file validator for NurOS
// Licensed under GPL 3.0
// Authors: m1lkydev (main), AnmiTaliDev (security patch)

package main

import (
	"archive/tar"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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

type ValidationResponse struct {
	Valid    bool                   `json:"valid"`
	Version  int                    `json:"version"`
	File     string                 `json:"file"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
	Errors   []string               `json:"errors"`
	Warnings []string               `json:"warnings"`
}

const (
	Version string = "0.3.0"
)

var (
	verboseMode   bool
	skipChecksums bool
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

// The log function logs detailed information if the --verbose flag is enabled
func log(detail string) {
	if !verboseMode {
		return
	}
	fmt.Fprintf(os.Stderr, "%s[*] %s %s\n", ColorBlue, detail, Reset)
}

func extractTarXz(src, dest string, maxTotalSize int64) error {
	fi, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("cannot stat archive: %w", err)
	}
	archiveSize := fi.Size()
	log(fmt.Sprintf("Archive size: %.2f MB", float64(archiveSize)/(1024*1024)))

	available, err := getAvailableSpace(filepath.Dir(dest))
	if err == nil {
		if uint64(archiveSize) > available {
			return fmt.Errorf("not enough space in destination: need %d, have %d", archiveSize, available)
		}
	}

	f, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("cannot open archive: %w", err)
	}
	defer f.Close()

	xzr, err := xz.NewReader(f)
	if err != nil {
		return fmt.Errorf("cannot create the XZ-reader: %w", err)
	}

	tr := tar.NewReader(xzr)
	absDest, _ := filepath.Abs(dest)

	var currentTotalSize int64

	log("Processing archive contents...")
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("error during reading archive: %w", err)
		}

		currentTotalSize += header.Size
		if currentTotalSize > maxTotalSize {
			return fmt.Errorf("tar-bomb detected or size limit exceeded (> %d MB)", maxTotalSize/(1024*1024))
		}

		cleanPath := filepath.Clean(header.Name)
		target := filepath.Join(absDest, cleanPath)

		switch header.Typeflag {
		case tar.TypeDir:
			os.MkdirAll(target, 0755)
		case tar.TypeReg:
			if header.Size > maxTotalSize {
				return fmt.Errorf("file too large: %s", header.Name)
			}

			os.MkdirAll(filepath.Dir(target), 0755)
			outFile, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
			if err != nil {
				return fmt.Errorf("failed to create file: %w", err)
			}

			_, err = io.CopyN(outFile, tr, header.Size)
			outFile.Close()
			if err != nil && err != io.EOF {
				return fmt.Errorf("failed to write file: %w", err)
			}
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

func getAvailableSpace(path string) (uint64, error) {
	var stat syscall.Statfs_t
	err := syscall.Statfs(path, &stat)
	if err != nil {
		return 0, err
	}
	return stat.Bavail * uint64(stat.Bsize), nil
}

func verifyHashes(dir string, sumsFile string, algo string) error {
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

		if verboseMode {
			log(fmt.Sprintf("Checking %s for %s...", algo, relPath))
		}

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

func checkApgFileV1(dir string) (error, error, string) {
	log("Checking the archive structure...")
	required := []string{"data", "md5sums", "metadata.json"}
	for _, name := range required {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return fmt.Errorf("required file or directory missing: '%s'", name), nil, "bad"
		}
	}

	if !skipChecksums {
		log("Verifying MD5 checksums...")
		if err := verifyHashes(dir, "md5sums", "MD5"); err != nil {
			return err, nil, "bad"
		}
	} else {
		log("Skipping checksum verification.")
	}

	log("Reading the metadata...")
	metadataPath := filepath.Join(dir, "metadata.json")
	fileData, err := os.ReadFile(metadataPath)
	if err != nil {
		return nil, fmt.Errorf("Failed to reading metadata: %w", err), "bad"
	}

	var meta MetadataV1
	if err := json.Unmarshal(fileData, &meta); err != nil {
		return nil, fmt.Errorf("Metadata invalid JSON: %w", err), "bad"
	}

	log("Checking the metadata...")
	var missingFields []string
	if meta.Name == "" {
		log("'name' not found!")
		missingFields = append(missingFields, "name")
	}
	if meta.Version == "" {
		log("'version' not found!")
		missingFields = append(missingFields, "version")
	}
	if meta.Description == "" {
		log("'description' not found!")
		missingFields = append(missingFields, "description")
	}
	if meta.Maintainer == "" {
		log("'maintainer' not found!")
		missingFields = append(missingFields, "maintainer")
	}
	if meta.Homepage == "" {
		log("'homepage' not found!")
		missingFields = append(missingFields, "homepage")
	}
	if meta.Dependencies == nil {
		log("'dependencies' not found!")
		missingFields = append(missingFields, "dependencies")
	}
	if meta.Conflicts == nil {
		log("'conflicts' not found!")
		missingFields = append(missingFields, "conflicts")
	}
	if meta.Provides == nil {
		log("'provides' not found!")
		missingFields = append(missingFields, "provides")
	}
	if meta.Replaces == nil {
		log("'replaces' not found!")
		missingFields = append(missingFields, "replaces")
	}

	if len(missingFields) > 0 {
		return nil, fmt.Errorf("missing or empty required metadata fields: %v", missingFields), "bad"
	}
	return nil, nil, "good"
}

func checkApgFileV2(dir string) (error, error, string) {
	log("Checking the archive structure...")
	required := []string{"data", "md5sums", "crc32sums", "metadata.json"}
	for _, name := range required {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return fmt.Errorf("required file or directory missing: '%s'", name), nil, "bad"
		}
	}

	if !skipChecksums {
		log("Verifying MD5 checksums...")
		if err := verifyHashes(dir, "md5sums", "MD5"); err != nil {
			return err, nil, "bad"
		}

		log("Verifying CRC32 checksums...")
		if err := verifyHashes(dir, "crc32sums", "CRC32"); err != nil {
			return err, nil, "bad"
		}
	} else {
		log("Skipping checksum verification.")
	}

	log("Reading the metadata...")
	metadataPath := filepath.Join(dir, "metadata.json")
	fileData, err := os.ReadFile(metadataPath)
	if err != nil {
		return nil, fmt.Errorf("Failed to reading metadata: %w", err), "bad"
	}

	var meta MetadataV2
	if err := json.Unmarshal(fileData, &meta); err != nil {
		return nil, fmt.Errorf("Metadata invalid JSON: %w", err), "bad"
	}

	log("Checking the metadata...")
	var missingFields []string
	if meta.Name == "" {
		log("'name' not found!")
		missingFields = append(missingFields, "name")
	}
	if meta.Version == "" {
		log("'version' not found!")
		missingFields = append(missingFields, "version")
	}
	if meta.Type == "" {
		log("'type' not found!")
		missingFields = append(missingFields, "type")
	}
	if meta.Description == "" {
		log("'description' not found!")
		missingFields = append(missingFields, "description")
	}
	if meta.Maintainer == "" {
		log("'maintainer' not found!")
		missingFields = append(missingFields, "maintainer")
	}
	if meta.Homepage == "" {
		log("'homepage' not found!")
		missingFields = append(missingFields, "homepage")
	}
	if meta.Tags == nil {
		log("'tags' not found!")
		missingFields = append(missingFields, "tags")
	}
	if meta.Dependencies == nil {
		log("'dependencies' not found!")
		missingFields = append(missingFields, "dependencies")
	}
	if meta.Conflicts == nil {
		log("'conflicts' not found!")
		missingFields = append(missingFields, "conflicts")
	}
	if meta.Provides == nil {
		log("'provides' not found!")
		missingFields = append(missingFields, "provides")
	}
	if meta.Replaces == nil {
		log("'replaces' not found!")
		missingFields = append(missingFields, "replaces")
	}
	if meta.Conf == nil {
		log("'conf' not found!")
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
	quiet := pflag.BoolP("quiet", "q", false, "suppress output")
	isJson := pflag.BoolP("json", "j", false, "output in JSON format")
	verbose := pflag.BoolP("verbose", "V", false, "verbose mode")
	skipSums := pflag.Bool("skip-checksums", false, "skip verification of MD5 and CRC32 hashes")
	maxSizeMB := pflag.Int64("max-size", 500, "maximum allowed total decompression size in MB")

	pflag.Parse()

	verboseMode = *verbose
	skipChecksums = *skipSums

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

	if verboseMode {
		if *isJson {
			fmt.Fprintf(os.Stderr, "%sError: Verbose mode not compatible with --json%s\n", ColorRed, Reset)
			os.Exit(1)
		}
		if *quiet {
			fmt.Fprintf(os.Stderr, "%sError: Verbose mode not compatible with --quiet%s\n", ColorRed, Reset)
			os.Exit(1)
		}
	}

	if IsEmpty(*apgFile) {
		fmt.Fprintf(os.Stderr, "%sError: No APG file specified%s\n", ColorRed, Reset)
		os.Exit(1)
	}

	log("Extracting the archive...")
	pathToFolderTMP := "/tmp/apgcheck-" + generateRandomNumber()
	if err := extractTarXz(*apgFile, pathToFolderTMP, *maxSizeMB*1024*1024); err != nil {
		fmt.Fprintf(os.Stderr, "%sExtraction Error: %v%s\n", ColorRed, err, Reset)
		os.RemoveAll(pathToFolderTMP)
		os.Exit(1)
	}

	report := ValidationResponse{
		Version:  *apgVersion,
		File:     *apgFile,
		Errors:   []string{},
		Warnings: []string{},
	}

	var fileErr, jsonErr error
	var status string

	if *apgVersion == 2 {
		fileErr, jsonErr, status = checkApgFileV2(pathToFolderTMP)
	} else {
		fileErr, jsonErr, status = checkApgFileV1(pathToFolderTMP)
	}

	if fileErr != nil {
		report.Errors = append(report.Errors, fileErr.Error())
	}
	if jsonErr != nil {
		report.Errors = append(report.Errors, jsonErr.Error())
	}

	report.Valid = (len(report.Errors) == 0 && status == "good")

	if *isJson && report.Valid {
		metaData, _ := os.ReadFile(filepath.Join(pathToFolderTMP, "metadata.json"))
		var meta map[string]interface{}
		json.Unmarshal(metaData, &meta)
		report.Metadata = meta
	}

	log("Removing the temporary folder...")
	os.RemoveAll(pathToFolderTMP)

	if *isJson {
		out, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(out))
	} else if !*quiet {
		if report.Valid {
			fmt.Printf("%s✓ APG v%d file validation successful%s\n", ColorGreen, *apgVersion, Reset)
			fmt.Printf("File: %s\n", *apgFile)
		} else {
			for _, e := range report.Errors {
				fmt.Fprintf(os.Stderr, "%sError: %v%s\n", ColorRed, e, Reset)
			}
		}
	}

	if !report.Valid {
		os.Exit(1)
	}
}
