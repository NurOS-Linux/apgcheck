// SPDX-FileCopyrightText: m1lkydev, AnmiTaliDev
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/pflag"

	checker "apgcheck/src"
)

func main() {
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

	colors := checker.NewColors(*noColor)

	if *help {
		pflag.Usage()
		os.Exit(0)
	}

	if *version {
		fmt.Printf("%sapgcheck v%s%s\n", colors.Bold, checker.Version, colors.Reset)
		fmt.Printf("%sAPG file validator for NurOS%s\n", colors.Blue, colors.Reset)
		os.Exit(0)
	}

	if *verbose {
		if *isJson {
			fmt.Fprintf(os.Stderr, "%sError: Verbose mode not compatible with --json%s\n", colors.Red, colors.Reset)
			os.Exit(1)
		}
		if *quiet {
			fmt.Fprintf(os.Stderr, "%sError: Verbose mode not compatible with --quiet%s\n", colors.Red, colors.Reset)
			os.Exit(1)
		}
	}

	if checker.IsEmpty(*apgFile) {
		fmt.Fprintf(os.Stderr, "%sError: No APG file specified%s\n", colors.Red, colors.Reset)
		os.Exit(1)
	}

	c := checker.New(*verbose, *skipSums, colors, *maxSizeMB)

	pathToFolderTMP := "/tmp/apgcheck-" + checker.GenerateRandomNumber()
	if err := checker.ExtractTarXz(*apgFile, pathToFolderTMP, *maxSizeMB*1024*1024, c); err != nil {
		fmt.Fprintf(os.Stderr, "%sExtraction Error: %v%s\n", colors.Red, err, colors.Reset)
		os.RemoveAll(pathToFolderTMP)
		os.Exit(1)
	}

	report := checker.ValidationResponse{
		Version:  *apgVersion,
		File:     *apgFile,
		Errors:   []string{},
		Warnings: []string{},
	}

	var fileErr, jsonErr error
	var status string

	if *apgVersion == 2 {
		fileErr, jsonErr, status = c.CheckV2(pathToFolderTMP)
	} else {
		fileErr, jsonErr, status = c.CheckV1(pathToFolderTMP)
	}

	if fileErr != nil {
		report.Errors = append(report.Errors, fileErr.Error())
	}
	if jsonErr != nil {
		report.Errors = append(report.Errors, jsonErr.Error())
	}

	report.Valid = len(report.Errors) == 0 && status == "good"

	if *isJson && report.Valid {
		metaData, _ := os.ReadFile(filepath.Join(pathToFolderTMP, "metadata.json"))
		var meta map[string]interface{}
		json.Unmarshal(metaData, &meta)
		report.Metadata = meta
	}

	os.RemoveAll(pathToFolderTMP)

	if *isJson {
		out, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(out))
	} else if !*quiet {
		if report.Valid {
			fmt.Printf("%s✓ APG v%d file validation successful%s\n", colors.Green, *apgVersion, colors.Reset)
			fmt.Printf("File: %s\n", *apgFile)
		} else {
			for _, e := range report.Errors {
				fmt.Fprintf(os.Stderr, "%sError: %v%s\n", colors.Red, e, colors.Reset)
			}
		}
	}

	if !report.Valid {
		os.Exit(1)
	}
}
