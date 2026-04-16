// SPDX-FileCopyrightText: m1lkydev, AnmiTaliDev
// SPDX-License-Identifier: GPL-3.0-or-later

package checker

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/ulikunitz/xz"
)

func ExtractTarXz(src, dest string, maxTotalSize int64, c *Checker) error {
	fi, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("cannot stat archive: %w", err)
	}
	archiveSize := fi.Size()
	c.log(fmt.Sprintf("Archive size: %.2f MB", float64(archiveSize)/(1024*1024)))

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

	c.log("Processing archive contents...")
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

func getAvailableSpace(path string) (uint64, error) {
	var stat syscall.Statfs_t
	err := syscall.Statfs(path, &stat)
	if err != nil {
		return 0, err
	}
	return stat.Bavail * uint64(stat.Bsize), nil
}
