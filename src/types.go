// SPDX-FileCopyrightText: m1lkydev, AnmiTaliDev
// SPDX-License-Identifier: GPL-3.0-or-later

package checker

const Version = "0.3.0"

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
