package service

import (
	"fmt"
	"strconv"
	"strings"
)

// ZCode builds use a separate release source. Official releases remain available
// to ordinary builds, but must never silently replace a deployed ZCode binary.
const ZCodeBuildType = "zcode"
const ZCodeUpdateRepository = "timfaner/sub2api"
const ZCodeCompatibilityAsset = "zcode-compatible-v1.txt"

func (s *UpdateService) releaseRepository() string {
	if s.buildType == ZCodeBuildType {
		return ZCodeUpdateRepository
	}
	return githubRepo
}
func (s *UpdateService) validateReleaseCompatibility(assets []Asset) error {
	if s.buildType != ZCodeBuildType {
		return nil
	}
	for _, a := range assets {
		if a.Name == ZCodeCompatibilityAsset {
			return nil
		}
	}
	return fmt.Errorf("ZCode build requires a verified ZCode-compatible release from %s; ordinary upstream packages cannot preserve this integration", ZCodeUpdateRepository)
}
func (s *UpdateService) releaseCompatible(r *GitHubRelease) bool {
	if r == nil {
		return false
	}
	assets := make([]Asset, len(r.Assets))
	for i, a := range r.Assets {
		assets[i] = Asset{Name: a.Name, DownloadURL: a.BrowserDownloadURL, Size: a.Size}
	}
	return s.validateReleaseCompatibility(assets) == nil
}

// Retain upstream semver ordering while permitting multiple tested ZCode fixes
// against the same upstream version (for example 0.2.17-zcode.1 -> zcode.2).
func (s *UpdateService) compareReleaseVersions(a, b string) int {
	if n := compareVersions(a, b); n != 0 || s.buildType != ZCodeBuildType {
		return n
	}
	revision := func(v string) int {
		_, suffix, ok := strings.Cut(v, "-zcode.")
		if !ok {
			return 0
		}
		n, err := strconv.Atoi(suffix)
		if err != nil || n < 0 {
			return 0
		}
		return n
	}
	x, y := revision(a), revision(b)
	if x < y {
		return -1
	}
	if x > y {
		return 1
	}
	return 0
}
