//go:build unit

package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestZCodeUpdaterRejectsOrdinaryPackageBeforeDownload(t *testing.T) {
	s := NewUpdateService(&updateServiceCacheStub{}, &updateServiceGitHubClientStub{}, "0.2.17", ZCodeBuildType)
	require.Equal(t, "timfaner/sub2api", s.releaseRepository())
	require.Error(t, s.applyReleaseAssets(context.Background(), []Asset{{Name: "sub2api_linux_arm64.tar.gz", DownloadURL: "https://github.com/Wei-Shaw/sub2api/releases/download/v9.0.0/sub2api_linux_arm64.tar.gz"}}))
	require.NoError(t, s.validateReleaseCompatibility([]Asset{{Name: ZCodeCompatibilityAsset}}))
	ordinary := NewUpdateService(nil, nil, "0.2.17", "release")
	require.Equal(t, githubRepo, ordinary.releaseRepository())
	require.NoError(t, ordinary.validateReleaseCompatibility(nil))
}
func TestZCodeUpdaterDoesNotOfferIncompatibleReleaseOrRollback(t *testing.T) {
	client := &updateServiceGitHubClientStub{release: &GitHubRelease{TagName: "v0.2.99"}, recentReleases: []*GitHubRelease{
		{TagName: "v0.2.16"},
		{TagName: "v0.2.15", Assets: []GitHubAsset{{Name: ZCodeCompatibilityAsset}}},
	}}
	s := NewUpdateService(&updateServiceCacheStub{}, client, "0.2.17", ZCodeBuildType)
	info, err := s.CheckUpdate(context.Background(), true)
	require.NoError(t, err)
	require.False(t, info.HasUpdate)
	require.NotEmpty(t, info.Warning)
	candidates, err := s.fetchRollbackCandidates(context.Background())
	require.NoError(t, err)
	require.Len(t, candidates, 1)
	require.Equal(t, "v0.2.15", candidates[0].TagName)
	client.release.Assets = []GitHubAsset{{Name: ZCodeCompatibilityAsset}}
	info, err = s.CheckUpdate(context.Background(), true)
	require.NoError(t, err)
	require.True(t, info.HasUpdate)
}
func TestZCodeUpdaterIgnoresPreviouslyCachedOfficialRelease(t *testing.T) {
	cache := &updateServiceCacheStub{}
	plain := NewUpdateService(cache, nil, "0.2.17", "release")
	plain.saveToCache(context.Background(), &UpdateInfo{LatestVersion: "9.0.0", ReleaseInfo: &ReleaseInfo{Assets: []Asset{{Name: "sub2api_linux_arm64.tar.gz"}}}})
	s := NewUpdateService(cache, nil, "0.2.17", ZCodeBuildType)
	_, err := s.getFromCache(context.Background())
	require.Error(t, err)
}

func TestZCodeUpdateRevisionOrdering(t *testing.T) {
	s := NewUpdateService(nil, nil, "0.2.17-zcode.1", ZCodeBuildType)
	require.Less(t, s.compareReleaseVersions("0.2.17-zcode.1", "0.2.17-zcode.2"), 0)
	require.Less(t, s.compareReleaseVersions("0.2.17-zcode.99", "0.2.18-zcode.1"), 0)
	require.Greater(t, s.compareReleaseVersions("0.2.17-zcode.2", "0.2.17-zcode.1"), 0)
}
