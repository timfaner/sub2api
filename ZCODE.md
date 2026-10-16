# ZCode integration and upgrades

This fork adds Z.ai personal ZCode authorization to Zhipu accounts. Select
**Z.ai / ZCode** when creating an account and complete the official authorization
page once. An unfinished account is not scheduled. Existing API-key accounts keep
their existing behavior.

The gateway uses the international Anthropic endpoint with ZCode request signing.
Messages, Chat Completions and Responses share this path. Quota uses the CN-provider
quota endpoint. Generic Claude usage is not used. Zhipu group model lists are
read from the group's schedulable upstream accounts, including ZCode's verified
PAT-authenticated model endpoint. Account mappings and group allowlists apply;
empty catalogs stay empty and failures never fall back to Claude defaults.

## Credential lifetime

The server encrypts the retained authorization and derived business/project tokens
in the database, bound to the account ID and the deployment's stable JWT secret.
Back up the database **and the existing JWT secret**. Changing that secret requires
reauthorization. Do not copy account ciphertext between deployments or account IDs.
No upstream credentials should appear in API responses or browser storage.

Requests and a background maintenance loop renew project tokens before expiry.
Redis ownership leases and database compare-and-swap prevent concurrent renewal
from overwriting reauthorization. Transient upstream failures use persisted bounded
backoff. Revoked authorization needs human reauthorization; an expired/rejected
authorization is never replaced with an unsigned or ordinary API-key request.

The inspected client does not establish a root OAuth refresh endpoint. In the
2026-10-17 live test, the original OAuth token expired after approximately one
hour and could no longer exchange business credentials. Therefore the current
official OAuth login alone does **not** satisfy long-term unattended operation,
even while its derived business/project credentials remain valid. The account
editor exposes renewal failure and retry state.

A separate, explicitly authorized local experiment used the same user's native
Z.ai web session. Identity and personal project were checked before binding. Two
business exchanges, encrypted persistence/reload, and actual application restart
with automatic renewal succeeded; Chat Completions tool calls and Responses also
completed. The project token was still valid and retained its original expiry, so
this does not yet prove renewal beyond its natural expiration. No declared web
session expiry is not a lifetime guarantee. This experimental credential has not
been deployed to production and is not exposed as a supported login option.

## Release channel

Keep this integration on branch `zcode`. Merge upstream into that branch and resolve
conflicts there. Do not replace it by resetting to upstream or pulling the official
container image.

Build with `-X main.BuildType=zcode` and a version such as `0.2.17-zcode.1`.
The Dockerfile supports `--build-arg BUILD_TYPE=zcode` and `VERSION`.
ZCode builds check releases in `timfaner/sub2api`; ordinary builds retain the
upstream source. Updates and rollback require the `zcode-compatible-v1.txt` asset.
Old cached official releases are rejected. The numeric `-zcode.N` suffix allows
fixes against the same upstream version.

Every push to `zcode` runs the compatible build checks without publishing.
The **ZCode compatible release** workflow can be dispatched on `zcode` once its
definition exists on the default branch. Alternatively, push a `vX.Y.Z-zcode.N`
tag whose commit is on `zcode`; this runs verification and publishing directly.
ZCode tags are excluded from the ordinary release workflow.

1. Choose a new `X.Y.Z-zcode.N` version; leave `publish` disabled for a build check.
2. The workflow runs protocol, service, repository and UI regression checks, builds
   embedded Linux amd64/arm64 archives and creates checksums and a compatibility
   marker. The marker identifies a tested fork release, not an upstream entitlement.
3. With `publish` enabled it additionally publishes a versioned GHCR image and a
   GitHub release. Publishing to GHCR requires repository package permissions.
4. For Docker deployment, back up DB/config and change the Compose image to
   `ghcr.io/timfaner/sub2api:X.Y.Z-zcode.N`. Recreate only the `sub2api` service.
   Preserve data volumes and environment. Check health, login, quota and a controlled
   inference request. Keep the previous image and backup for rollback.

ZCode images set `SUB2API_UPDATE_CHANNEL=zcode`. The entrypoint seeds the tested
image binary into `/app/data/zcode-bin/sub2api` on first start and runs it there.
The existing web updater then replaces this persistent executable. Web updates
survive both restart and container recreation as long as `/app/data` is retained.
The web update source is this fork's compatible GitHub releases. Restart using
the existing web restart action after an update. The persisted binary takes
precedence over the image; changing the image alone does not downgrade it. To
reset deliberately, stop the service and move aside `data/zcode-bin`, then start
a compatible image. Preserve that directory in backups. Never use
`weishaw/sub2api:latest` for this deployment.

## Verification scope

A local real-account test on 2026-10-17 completed streaming Messages through the
full gateway. A controlled 21,461-input/20-output request consumed about five
integer weekly credits: consistent with the observed ZCode discount in addition
to off-peak pricing, rather than the roughly 7.43 off-peak-only estimate. This is
quota evidence, not a precise per-request bill or a promise of future pricing.

After restart, Chat Completions tool call/result and Responses completed without
interactive reauthorization. Earlier attempts timed out; no deterministic cause
was established, so those failures remain an operational caveat. Natural root
expiry and sustained unattended operation are separate acceptance checks; do not
infer them from a successful short request.

Release `v0.2.17-zcode.4` passed full CI and was installed on the existing
mac-server deployment through the web updater API. Its web restart action loaded
version `0.2.17-zcode.4`, and recreating only the application container retained
that version with healthy status. The update check then reported this fork release
as current with no warning. Both standard and Codex model catalogs returned the
same eleven upstream GLM models. No production account status, routing or group
membership was changed. This deployment still uses its original OAuth credential;
the experimental native web session remains local only.
