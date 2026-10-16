# ZCode integration and upgrades

This fork adds Z.ai personal ZCode authorization to Zhipu accounts. Select
**Z.ai / ZCode** when creating an account and complete the official authorization
page once. An unfinished account is not scheduled. Existing API-key accounts keep
their existing behavior.

The gateway uses the international Anthropic endpoint with ZCode request signing.
Messages, Chat Completions and Responses share this path. Quota uses the CN-provider
quota endpoint. Generic Claude usage and unverified model discovery are not used.

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

The inspected client does not establish a root OAuth refresh endpoint. Derived
token renewal alone does not prove indefinitely unattended operation. Natural root
expiry and subsequent exchange must be verified separately before claiming that
guarantee. The account editor exposes renewal failure and retry state.

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

The built-in updater can replace a running binary, but a later Docker recreation
restores the image's binary. Use a versioned compatible **container image** for
durable Docker upgrades. Never use `weishaw/sub2api:latest` for this deployment.

## Verification scope

A local real-account test on 2026-10-17 completed streaming Messages through the
full gateway. A controlled 21,461-input/20-output request consumed about five
integer weekly credits: consistent with the observed ZCode discount in addition
to off-peak pricing, rather than the roughly 7.43 off-peak-only estimate. This is
quota evidence, not a precise per-request bill or a promise of future pricing.

After restart, Chat Completions tool call/result and Responses completed without
interactive reauthorization. Earlier attempts timed out; no deterministic cause
was established, so those failures remain an operational caveat. Natural root
expiry, sustained unattended operation and production deployment are separate
acceptance checks; do not infer them from a successful short request.
