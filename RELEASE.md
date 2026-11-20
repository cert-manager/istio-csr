# Releases

## Schedule

The release schedule for this project is ad-hoc. Given the pre-1.0 status of the project we do not have a fixed release cadence. However if a vulnerability is discovered we will respond in accordance with our [security policy](https://github.com/cert-manager/community/blob/main/SECURITY.md) and this response may include a release.

## Process

There is a semi-automated release process for this project. When you create a Git tag with a tagname that has a `v` prefix and push it to GitHub it will trigger the [release workflow].

### Narrate the release in `#cert-manager-dev`

Releases are narrated as a single thread in [`#cert-manager-dev`](https://kubernetes.slack.com/archives/CDEQJ0Q8M) on the Kubernetes Slack. Open the thread before you start the pre-release checks, so each step that follows can be posted as a reply.

Start with a top-level message such as:

```
:thread: Releasing istio-csr v0.17.0 ...
```

As the release progresses, reply in the thread with:

- the pre-release check summary (see below);
- the tag URL after pushing;
- the release-workflow run URL once it starts building;
- the published release URL with `:tada:` once it is live.

This gives the whole team a single, scannable record of what was done, by whom, and when, and lets non-PANW maintainers see what is happening with the steps they cannot perform themselves (see "Post-release: Verify the Helm Chart Reaches ArtifactHub" below).

### Pre-release Checks

1. **Check open issues and PRs for release blockers.** Scan anything opened
   since the last release — a regression report against the current release, or
   a nearly-ready fix that should be included, may change what you tag:
    ```sh
    # Date of the last release:
    LAST=$(gh release view --repo cert-manager/istio-csr --json publishedAt -q .publishedAt | cut -dT -f1)
    gh issue list --repo cert-manager/istio-csr --search "created:>=${LAST}" --limit 100
    gh pr list --repo cert-manager/istio-csr --search "created:>=${LAST}" --limit 100
    ```
    This is a judgement call, not a gate: most open items are feature requests
    or in-review work that can wait for the next release. Mention anything
    borderline in the pre-release Slack summary so others can veto.

2. **Check for known vulnerabilities** using `govulncheck` and `trivy`:
    ```sh
    # Check the nightly security-scan GitHub workflow is green on main:
    # https://github.com/cert-manager/istio-csr/actions/workflows/govulncheck.yaml
    # (The workflow file keeps its historic govulncheck name; it runs both
    # govulncheck and the trivy image scan. You can also trigger it on demand:)
    gh workflow run govulncheck.yaml --repo cert-manager/istio-csr

    # Or run the scans locally. oci-security-scan builds the manager image and
    # scans it with trivy, reporting fixable vulnerabilities of severity
    # MEDIUM, HIGH and CRITICAL. This matches what ArtifactHub scans (the
    # published image); only fixable vulnerabilities can be addressed by
    # bumping dependencies. vendor-go ensures the image is built with the same
    # pinned Go version as the release workflow, so Go stdlib vulnerabilities
    # already fixed by a toolchain bump are not falsely reported by an older
    # host Go:
    make vendor-go verify-govulncheck oci-security-scan
    ```
    If trivy reports vulnerabilities, bump the affected dependencies before tagging,
    even if they are indirect. ArtifactHub displays trivy results on the
    [security report page](https://artifacthub.io/packages/helm/cert-manager/cert-manager-istio-csr?modal=security-report),
    and users rely on a clean report.

    **If govulncheck reports Go standard library vulnerabilities**, the fix is
    a new Go patch release, and it must propagate to this repo before you tag:

    1. Renovate bumps `VENDORED_GO_VERSION` in
       [makefile-modules](https://github.com/cert-manager/makefile-modules)
       (`modules/tools/00_mod.mk`). Go upgrades are exempt from the 3-day
       `minimumReleaseAge` hold in the shared
       [renovate-config](https://github.com/cert-manager/renovate-config)
       preset (since
       [renovate-config#62](https://github.com/cert-manager/renovate-config/pull/62)),
       so the PR opens on the next Renovate run — see
       [makefile-modules#697](https://github.com/cert-manager/makefile-modules/pull/697)
       (Go 1.26.6) for an example. The PR is deliberately **not** auto-merged:
       same-day Go patch releases have shipped regressions before (see the
       evidence on renovate-config#62), so verify the updated `SHA256SUM`
       values against the checksums published at https://go.dev/dl/, then get
       it reviewed and merged. Other dependencies still wait 3 days; those can
       be forced by ticking their checkbox in the "Pending" section of the
       [makefile-modules dependency dashboard](https://github.com/cert-manager/makefile-modules/issues/487).
    2. Renovate then opens a `chore(deps): update makefile modules` PR in this
       repo, updating `klone.yaml` (and with it the pinned Go version) to the
       new makefile-modules commit — see
       [#888](https://github.com/cert-manager/istio-csr/pull/888) for an
       example. Force an immediate Renovate run from the
       [dependency dashboard](https://github.com/cert-manager/istio-csr/issues/687)
       if you do not want to wait for the next scheduled run. If the PR sits
       unmerged with a required prow job stuck "pending" and no details link,
       the job never started (this can happen after a Renovate rebase) —
       retrigger it by commenting `/test <job-name>` on the PR, as happened on
       [#883](https://github.com/cert-manager/istio-csr/pull/883).
    3. Re-run the security-scan workflow on main and check that it is green
       before tagging. The matrix leg for the previous release tag will stay
       red until this release is published — that is the early-warning signal
       telling users of the released version to upgrade, not a reason to hold
       this release.

3. **Verify signed-tag config** so the release tag is shown as Verified on GitHub:
    ```sh
    git config --get tag.gpgsign     # must print: true
    git config --get gpg.format      # ssh (or openpgp), matching your signing setup
    git config --get user.signingkey # path to a key that is also registered with GitHub
    ```
    If `tag.gpgsign` is unset, `git tag --annotate` produces an unsigned tag and the
    GitHub release page will display **Unverified** next to the tag. Set it globally
    once with `git config --global tag.gpgsign true` so every future annotated tag
    is signed automatically. (csi-driver-spiffe v0.14.0 was tagged unsigned for this
    exact reason.)

4. **Post a pre-release check summary to the Slack thread** so the team can see the
   state of the world before you tag. Cover: govulncheck/trivy results, any
   outstanding CVEs and how they have been addressed, sidecar image status (none
   for istio-csr), notable community PRs included, dependency updates, and
   anything else relevant to this release.

### Doing a Release

The release process for this repo is documented below:

1. Create a tag for the new release:
    ```sh
    export VERSION=v0.17.0
    git tag --annotate --message="Release ${VERSION}" "${VERSION}"
    git push origin "${VERSION}"
    ```
   Post the tag URL to the Slack thread.

2. A GitHub action will see the new tag and do the following:
    - Build and publish the container images
    - Build and publish the OCI Helm chart
    - Create a draft GitHub release

   Post the workflow-run URL to the Slack thread so others can follow along.

3. Visit the [releases page], edit the draft release, click "Generate release notes", then curate the notes (see [v0.17.0](https://github.com/cert-manager/istio-csr/releases/tag/v0.17.0) for an example):
    - Add the following intro line at the top:
      ```
      istio-csr integrates cert-manager into Istio, allowing you to issue workload certificates using the power of cert-manager.
      ```
    - Add a **Security** section listing the vulnerabilities fixed in this
      release (Go vulnerability IDs and the dependency bumps that fixed them).
    - Add a **Highlights** section summarizing notable changes, crediting the
      community PRs and their authors.
    - Keep the generated changelog (including "New Contributors") and the
      Artifacts section from the draft body (image and chart coordinates with
      digests).

    It is easier to draft the notes in a local file and apply them with:
    ```sh
    gh release edit "${VERSION}" --repo cert-manager/istio-csr --notes-file notes.md
    ```
4. Publish the release, marking it as latest:
    ```sh
    gh release edit "${VERSION}" --repo cert-manager/istio-csr --draft=false --latest
    ```
   Post the release URL to the Slack thread, prefixed with `:tada:`.

### Post-release: Verify the Helm Chart Reaches ArtifactHub

> [!IMPORTANT]
> The steps in this section can **only be performed by Palo Alto Networks
> employees**. The [jetstack/jetstack-charts](https://github.com/jetstack/jetstack-charts)
> repository is private and pre-dates the cert-manager project moving to a
> community governance model — it remains the path through which OCI charts on
> `quay.io/jetstack` are syndicated to `charts.jetstack.io` and ArtifactHub.
>
> If you are a release manager outside Palo Alto Networks, **do not skip this
> section**. Post in the release Slack thread asking a PANW cert-manager
> maintainer to run these steps, and link them this section as a reference.

The release workflow pushes the Helm chart to `quay.io/jetstack/charts`, and an
`oci-sync` workflow in `jetstack/jetstack-charts` opens a PR to sync it to
`charts.jetstack.io`. That PR requires a maintainer approval before it is merged.
Until it is merged, ArtifactHub will continue to show the previous version.

`oci-sync` runs hourly on cron. If you do not want to wait for the next scheduled
run, trigger it on demand:

```sh
gh workflow run oci-sync.yaml --repo jetstack/jetstack-charts
gh pr list --repo jetstack/jetstack-charts --search "oci-sync" --state open
```

**Before merging the sync PR**, verify that the chart published to the preview
repo matches expectations. The Cloudflare Pages check on the sync PR posts a
deployment preview URL — render the chart for both the new and previous releases
from that preview, and diff them with version-label noise filtered out:

```sh
# PREVIEW is the per-deployment URL from the PR's Cloudflare Pages comment, e.g.
# https://8cebb8e5.jetstack-charts.pages.dev
export PREVIEW=https://DEPLOYMENT-ID.jetstack-charts.pages.dev
export NEW=v0.17.0
export OLD=v0.16.0     # the previous release

helm template istio-csr cert-manager-istio-csr --repo "$PREVIEW" --version "$NEW" > /tmp/istio-csr-new.yaml
helm template istio-csr cert-manager-istio-csr --repo "$PREVIEW" --version "$OLD" > /tmp/istio-csr-old.yaml

diff -u /tmp/istio-csr-old.yaml /tmp/istio-csr-new.yaml \
  | grep -v -E "^[-+][[:space:]]*(helm\.sh/chart:|app\.kubernetes\.io/version:|image:).*(${OLD}|${NEW})"
```

The only remaining diff should correspond to actual behavioural changes shipped
in this release.

> [!NOTE]
> A `make helm-diff` target which automates this comparison (local chart vs a
> released OCI chart version, with version-label noise filtered) is proposed in
> [makefile-modules#470](https://github.com/cert-manager/makefile-modules/pull/470)
> and adopted here by [#889](https://github.com/cert-manager/istio-csr/pull/889).
> Once merged, it can also be run before tagging to preview the chart changes:
> `make helm-diff helm_chart_old_version=v0.16.0`. Then confirm the referenced container image is published with
the expected platforms:

```sh
make _bin/tools/crane
_bin/tools/crane manifest "quay.io/jetstack/cert-manager-istio-csr:${NEW}"
```

Record the commands you ran (and any non-trivial filtered diff) as a comment on
the sync PR before approving and merging — this leaves an audit trail for the
next maintainer. Then approve and merge the sync PR.

After merge, confirm the new version appears on ArtifactHub:
https://artifacthub.io/packages/helm/cert-manager/cert-manager-istio-csr

### Post-release: Check the ArtifactHub Security Report

Once the new version appears on ArtifactHub, check its security report for
vulnerabilities. istio-csr ships only the manager image — there are no
sidecar images — so any finding here is in code or dependencies we control and
should be addressed in a follow-up patch release.

The security report is visible in the web UI at:

https://artifacthub.io/packages/helm/cert-manager/cert-manager-istio-csr/VERSION?modal=security-report

It can also be fetched programmatically using the [ArtifactHub API]. The package
ID for istio-csr is `5790e939-c4f4-4c00-9f9e-e2914dee58af`. Note that
ArtifactHub identifies chart versions without the `v` prefix — even though our
release tags and the `version`/`appVersion` fields in `Chart.yaml` carry one —
so the API path uses the bare semver (e.g. `0.17.0`, not `v0.17.0`, which 404s):

```sh
export VERSION=0.17.0
make _bin/tools/yq
curl -sL "https://artifacthub.io/api/v1/packages/5790e939-c4f4-4c00-9f9e-e2914dee58af/${VERSION}/security-report" \
  | _bin/tools/yq -p json -o tsv '
    ["IMAGE", "SEVERITY", "CVE", "PACKAGE", "INSTALLED", "FIXED"],
    (
      to_entries[] |
      .key as $image |
      .value.Results[]? |
      .Vulnerabilities[]? |
      [$image, .Severity, .VulnerabilityID, .PkgName, .InstalledVersion, .FixedVersion // "n/a"]
    ) | @tsv
  ' | column -t -s$'\t'
```

### Post-release: Notify Community Contributors

For every non-bot, non-maintainer PR included in the release, comment thanking
the author, linking the release, and asking them to install and verify the
change in their own environment. For every public issue closed by those PRs,
comment on the issue too — invite the original reporter (and any other
commenters) to confirm the fix.

Use this template on the PR:

```
@<author> This change has been included in [vX.Y.Z](https://github.com/cert-manager/istio-csr/releases/tag/vX.Y.Z), which is now published.

Installation instructions are at https://cert-manager.io/docs/usage/istio-csr/installation/

If you are able to install the new release and verify the fix in your environment, that would be much appreciated. Thank you for the contribution.
```

When commenting on a closed issue, tailor the second sentence to the specific
failure the reporter described, rather than the generic "verify the fix"
wording.

## Artifacts

This repo will produce the following artifacts each release. For documentation on how those artifacts are produced see the "Process" section.

- *Container Images* - Container images for istio-csr are published to `quay.io/jetstack/cert-manager-istio-csr`
- *Helm chart* - An official Helm chart is maintained within this repo and published as an OCI chart to `quay.io/jetstack/charts/cert-manager-istio-csr` on each release.
  *  The chart is also published to the legacy HTTP Helm repository at `https://charts.jetstack.io` (maintained by Venafi).
     Publishing to the legacy repo depends on a PR to be merged in a closed Venafi repo, and might be delayed.

[ArtifactHub API]: https://artifacthub.io/docs/api/
[release workflow]: https://github.com/cert-manager/istio-csr/actions/workflows/release.yaml
[releases page]: https://github.com/cert-manager/istio-csr/releases
