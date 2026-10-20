# Rust verification and pinned companion integration

`rust-verification.yml` runs the exact PR **head SHA**, without companion fixes,
on Linux, macOS and Windows. The repository's unchanged `cargo xtask ci` runs
strict workspace/all-target release Clippy with `-D warnings` exactly once,
alongside formatting, tests, policies and WASM. The complete gate log is retained
as an artifact, with pipeline failure preserved. The source/lockfile drift check
and subsequent locked desktop build enforce lockfile consistency.
No failed standalone gate is relabelled as passed because a combined run passed.

Both workflows pin Rust 1.99.1, install Clippy/rustfmt/WASM, cap Cargo at two
jobs, and allow 120 minutes per OS. Release tests stay optimized; LTO is disabled
and codegen units are 16, explicitly in the workflow. First-party MIT-licensed
`actions/cache` stores registry, git dependencies and build artifacts by OS,
architecture, toolchain, profile and lock/manifests. The save step also runs
after failures so a real lint failure does not force the next run to rebuild
all dependencies. Cargo's fingerprints still validate restored artifacts;
no test or lint result is cached as an approval.

Dedicated `sol-ci-candidate-*` fork branches trigger the exact-head gate, followed
by native smoke in each existing OS job, without requiring an upstream PR or a
default-branch change. Publish only the frozen candidate on that prefix. The job
reuses `target/standalone` and Cargo's compiled dependencies to build the actual
executable only when its fingerprints require it, then runs the playback owner's
`tools/native-smoke/smoke.py` on Windows, macOS and Linux (Xvfb). Its generated
project, source/binary identities, report and child logs are artifacts. Device
audio capture remains separate; this smoke also does not establish queued
export/cancel/overwrite acceptance. The candidate must include the harness.
`native-entry-smoke.yml` remains manual-only for targeted reruns.

The manual `companion-integration.yml` is supplementary. It assembles exactly
the eight heads in `integration-heads.json`, refuses live PR-head changes,
records intermediate and final Git tree IDs, then runs the same repository gate
with one strict Clippy invocation. It uploads the manifest, receipt and gate log. It never claims that
an individual source head passed. Its standalone counterpart requires no
manifest or companion PRs.

Its `manifest_path` dispatch input selects an explicitly packaged worker-patch
manifest when testing newer frozen work; the default eight-head manifest is
the reviewed historical baseline, not a proxy for subsequent worker changes.
Prefreeze snapshots are preparation evidence only. Do not spend a broad gate
on a candidate already known to fail required ordinary-overwrite tests, and
never skip those tests to create a green integration badge.

## Local assembly (no commits)

Requires Python 3.11+ and Git 2.40+. Run from the checkout containing this tooling:

```sh
python -m unittest discover -s ci -p 'test_*.py' -v
python ci/assemble_integration.py --manifest ci/integration-heads.json \
  --destination ../effectcraft-combined-unique --receipt ../combined-source-unique.json
# Add --fetch --check-live to fetch the immutable objects and refuse moved PRs.
# Omit --destination for tree/provenance verification without a checkout.
```

The destination and receipt must not exist. No existing checkout or index is
modified. Git objects are added to the source object store, and a new detached
worktree is created only after all merges and hashes validate. It has the common
base as HEAD and the combined tree staged in its private index. **The receipt's
tree, rather than HEAD, identifies the assembled sources.** No assembly commit,
branch update, generated lockfile or unpublished source overlay is required.

For work awaiting its required pre-commit gate, a manifest may declare an
ordered `patches` list: each entry has a `path` relative to the manifest directory
and a `sha256` of its exact bytes. Those patches apply to temporary Git indexes
after the pinned heads, without modifying an existing checkout or making a
commit. The final `expected_tree` must include them; the receipt records each
patch digest and intermediate tree. Changed bytes, failed hunks or paths outside
the manifest directory are refused. The supplied eight-head manifest has no
patches. New worker changes need an explicit updated manifest, never an
unrecorded overlay added after assembly.

Set `CARGO_TARGET_DIR` to a directory owned by the verifier, and
`CARGO_BUILD_JOBS=2`, before testing. For the complete gate run `cargo xtask ci`
inside that new directory. Afterwards verify the tested files and index:

```sh
python ci/verify_integration.py --receipt ../combined-source-unique.json
```

Tracked-source or index drift fails verification. The existing export filesystem
workflow remains responsible for the Windows privileged audit tests and separate
unprivileged process; a full workspace test run alone does not exercise those
ignored privileged cases.

## Dependencies and merge decisions at the pinned heads

Every PR has common base `ef74d82902ba486891b02afa87e42963cc9b84cc`.
Each manifest entry contains its full reviewed head. These are parallel PRs,
not an ancestry stack; no companion head is silently substituted for another.

| PRs | Actual overlap / dependency |
| --- | --- |
| #1889 | Gates the Unix-only `Stills` test importer. Required to clear strict Windows engine-test Clippy on the other unchanged heads. This is a verification prerequisite, not a runtime dependency. |
| #1890 / #1907 | Both change `crates/text/src/fonts.rs`, in disjoint resolution and CJK-fallback sections. Git merges them without a conflict; no required source merge order. |
| #1891 / #1922 | Both extend `Cargo.lock`, for different packages/dependency lists. Git combines them without regeneration or conflict. |
| #1827 / #1922 | Both change `crates/export/src/lib.rs` and `crates/export/tests/render_settings.rs`. Runtime `lib.rs` hunks merge cleanly. Both append independent test groups at EOF, causing one content conflict. |
| #1915 / #1916 | Separate render Auto-backend and Windows viewer-test files; no source overlap with the other seven PRs. They are reliability fixes for their respective tests, not runtime prerequisites of export/audio. |

The only conflict resolution preserves the complete audio-side file, including
its added comments and tests, then concatenates the exact export-side EOF
append. The resolver verifies that the entire base file is an unchanged prefix
of that export-side file. The manifest pins the base/ours/theirs blob IDs and
the resolved blob `2cd474a2610a7ca0dc2ecdf38b03e1af3d48043b`. An initial
automatic union was rejected: it aligned similar closing braces and failed
Rust parsing. No automatic union or runtime-file resolution is used. Any
unexpected conflict or changed input/output blob stops assembly. The final
expected source tree is `5baca7023f17469b437e87135d4ae47f5fc29808`.

When a head moves or a base is updated, review the new diffs and conflict
resolution before updating the manifest and final tree. A checksum failure is
not permission to regenerate and accept a new hash automatically.

## CodeRabbit Clippy timeout

On 20 October 2026 the eight current PR summaries each retained an embedded
`Clippy (1.98.1): Clippy execution timed out` warning despite successful
CodeRabbit statuses and latest-head review coverage. A review's success status
therefore does not establish completion of its Clippy tool.

The [current configuration reference](https://docs.coderabbit.ai/reference/configuration)
and [published schema](https://coderabbit.ai/integrations/schema.v2.json)
expose only `enabled` for `reviews.tools.clippy`; no Clippy execution-timeout
control is published. `clippy.toml` configures lints, not the service sandbox.
The current `github-checks` object also only publishes `enabled`; do not copy
an unsupported `timeout_ms` setting from older examples. No CodeRabbit settings
are changed by this tooling, and Clippy remains enabled.

The repository-side alternative is strict Clippy inside the required gate above.
GitHub retains the failure logs, which CodeRabbit can consume through its
[CI/CD pipeline analysis](https://docs.coderabbit.ai/pr-reviews/cicd-pipeline-analysis).
After publishing, require the standalone OS checks in the GitHub branch ruleset;
the supplementary combined check cannot satisfy a failed standalone check.
Introducing a workflow does not itself change branch protection.

To remedy the provider execution failure itself, the repository/CodeRabbit
administrator should open **CodeRabbit app → profile picture (bottom left) →
Contact Support**, as described in [Get support](https://docs.coderabbit.ai/support).
Supply the PR URLs, exact heads, review run IDs, embedded error and local/CI
command results; request the actual sandbox command, timeout budget, cache
diagnostics, and a supported budget/cache remedy. Do not assert a specific
timeout value from an error that reports none. The provider issue remains open
until a run shows tool completion; the independent CI gate supplies additional
verification without concealing that failure.
