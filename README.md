# dependency-gate

The deterministic dependency gate for the `factorydependencydefense` fleet.

Fleet repos call `.github/workflows/dependency-gate.yml` as a reusable workflow, pinned to a full
commit SHA, from a `pull_request_target` trigger. That trigger always runs the workflow from the
default branch, so a pull request cannot weaken the check that judges it (SPEC Decision 15).

The job reads the pull request's `package.json` and `package-lock.json` through the GitHub API as
data. It does not check out, install, build or execute anything from the pull request, and it holds
no secrets.

`gate.ts` is generated. Edit `tools/gate.ts` in the `droid-dependency-defense` kit and run
`npx tsx tools/publish-gate.ts <path-to-this-clone>`; the header records the source commit.

## Severities

- `block` fails the check: an install script that is not on the allowlist, a native build file, a
  resolved URL on an unexpected registry, a missing integrity hash, an integrity hash that changed
  without a version change, or an invalid registry signature.
- `review` does not fail the check: a new dependency, or a version published inside the recency
  window. A code owner decides. A security fix is often hours old, so blocking on recency would
  reject the remediation the policy asks for (SPEC Decision 12).
