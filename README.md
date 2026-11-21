# V-Patch

Scan the packages installed in a Node.js project for known vulnerabilities, show the **smallest safe fix** for each one, let a human (or your policy) choose which to apply, and **prove the application still works** before keeping any change. Anything that fails verification is rolled back automatically.

```
scan ──► plan ──► select ──► [ snapshot → apply → verify ] ──► keep │ roll back ──► report
 (npm audit / OSV)  (registry)  (interactive / --all-safe)        per fix, in isolation
```

## Quick start

```bash
npm i -D v-patch
npx vpatch init                 # writes vpatch.config.json
npx vpatch scan                 # list vulnerabilities (exit 1 if >= failOn)
npx vpatch plan                 # show the fix for each one, change nothing
npx vpatch fix                  # interactive: pick fixes with the keyboard
npx vpatch fix --all-safe       # CI: apply everything policy marks safe
npx vpatch fix --select lodash@4.18.0,minimist
npx vpatch rollback             # restore the last snapshot
```

Requires Node >= 18.17, npm >= 7 and a `package-lock.json`.

## How it avoids breaking your application

| Layer | What it does |
|---|---|
| **Minimal change** | Picks the *lowest* published version outside every advisory's vulnerable range (or newest-in-major with `versionStrategy`). Versions come from the registry, never guessed. |
| **Risk classification** | patch = low, minor = medium, major = high. Transitive fixes outside a dependent's declared range are escalated one level. Major bumps are never auto-applied. |
| **Baseline gate** | Your build/tests must pass *before* patching, otherwise V-Patch refuses to run: it could not attribute a failure to a fix. |
| **Isolated transactions** | Default mode applies one fix, verifies, then keeps or rolls back *that fix only*. One bad upgrade never blocks the other nine. (`--mode batch` = apply all, verify once.) |
| **Verification pipeline** | Fail-fast, cheapest first: blast-radius (lockfile entries changed, unplanned major bumps) → dependency-tree health (only *new* problems vs. baseline) → security re-scan (advisory actually gone, nothing new introduced) → `build` → `test` → your custom smoke/contract commands. |
| **Reversible** | `package.json` + lockfile are snapshotted to `.vpatch/snapshots/<id>` before anything changes; rollback restores them and rebuilds `node_modules` with `npm ci`. |
| **Supply-chain guard** | `minReleaseAgeDays` refuses brand-new releases; advisory data is never passed to a shell (strict name/version validation, no shell for npm calls on POSIX). |

Verification is only as strong as your tests. Put contract / smoke tests that exercise your critical paths into `verify.commands`.

## CI/CD

* Exit codes: `0` ok, `1` vulnerabilities at/above `--fail-on`, `2` error, `3` some fixes were rolled back.
* Formats: `-f table|json|markdown|sarif`, `-o file`. Logs go to stderr, so stdout is always parseable.
* `.github/workflows/vpatch.yml` gives you (1) a PR gate that uploads SARIF to GitHub code scanning and (2) a weekly job that applies safe fixes and opens a PR with the Markdown report as its body.
* GitLab / Jenkins / Azure: just call the CLI, e.g. GitLab: `script: [npm ci, npx vpatch -f json -o vpatch.json scan --fail-on high]`.

## Configuration (`vpatch.config.json`)

See [`vpatch.config.example.json`](./vpatch.config.example.json). Notable keys:

* `failOn` – CI gate severity. `severityThreshold` – ignore anything below.
* `policy.autoApplyMaxBump` – largest bump `--all-safe` may apply (`patch|minor|major`; high-risk is always manual).
* `policy.maxChangedPackages` – blast-radius limit per run.
* `ignore[]` – waivers require a `reason` and may carry an `expires` date; expired waivers stop applying.
* `verify.commands` – extra shell commands that must exit 0.
* `apply.ignoreScripts` – pass `--ignore-scripts` to installs (recommended for hardened pipelines; may break native modules).

## Library usage

```ts
import { VPatch, gate } from 'v-patch';

const vp = await VPatch.create({ projectDir: process.cwd(), config: { verify: { commands: ['npm run smoke'] } } });
const scan = await vp.scan();
if (gate(scan, 'high').length) {
  const plan = await vp.plan(scan);
  const result = await vp.apply(vp.select(plan, { allSafe: true }), scan);
  console.log(result.outcomes.map((o) => `${o.candidate.id}: ${o.status}`));
}
```

## Extending

| To add | Implement | Where |
|---|---|---|
| A vulnerability source (Snyk, Artifactory Xray, internal feed) | `AuditProvider` | `src/scanner/` |
| pnpm / yarn | `PackageManager` | `src/pm/` |
| Another report format | add a case to `render()` | `src/reporters/` |
| A custom verification step | wrap `VerificationRunner` | `src/patcher/verifier.ts` |

```
src/
  vpatch.ts            orchestrator / public API
  scanner/             npm-audit + OSV providers, policy (thresholds, waivers)
  planner/             vulnerability → minimal fix candidate
  patcher/             snapshot store, verifier, transactional applier
  pm/                  package-manager adapter (npm)
  reporters/           table, JSON, Markdown, SARIF
  cli/                 commander CLI + interactive selector
```

## Known limitations

* **npm only** (lockfile v2/v3). pnpm/yarn are detected and rejected with a clear message.
* **Transitive fixes use npm `overrides`**, which pin a version for the whole tree. When several major lines of one package are vulnerable, V-Patch writes version-qualified override keys; the verification gate is the safety net if npm resolves them differently than expected.
* The **OSV provider** (`--provider osv`) is covered by unit tests for range conversion but was not exercised against the live OSV API during development.
* Not yet tested on Windows.
* Reachability analysis (is the vulnerable function actually called?) is out of scope; use `ignore[]` waivers for accepted risk.
