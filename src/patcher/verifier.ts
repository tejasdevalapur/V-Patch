import type { VPatchConfig } from '../config.js';
import type { Executor } from '../exec.js';
import { tail } from '../exec.js';
import type { Logger } from '../logger.js';
import { diffLockfiles, readLockfile, type Lock } from '../lockfile.js';
import type { PackageManager } from '../pm/adapter.js';
import { hasRealScript, readManifest } from '../project.js';
import type { ExecResult } from '../exec.js';
import type { FixCandidate, VerificationReport, VerificationStep, Vulnerability } from '../types.js';

/** First line is a one-line reason (shown in reports); the rest is the output tail for debugging. */
const summarize = (r: ExecResult): string => {
  const out = (r.stderr.trim() || r.stdout.trim());
  const last = out.split('\n').filter(Boolean).at(-1) ?? '';
  return `exit ${r.exitCode}${r.timedOut ? ' (timed out)' : ''}${last ? ` – ${last.slice(0, 160)}` : ''}\n${tail(out)}`;
};

export const vulnKey = (v: Pick<Vulnerability, 'id' | 'packageName'>) => `${v.id}|${v.packageName}`;

export interface VerifyInput {
  /** Every candidate in this run (used to tell intended major bumps from collateral ones). */
  approved: FixCandidate[];
  /** The candidate(s) just applied, whose advisories must now be gone. */
  applied: FixCandidate[];
  initialLock: Lock;
  initialVulnKeys: Set<string>;
}

export interface VerificationRunner {
  captureBaseline(): Promise<VerificationReport>;
  verify(input: VerifyInput): Promise<VerificationReport>;
}

export interface VerifierDeps {
  projectDir: string;
  pm: PackageManager;
  exec: Executor;
  config: VPatchConfig;
  logger: Logger;
  /** Policy-filtered scan of the current tree. */
  scan: () => Promise<Vulnerability[]>;
}

/**
 * The "do not break the application" gate. Cheap, high-signal checks run first so a
 * bad fix is rejected quickly; project build/tests/smoke commands run last.
 */
export class ProjectVerifier implements VerificationRunner {
  private baselineProblems: string[] = [];
  constructor(private d: VerifierDeps) {}

  private async step(name: string, fn: () => Promise<string | undefined>): Promise<VerificationStep> {
    const t = Date.now();
    try {
      const failure = await fn();
      return { name, status: failure ? 'failed' : 'passed', durationMs: Date.now() - t, detail: failure };
    } catch (err: any) {
      return { name, status: 'failed', durationMs: Date.now() - t, detail: err.message };
    }
  }

  private skipped = (name: string, why: string): VerificationStep => ({ name, status: 'skipped', durationMs: 0, detail: why });

  /** Project-level checks (build, tests, custom commands). */
  private async projectSteps(): Promise<VerificationStep[]> {
    const { config, pm, exec, projectDir } = this.d;
    const manifest = await readManifest(projectDir);
    const timeoutMs = config.verify.timeoutSeconds * 1000;
    const steps: VerificationStep[] = [];

    const script = async (name: 'build' | 'test', enabled: boolean) => {
      if (!enabled) return steps.push(this.skipped(name, 'disabled in config'));
      if (!hasRealScript(manifest, name)) return steps.push(this.skipped(name, `no "${name}" script in package.json`));
      const s = await this.step(name, async () => {
        const r = await pm.runScript(name);
        return r.exitCode === 0 ? undefined : summarize(r);
      });
      steps.push(s);
    };

    await script('build', config.verify.runBuild);
    if (steps.at(-1)?.status !== 'failed') await script('test', config.verify.runTests);

    for (const cmd of config.verify.commands) {
      if (steps.some((s) => s.status === 'failed')) break;
      steps.push(
        await this.step(`command: ${cmd}`, async () => {
          const r = await exec.runShell(cmd, { cwd: projectDir, timeoutMs });
          return r.exitCode === 0 ? undefined : summarize(r);
        }),
      );
    }
    return steps;
  }

  async captureBaseline(): Promise<VerificationReport> {
    this.baselineProblems = await this.d.pm.listProblems();
    const steps = await this.projectSteps();
    return { passed: steps.every((s) => s.status !== 'failed'), steps };
  }

  async verify(input: VerifyInput): Promise<VerificationReport> {
    const { config, pm, projectDir } = this.d;
    const steps: VerificationStep[] = [];
    const run = async (s: Promise<VerificationStep>) => {
      if (steps.some((x) => x.status === 'failed')) return;
      steps.push(await s);
    };

    await run(
      this.step('blast-radius', async () => {
        const changes = diffLockfiles(input.initialLock, await readLockfile(projectDir));
        const max = config.policy.maxChangedPackages;
        if (changes.length > max) return `${changes.length} lockfile entries changed (limit ${max}).`;
        const allowed = new Set(input.approved.map((c) => c.packageName));
        const collateral = changes.filter((c) => c.bump === 'major' && !allowed.has(c.name));
        if (collateral.length) {
          return `Unplanned major upgrade(s): ${collateral.map((c) => `${c.name} ${c.from} → ${c.to}`).join(', ')}`;
        }
        return undefined;
      }),
    );

    await run(
      this.step('dependency-tree', async () => {
        const base = new Set(this.baselineProblems);
        const fresh = (await pm.listProblems()).filter((p) => !base.has(p));
        return fresh.length ? `New dependency-tree problems:\n${fresh.slice(0, 5).join('\n')}` : undefined;
      }),
    );

    if (config.verify.rescan) {
      await run(
        this.step('security-rescan', async () => {
          const now = await this.d.scan();
          const nowKeys = new Set(now.map(vulnKey));
          const still = input.applied.flatMap((c) => c.resolves.filter((id) => nowKeys.has(`${id}|${c.packageName}`)).map((id) => `${id} (${c.packageName})`));
          if (still.length) return `Fix ineffective, still vulnerable: ${still.join(', ')}`;
          const introduced = now.filter((v) => !input.initialVulnKeys.has(vulnKey(v)));
          if (introduced.length) return `Introduces new vulnerabilities: ${introduced.map((v) => `${v.id} (${v.packageName})`).join(', ')}`;
          return undefined;
        }),
      );
    } else {
      steps.push(this.skipped('security-rescan', 'disabled in config'));
    }

    if (!steps.some((s) => s.status === 'failed')) steps.push(...(await this.projectSteps()));
    return { passed: steps.every((s) => s.status !== 'failed'), steps };
  }
}
