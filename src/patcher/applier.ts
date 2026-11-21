import type { VPatchConfig } from '../config.js';
import { VPatchError } from '../errors.js';
import type { Logger } from '../logger.js';
import { diffLockfiles, parseLockfile, readLockfile } from '../lockfile.js';
import type { PackageManager } from '../pm/adapter.js';
import { savePrefixOf, writeOverride } from '../project.js';
import { stamp } from '../util.js';
import type { ApplyResult, FixCandidate, FixOutcome, VerificationReport, Vulnerability } from '../types.js';
import type { Checkpoint, SnapshotStore } from './snapshot.js';
import { vulnKey, type VerificationRunner } from './verifier.js';

export interface ApplierDeps {
  projectDir: string;
  pm: PackageManager;
  verifier: VerificationRunner;
  snapshots: SnapshotStore;
  config: VPatchConfig;
  logger: Logger;
  /** Policy-filtered scan of the current tree. */
  scan: () => Promise<Vulnerability[]>;
}

export interface ApplyOptions {
  dryRun?: boolean;
  skipBaseline?: boolean;
  mode?: 'isolated' | 'batch';
}

const firstFailure = (r?: VerificationReport): string =>
  r?.steps.find((s) => s.status === 'failed')?.detail?.split('\n')[0] ?? 'verification failed';
const failedStepName = (r?: VerificationReport): string => r?.steps.find((s) => s.status === 'failed')?.name ?? 'apply';

/**
 * Applies fixes as a transaction: snapshot → change → verify → keep or roll back.
 * The working tree is never left in a state that has not passed verification.
 */
export class PatchApplier {
  constructor(private d: ApplierDeps) {}

  async apply(candidates: FixCandidate[], before: Vulnerability[], opts: ApplyOptions = {}): Promise<ApplyResult> {
    const { logger, config } = this.d;
    const mode = opts.mode ?? config.apply.mode;
    const snapshotId = stamp();

    if (opts.dryRun) {
      return {
        snapshotId: '(dry-run)',
        mode,
        outcomes: candidates.map((candidate) => ({ candidate, status: 'dry-run', durationMs: 0 })),
        changes: [],
        remaining: before,
      };
    }
    if (candidates.length === 0) return { snapshotId: '(none)', mode, outcomes: [], changes: [], remaining: before };

    let baseline: VerificationReport | undefined;
    if (config.verify.baseline && !opts.skipBaseline) {
      logger.info('Verifying the project passes BEFORE patching (baseline)…');
      baseline = await this.d.verifier.captureBaseline();
      if (!baseline.passed) {
        const bad = baseline.steps.find((s) => s.status === 'failed');
        throw new VPatchError(
          'BASELINE_FAILED',
          `Baseline "${bad?.name}" already fails, so V-Patch cannot tell whether a fix breaks anything. Fix it first or pass --skip-baseline.\n${bad?.detail ?? ''}`,
        );
      }
    }

    const initial = await this.d.snapshots.read();
    await this.d.snapshots.persist(initial, snapshotId);
    const ctx = { initial, initialLock: parseLockfile(initial.lockfile), initialVulnKeys: new Set(before.map(vulnKey)), approved: candidates };

    const outcomes = mode === 'batch' ? await this.runBatch(candidates, ctx) : await this.runIsolated(candidates, ctx);

    const finalLock = await readLockfile(this.d.projectDir);
    const applied = new Set(outcomes.filter((o) => o.status === 'applied').flatMap((o) => o.candidate.resolves.map((id) => `${id}|${o.candidate.packageName}`)));
    const remaining = config.verify.rescan ? await this.d.scan() : before.filter((v) => !applied.has(vulnKey(v)));
    return { snapshotId, mode, outcomes, changes: diffLockfiles(ctx.initialLock, finalLock), remaining, baseline };
  }

  // -- strategies ---------------------------------------------------------

  private async runIsolated(candidates: FixCandidate[], ctx: Ctx): Promise<FixOutcome[]> {
    const outcomes: FixOutcome[] = [];
    for (const [i, c] of candidates.entries()) {
      const t = Date.now();
      this.d.logger.info(`[${i + 1}/${candidates.length}] ${c.packageName} ${c.fromVersion} → ${c.toVersion} (${c.bump}, ${c.risk} risk)`);
      const checkpoint = await this.d.snapshots.read();
      let verification: VerificationReport | undefined;
      try {
        await this.applyOne(c);
        verification = await this.d.verifier.verify({ ...ctx, applied: [c] });
        if (verification.passed) {
          outcomes.push({ candidate: c, status: 'applied', verification, durationMs: Date.now() - t });
          continue;
        }
      } catch (err: any) {
        verification = { passed: false, steps: [{ name: 'apply', status: 'failed', durationMs: Date.now() - t, detail: err.message }] };
      }
      this.d.logger.warn(`  ✗ ${failedStepName(verification)} failed – rolling back ${c.packageName}: ${firstFailure(verification)}`);
      await this.restore(checkpoint);
      outcomes.push({ candidate: c, status: 'rolled-back', reason: `${failedStepName(verification)}: ${firstFailure(verification)}`, verification, durationMs: Date.now() - t });
    }
    return outcomes;
  }

  private async runBatch(candidates: FixCandidate[], ctx: Ctx): Promise<FixOutcome[]> {
    const t = Date.now();
    let verification: VerificationReport;
    try {
      for (const c of candidates) await this.applyOne(c);
      verification = await this.d.verifier.verify({ ...ctx, applied: candidates });
    } catch (err: any) {
      verification = { passed: false, steps: [{ name: 'apply', status: 'failed', durationMs: Date.now() - t, detail: err.message }] };
    }
    if (verification.passed) {
      return candidates.map((candidate) => ({ candidate, status: 'applied' as const, verification, durationMs: Date.now() - t }));
    }
    this.d.logger.warn(`Batch failed at ${failedStepName(verification)} – rolling everything back: ${firstFailure(verification)}`);
    await this.restore(ctx.initial);
    return candidates.map((candidate) => ({
      candidate, status: 'rolled-back' as const, reason: `${failedStepName(verification)}: ${firstFailure(verification)}`, verification, durationMs: Date.now() - t,
    }));
  }

  // -- primitives ---------------------------------------------------------

  private async applyOne(c: FixCandidate): Promise<void> {
    if (c.action === 'upgrade-direct') {
      await this.d.pm.installExact(c.packageName, c.toVersion, savePrefixOf(c.declaredRange));
    } else {
      await writeOverride(this.d.projectDir, c.overrideKey ?? c.packageName, c.toVersion);
      await this.d.pm.install();
    }
  }

  /** Restore dependency files and rebuild node_modules from them. */
  async restore(cp: Checkpoint): Promise<void> {
    await this.d.snapshots.write(cp);
    try {
      await this.d.pm.cleanInstall();
    } catch (err: any) {
      throw new VPatchError('ROLLBACK_FAILED', `${err.message}\npackage.json and the lockfile were restored; run \`npm ci\` manually.`, { cause: err });
    }
  }
}

interface Ctx {
  initial: Checkpoint;
  initialLock: ReturnType<typeof parseLockfile>;
  initialVulnKeys: Set<string>;
  approved: FixCandidate[];
}
