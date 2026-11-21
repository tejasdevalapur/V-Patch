import { existsSync } from 'node:fs';
import path from 'node:path';
import { loadConfig, parseConfig, type VPatchConfig, type VPatchConfigInput } from './config.js';
import { VPatchError } from './errors.js';
import { NodeExecutor, type Executor } from './exec.js';
import { ConsoleLogger, type Logger } from './logger.js';
import { readLockfile } from './lockfile.js';
import { PatchApplier, type ApplyOptions } from './patcher/applier.js';
import { SnapshotStore } from './patcher/snapshot.js';
import { ProjectVerifier } from './patcher/verifier.js';
import { FixPlanner } from './planner/planner.js';
import type { PackageManager } from './pm/adapter.js';
import { NpmPackageManager } from './pm/npm.js';
import { readManifest } from './project.js';
import { NpmAuditProvider } from './scanner/npm-audit.js';
import { OsvProvider } from './scanner/osv.js';
import { applyPolicy } from './scanner/policy.js';
import type { AuditProvider } from './scanner/provider.js';
import { nowIso } from './util.js';
import { severityRank, type ApplyResult, type FixCandidate, type FixPlan, type ScanResult, type Severity, type Vulnerability } from './types.js';

export interface VPatchOptions {
  projectDir?: string;
  /** Inline config (validated) or leave undefined to load vpatch.config.json. */
  config?: VPatchConfigInput;
  configPath?: string;
  logger?: Logger;
  /** Dependency-injection seams for tests and custom integrations. */
  executor?: Executor;
  provider?: AuditProvider;
  packageManager?: PackageManager;
}

export interface Selection {
  /** Candidate ids (`lodash@4.17.21`) or bare package names. */
  ids?: string[];
  /** Every candidate that policy marks as safe to auto-apply. */
  allSafe?: boolean;
}

export class VPatch {
  private constructor(
    readonly projectDir: string,
    readonly config: VPatchConfig,
    private logger: Logger,
    private exec: Executor,
    private provider: AuditProvider,
    private pm: PackageManager,
  ) {}

  static async create(opts: VPatchOptions = {}): Promise<VPatch> {
    const projectDir = path.resolve(opts.projectDir ?? process.cwd());
    const config = opts.config ? parseConfig(opts.config) : await loadConfig(projectDir, opts.configPath);
    const logger = opts.logger ?? new ConsoleLogger();
    const exec = opts.executor ?? new NodeExecutor();

    if (!opts.packageManager) {
      for (const [file, pm] of [['pnpm-lock.yaml', 'pnpm'], ['yarn.lock', 'yarn']] as const) {
        if (existsSync(path.join(projectDir, file)) && !existsSync(path.join(projectDir, 'package-lock.json'))) {
          throw new VPatchError('UNSUPPORTED_PROJECT', `${pm} projects are not supported yet (found ${file}). Implement PackageManager in src/pm/ to add it.`);
        }
      }
    }
    const pm = opts.packageManager ?? new NpmPackageManager(exec, projectDir, { ignoreScripts: config.apply.ignoreScripts, timeoutMs: config.verify.timeoutSeconds * 1000 });
    const provider = opts.provider ?? (config.provider === 'osv' ? new OsvProvider() : new NpmAuditProvider());
    return new VPatch(projectDir, config, logger, exec, provider, pm);
  }

  async scan(opts: { quiet?: boolean } = {}): Promise<ScanResult> {
    if (!opts.quiet) this.logger.info(`Scanning with ${this.provider.name}…`);
    const found = await this.provider.scan({ projectDir: this.projectDir, includeDev: this.config.includeDev, pm: this.pm, logger: this.logger });
    const { kept, ignored } = applyPolicy(found, this.config);
    return { provider: this.provider.name, scannedAt: nowIso(), projectDir: this.projectDir, vulnerabilities: kept, ignored };
  }

  async plan(scan: ScanResult): Promise<FixPlan> {
    this.logger.info('Planning minimal safe fixes…');
    const [manifest, lock] = await Promise.all([readManifest(this.projectDir), readLockfile(this.projectDir)]);
    return new FixPlanner({ registry: this.pm, manifest, lock, policy: this.config.policy, logger: this.logger }).plan(scan.vulnerabilities);
  }

  select(plan: FixPlan, sel: Selection): FixCandidate[] {
    const chosen = new Map<string, FixCandidate>();
    if (sel.allSafe) plan.candidates.filter((c) => c.autoApply).forEach((c) => chosen.set(c.id, c));
    for (const key of sel.ids ?? []) {
      const hits = plan.candidates.filter((c) => c.id === key || c.packageName === key);
      if (!hits.length) throw new VPatchError('CONFIG_INVALID', `No fix available for "${key}". Run \`vpatch plan\` to list valid ids.`);
      hits.forEach((c) => chosen.set(c.id, c));
    }
    return [...chosen.values()];
  }

  async apply(candidates: FixCandidate[], scan: ScanResult, opts: ApplyOptions = {}): Promise<ApplyResult> {
    const scanNow = async (): Promise<Vulnerability[]> => (await this.scan({ quiet: true })).vulnerabilities;
    const verifier = new ProjectVerifier({ projectDir: this.projectDir, pm: this.pm, exec: this.exec, config: this.config, logger: this.logger, scan: scanNow });
    const snapshots = this.snapshots();
    return new PatchApplier({ projectDir: this.projectDir, pm: this.pm, verifier, snapshots, config: this.config, logger: this.logger, scan: scanNow }).apply(candidates, scan.vulnerabilities, opts);
  }

  private snapshots(): SnapshotStore {
    return new SnapshotStore(this.projectDir, this.config.apply.snapshotDir, this.pm.lockfile);
  }

  /** Restore package.json + lockfile from a snapshot (default: most recent) and rebuild node_modules. */
  async rollback(id?: string): Promise<string> {
    const store = this.snapshots();
    const target = id ?? (await store.latestId());
    await store.write(await store.load(target));
    await this.pm.cleanInstall();
    return target;
  }
}

/** Vulnerabilities that should fail a CI gate. */
export const gate = (scan: ScanResult, failOn: Severity): Vulnerability[] =>
  scan.vulnerabilities.filter((v) => severityRank(v.severity) >= severityRank(failOn));
