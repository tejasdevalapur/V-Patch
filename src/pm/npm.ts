import type { Executor, ExecResult } from '../exec.js';
import { assertSafePackageName, assertSafeVersion, tail } from '../exec.js';
import { VPatchError } from '../errors.js';
import type { PackageManager, RegistryVersion } from './adapter.js';
import semver from 'semver';

export interface NpmOptions {
  ignoreScripts?: boolean;
  timeoutMs?: number;
}

export class NpmPackageManager implements PackageManager {
  readonly name = 'npm';
  readonly lockfile = 'package-lock.json';
  private cache = new Map<string, RegistryVersion[]>();

  constructor(
    private exec: Executor,
    private cwd: string,
    private opts: NpmOptions = {},
  ) {}

  private run(args: string[], timeoutMs = this.opts.timeoutMs): Promise<ExecResult> {
    return this.exec.run('npm', args, { cwd: this.cwd, timeoutMs });
  }

  private installFlags(): string[] {
    return ['--no-audit', '--no-fund', ...(this.opts.ignoreScripts ? ['--ignore-scripts'] : [])];
  }

  async audit({ includeDev }: { includeDev: boolean }): Promise<string> {
    // `npm audit` exits 1 when it finds vulnerabilities, so only stdout content matters.
    const r = await this.run(['audit', '--json', ...(includeDev ? [] : ['--omit=dev'])]);
    if (!r.stdout.trim()) {
      throw new VPatchError('SCAN_FAILED', `npm audit produced no output (exit ${r.exitCode}): ${tail(r.stderr, 5)}`);
    }
    return r.stdout;
  }

  async getVersions(name: string): Promise<RegistryVersion[]> {
    assertSafePackageName(name);
    const hit = this.cache.get(name);
    if (hit) return hit;
    const r = await this.run(['view', name, 'time', '--json']);
    let parsed: Record<string, string>;
    try {
      parsed = JSON.parse(r.stdout);
    } catch {
      throw new VPatchError('REGISTRY_FAILED', `Could not read versions for ${name}: ${tail(r.stderr || r.stdout, 5)}`);
    }
    if ((parsed as any).error) {
      throw new VPatchError('REGISTRY_FAILED', `Registry error for ${name}: ${(parsed as any).error.summary ?? 'unknown'}`);
    }
    const versions = Object.entries(parsed)
      .filter(([v]) => semver.valid(v))
      .map(([version, publishedAt]) => ({ version, publishedAt }));
    this.cache.set(name, versions);
    return versions;
  }

  async installExact(name: string, version: string, savePrefix: '^' | '~' | ''): Promise<void> {
    assertSafePackageName(name);
    assertSafeVersion(version);
    const r = await this.run(['install', `${name}@${version}`, `--save-prefix=${savePrefix}`, ...this.installFlags()]);
    if (r.exitCode !== 0) throw new VPatchError('APPLY_FAILED', `npm install ${name}@${version} failed:\n${tail(r.stderr)}`);
  }

  async install(): Promise<void> {
    const r = await this.run(['install', ...this.installFlags()]);
    if (r.exitCode !== 0) throw new VPatchError('APPLY_FAILED', `npm install failed:\n${tail(r.stderr)}`);
  }

  async cleanInstall(): Promise<void> {
    const r = await this.run(['ci', ...this.installFlags()]);
    if (r.exitCode !== 0) throw new VPatchError('ROLLBACK_FAILED', `npm ci failed during restore:\n${tail(r.stderr)}`);
  }

  runScript(name: string): Promise<ExecResult> {
    return this.run(['run', name], this.opts.timeoutMs);
  }

  async listProblems(): Promise<string[]> {
    const r = await this.run(['ls', '--all', '--json']);
    try {
      const problems: string[] = JSON.parse(r.stdout).problems ?? [];
      // Strip absolute paths so baseline and post-patch problems compare equal.
      return problems.map((p) => p.split(this.cwd).join('.')).sort();
    } catch {
      return [];
    }
  }
}
