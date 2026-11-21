import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { parseConfig } from '../src/config.js';
import { silentLogger } from '../src/logger.js';
import { PatchApplier } from '../src/patcher/applier.js';
import { SnapshotStore } from '../src/patcher/snapshot.js';
import type { VerificationRunner } from '../src/patcher/verifier.js';
import type { PackageManager } from '../src/pm/adapter.js';
import type { FixCandidate } from '../src/types.js';

let dir: string;
const j = (p: string) => path.join(dir, p);
const read = async (p: string) => JSON.parse(await readFile(j(p), 'utf8'));

const cand = (name: string, to: string): FixCandidate => ({
  id: `${name}@${to}`, action: 'upgrade-direct', packageName: name, fromVersion: '1.0.0', toVersion: to, declaredRange: '^1.0.0',
  bump: 'patch', risk: 'low', severity: 'high', resolves: [`GHSA-${name}`], autoApply: true, notes: [],
});

/** Fake npm: mutates package.json + lockfile exactly like an install would. */
class FakePm implements PackageManager {
  name = 'fake'; lockfile = 'package-lock.json'; ci = 0;
  async audit() { return '{}'; }
  async getVersions() { return []; }
  async installExact(name: string, version: string) {
    const pkg = await read('package.json'); pkg.dependencies[name] = `^${version}`;
    await writeFile(j('package.json'), JSON.stringify(pkg, null, 2));
    const lock = await read('package-lock.json'); lock.packages[`node_modules/${name}`].version = version;
    await writeFile(j('package-lock.json'), JSON.stringify(lock, null, 2));
  }
  async install() {}
  async cleanInstall() { this.ci++; }
  async runScript() { return { stdout: '', stderr: '', exitCode: 0, timedOut: false }; }
  async listProblems() { return []; }
}

const verifier = (failFor: string[], baselinePasses = true): VerificationRunner & { calls: string[][] } => {
  const calls: string[][] = [];
  return {
    calls,
    async captureBaseline() {
      return { passed: baselinePasses, steps: [{ name: 'test', status: baselinePasses ? 'passed' : 'failed', durationMs: 1, detail: 'baseline red' }] };
    },
    async verify({ applied }) {
      calls.push(applied.map((c) => c.packageName));
      const bad = applied.some((c) => failFor.includes(c.packageName));
      return { passed: !bad, steps: [{ name: 'test', status: bad ? 'failed' : 'passed', durationMs: 1, detail: bad ? 'tests failed: 3 failing' : undefined }] };
    },
  };
};

const build = (v: VerificationRunner, pm = new FakePm(), mode: 'isolated' | 'batch' = 'isolated') => ({
  pm,
  applier: new PatchApplier({
    projectDir: dir, pm, verifier: v, logger: silentLogger, scan: async () => [],
    config: parseConfig({ apply: { mode } }), snapshots: new SnapshotStore(dir, '.vpatch', 'package-lock.json'),
  }),
});

beforeEach(async () => {
  dir = await mkdtemp(path.join(os.tmpdir(), 'vpatch-'));
  await writeFile(j('package.json'), JSON.stringify({ name: 'app', dependencies: { a: '^1.0.0', b: '^1.0.0', c: '^1.0.0' } }, null, 2));
  await writeFile(j('package-lock.json'), JSON.stringify({
    lockfileVersion: 3,
    packages: { '': {}, 'node_modules/a': { version: '1.0.0' }, 'node_modules/b': { version: '1.0.0' }, 'node_modules/c': { version: '1.0.0' } },
  }, null, 2));
});
afterEach(() => rm(dir, { recursive: true, force: true }));

describe('PatchApplier', () => {
  it('isolated mode: keeps good fixes, rolls back only the one that breaks the app', async () => {
    const { applier, pm } = build(verifier(['b']));
    const r = await applier.apply([cand('a', '1.0.1'), cand('b', '1.0.1'), cand('c', '1.0.1')], []);

    expect(r.outcomes.map((o) => `${o.candidate.packageName}:${o.status}`)).toEqual(['a:applied', 'b:rolled-back', 'c:applied']);
    expect(r.outcomes[1]!.reason).toMatch(/tests failed/);
    const lock = await read('package-lock.json');
    expect(lock.packages['node_modules/a'].version).toBe('1.0.1');
    expect(lock.packages['node_modules/b'].version).toBe('1.0.0'); // restored
    expect(lock.packages['node_modules/c'].version).toBe('1.0.1');
    expect((await read('package.json')).dependencies.b).toBe('^1.0.0');
    expect(pm.ci).toBe(1); // node_modules rebuilt once, for the rollback
    expect(r.changes.map((c) => c.name).sort()).toEqual(['a', 'c']);
  });

  it('batch mode: one failure restores the original state completely', async () => {
    const before = { pkg: await readFile(j('package.json'), 'utf8'), lock: await readFile(j('package-lock.json'), 'utf8') };
    const { applier } = build(verifier(['c']), new FakePm(), 'batch');
    const r = await applier.apply([cand('a', '1.0.1'), cand('b', '1.0.1'), cand('c', '1.0.1')], []);

    expect(r.outcomes.every((o) => o.status === 'rolled-back')).toBe(true);
    expect(await readFile(j('package.json'), 'utf8')).toBe(before.pkg);
    expect(await readFile(j('package-lock.json'), 'utf8')).toBe(before.lock);
  });

  it('aborts before touching anything when the baseline is already failing', async () => {
    const { applier } = build(verifier([], false));
    await expect(applier.apply([cand('a', '1.0.1')], [])).rejects.toMatchObject({ code: 'BASELINE_FAILED' });
    expect((await read('package-lock.json')).packages['node_modules/a'].version).toBe('1.0.0');
  });

  it('dry-run changes nothing and runs no verification', async () => {
    const v = verifier([]);
    const { applier, pm } = build(v);
    const r = await applier.apply([cand('a', '1.0.1')], [], { dryRun: true });
    expect(r.outcomes[0]!.status).toBe('dry-run');
    expect(v.calls).toEqual([]);
    expect(pm.ci).toBe(0);
  });

  it('turns an install crash into a rollback instead of leaving a half-applied tree', async () => {
    const pm = new FakePm();
    const original = pm.installExact.bind(pm);
    pm.installExact = async (n, v) => { await original(n, v); if (n === 'b') throw new Error('ERESOLVE unable to resolve dependency tree'); };
    const { applier } = build(verifier([]), pm);
    const r = await applier.apply([cand('b', '1.0.1')], []);
    expect(r.outcomes[0]).toMatchObject({ status: 'rolled-back', reason: expect.stringContaining('ERESOLVE') });
    expect((await read('package-lock.json')).packages['node_modules/b'].version).toBe('1.0.0');
  });

  it('persists a snapshot that `rollback` can restore later', async () => {
    const { applier } = build(verifier([]));
    const r = await applier.apply([cand('a', '1.0.1')], []);
    const store = new SnapshotStore(dir, '.vpatch', 'package-lock.json');
    const snap = await store.load(r.snapshotId);
    expect(JSON.parse(snap.lockfile).packages['node_modules/a'].version).toBe('1.0.0');
  });
});
