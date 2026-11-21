import { describe, expect, it } from 'vitest';
import { FixPlanner } from '../src/planner/planner.js';
import { parseConfig } from '../src/config.js';
import { silentLogger } from '../src/logger.js';
import type { Manifest } from '../src/project.js';
import type { Vulnerability } from '../src/types.js';
import { lockOf } from './fixtures.js';

const manifest = (deps: Record<string, string>): Manifest => ({
  raw: {}, dependencies: deps, devDependencies: {}, optionalDependencies: {}, scripts: {}, overrides: {},
});
const registry = (table: Record<string, string[]>, dates: Record<string, string> = {}) => ({
  getVersions: async (n: string) => (table[n] ?? []).map((version) => ({ version, publishedAt: dates[`${n}@${version}`] })),
});
const vuln = (o: Partial<Vulnerability> & Pick<Vulnerability, 'packageName' | 'installedVersions' | 'vulnerableRange'>): Vulnerability => ({
  id: `GHSA-${o.packageName}`, severity: 'high', title: 't', cwe: [], isDirect: true, paths: [`node_modules/${o.packageName}`], source: 't', ...o,
});
const planner = (reg: any, deps: Record<string, string>, lock = lockOf({}), policy: any = {}, now?: Date) =>
  new FixPlanner({ registry: reg, manifest: manifest(deps), lock, policy: parseConfig({ policy }).policy, logger: silentLogger, now: now ? () => now : undefined });

describe('FixPlanner', () => {
  it('picks the lowest patched version and classes a patch bump as low risk, auto-applicable', async () => {
    const p = await planner(registry({ lodash: ['4.17.15', '4.17.20', '4.17.21', '4.18.0', '5.0.0'] }), { lodash: '^4.17.15' })
      .plan([vuln({ packageName: 'lodash', installedVersions: ['4.17.15'], vulnerableRange: '<4.17.21' })]);
    expect(p.candidates).toHaveLength(1);
    expect(p.candidates[0]).toMatchObject({ id: 'lodash@4.17.21', action: 'upgrade-direct', bump: 'patch', risk: 'low', autoApply: true });
  });

  it('flags a major-only fix as high risk and NOT auto-applicable', async () => {
    const p = await planner(registry({ old: ['1.0.0', '1.5.0', '2.0.0'] }), { old: '^1.0.0' })
      .plan([vuln({ packageName: 'old', installedVersions: ['1.5.0'], vulnerableRange: '<2.0.0' })]);
    expect(p.candidates[0]).toMatchObject({ toVersion: '2.0.0', bump: 'major', risk: 'high', autoApply: false });
    expect(p.candidates[0]!.notes.join(' ')).toMatch(/Major version/);
  });

  it('uses "overrides" for transitive deps and escalates risk when outside the dependent\'s range', async () => {
    const lock = lockOf({ 'node_modules/mkdirp': { version: '0.5.1', dependencies: { minimist: '~1.2.0' } }, 'node_modules/minimist': { version: '1.2.0' } });
    const p = await planner(registry({ minimist: ['1.2.0', '1.2.6', '1.3.0'] }), { mkdirp: '^0.5.1' }, lock, { versionStrategy: 'latest-in-major' })
      .plan([vuln({ packageName: 'minimist', installedVersions: ['1.2.0'], vulnerableRange: '<1.2.6', isDirect: false })]);
    expect(p.candidates[0]).toMatchObject({ action: 'override-transitive', overrideKey: 'minimist', toVersion: '1.3.0', bump: 'minor', risk: 'high' });
    expect(p.candidates[0]!.notes.join(' ')).toMatch(/Outside the range declared by mkdirp/);
  });

  it('reports unfixable when no patched version exists', async () => {
    const p = await planner(registry({ dead: ['1.0.0', '1.1.0'] }), { dead: '^1.0.0' })
      .plan([vuln({ packageName: 'dead', installedVersions: ['1.1.0'], vulnerableRange: '*' })]);
    expect(p.candidates).toEqual([]);
    expect(p.unfixable[0]!.reason).toMatch(/No patched version/);
  });

  it('honours minReleaseAgeDays (supply-chain cool-down)', async () => {
    const now = new Date('2026-11-21T00:00:00Z');
    const reg = registry({ x: ['1.0.0', '1.0.1'] }, { 'x@1.0.1': '2026-11-20T00:00:00Z' });
    const p = await planner(reg, { x: '^1.0.0' }, lockOf({}), { minReleaseAgeDays: 3 }, now)
      .plan([vuln({ packageName: 'x', installedVersions: ['1.0.0'], vulnerableRange: '<1.0.1' })]);
    expect(p.candidates).toEqual([]);
    expect(p.unfixable[0]!.reason).toMatch(/minReleaseAgeDays/);
  });

  it('never targets prereleases or versions that are themselves vulnerable', async () => {
    const p = await planner(registry({ y: ['1.0.0', '1.1.0-beta.1', '1.1.0', '1.2.0'] }), { y: '^1.0.0' })
      .plan([vuln({ packageName: 'y', installedVersions: ['1.0.0'], vulnerableRange: '<1.2.0' })]);
    expect(p.candidates[0]!.toVersion).toBe('1.2.0');
  });

  it('plans one fix per vulnerable major line with version-qualified override keys', async () => {
    const p = await planner(registry({ z: ['1.0.0', '1.0.5', '2.0.0', '2.0.4'] }), {})
      .plan([vuln({ packageName: 'z', installedVersions: ['1.0.0', '2.0.0'], vulnerableRange: '<1.0.5 || >=2.0.0 <2.0.4', isDirect: false })]);
    expect(p.candidates.map((c) => [c.toVersion, c.overrideKey]).sort()).toEqual([
      ['1.0.5', 'z@>=1.0.0 <2.0.0'], ['2.0.4', 'z@>=2.0.0 <3.0.0'],
    ]);
  });

  it('sorts by severity first', async () => {
    const p = await planner(registry({ a: ['1.0.0', '1.0.1'], b: ['1.0.0', '1.0.1'] }), { a: '^1.0.0', b: '^1.0.0' }).plan([
      vuln({ packageName: 'a', installedVersions: ['1.0.0'], vulnerableRange: '<1.0.1', severity: 'low' }),
      vuln({ packageName: 'b', installedVersions: ['1.0.0'], vulnerableRange: '<1.0.1', severity: 'critical' }),
    ]);
    expect(p.candidates.map((c) => c.packageName)).toEqual(['b', 'a']);
  });
});
