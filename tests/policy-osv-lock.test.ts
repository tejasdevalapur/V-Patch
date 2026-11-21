import { describe, expect, it } from 'vitest';
import { applyPolicy } from '../src/scanner/policy.js';
import { osvEventsToRange } from '../src/scanner/osv.js';
import { diffLockfiles } from '../src/lockfile.js';
import { parseConfig } from '../src/config.js';
import type { Vulnerability } from '../src/types.js';
import { lockOf } from './fixtures.js';

const v = (id: string, severity: Vulnerability['severity']): Vulnerability => ({
  id, packageName: 'p', installedVersions: ['1.0.0'], severity, title: '', cwe: [], vulnerableRange: '*', isDirect: true, paths: [], source: 't',
});

describe('applyPolicy', () => {
  const cfg = (extra: object) => parseConfig({ severityThreshold: 'moderate', ...extra });
  it('filters below the severity threshold', () => {
    expect(applyPolicy([v('a', 'low'), v('b', 'high')], cfg({})).kept.map((x) => x.id)).toEqual(['b']);
  });
  it('honours a waiver until it expires', () => {
    const c = cfg({ ignore: [{ id: 'GHSA-1', reason: 'not reachable', expires: '2026-12-01' }] });
    const before = applyPolicy([v('ghsa-1', 'high')], c, new Date('2026-11-21'));
    expect(before.ignored).toHaveLength(1);
    const after = applyPolicy([v('ghsa-1', 'high')], c, new Date('2027-01-01'));
    expect(after.kept).toHaveLength(1);
  });
  it('rejects a waiver without a reason', () => {
    expect(() => parseConfig({ ignore: [{ id: 'x', reason: '' }] })).toThrow(/reason/);
  });
});

describe('osvEventsToRange', () => {
  it('handles introduced/fixed pairs, multiple windows and open-ended ranges', () => {
    expect(osvEventsToRange([{ introduced: '0' }, { fixed: '4.17.21' }])).toBe('>=0.0.0 <4.17.21');
    expect(osvEventsToRange([{ introduced: '1.0.0' }, { fixed: '1.2.0' }, { introduced: '2.0.0' }, { last_affected: '2.1.0' }])).toBe('>=1.0.0 <1.2.0 || >=2.0.0 <=2.1.0');
    expect(osvEventsToRange([{ introduced: '3.0.0' }])).toBe('>=3.0.0');
  });
});

describe('diffLockfiles', () => {
  it('reports added / removed / changed with bump type', () => {
    const a = lockOf({ 'node_modules/a': { version: '1.0.0' }, 'node_modules/b': { version: '1.0.0' }, 'node_modules/c': { version: '1.0.0' } });
    const b = lockOf({ 'node_modules/a': { version: '1.0.1' }, 'node_modules/b': { version: '2.0.0' }, 'node_modules/d': { version: '1.0.0' } });
    const d = diffLockfiles(a, b);
    expect(d.map((x) => `${x.name}:${x.type}:${x.bump ?? ''}`)).toEqual(['a:changed:patch', 'b:changed:major', 'c:removed:', 'd:added:']);
  });
});
