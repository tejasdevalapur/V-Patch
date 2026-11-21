import { describe, expect, it } from 'vitest';
import { advisoryId, parseNpmAuditReport } from '../src/scanner/npm-audit.js';
import { VPatchError } from '../src/errors.js';
import { AUDIT_REPORT, lockOf } from './fixtures.js';

const lock = lockOf({
  'node_modules/lodash': { version: '4.17.15' },
  'node_modules/mkdirp': { version: '0.5.1', dependencies: { minimist: '0.0.8' } },
  'node_modules/mkdirp/node_modules/minimist': { version: '1.2.0' },
});

describe('parseNpmAuditReport', () => {
  const vulns = parseNpmAuditReport(JSON.stringify(AUDIT_REPORT), lock);

  it('emits one entry per advisory and ignores string-only "via" links', () => {
    expect(vulns.map((v) => `${v.packageName}:${v.id}`).sort()).toEqual([
      'lodash:GHSA-29mw-wpgm-hmr9', 'lodash:GHSA-35jh-r3h4-6jhm', 'minimist:GHSA-xvch-5gv4-984h',
    ]);
  });
  it('resolves installed versions from the lockfile, including nested copies', () => {
    expect(vulns.find((v) => v.packageName === 'minimist')?.installedVersions).toEqual(['1.2.0']);
    expect(vulns.find((v) => v.packageName === 'lodash')?.installedVersions).toEqual(['4.17.15']);
  });
  it('maps severity, cvss and directness', () => {
    const m = vulns.find((v) => v.packageName === 'minimist')!;
    expect(m).toMatchObject({ severity: 'critical', cvssScore: 9.8, isDirect: false });
  });
  it('drops advisories whose range does not match anything installed', () => {
    const fixedLock = lockOf({ 'node_modules/lodash': { version: '4.17.21' } });
    expect(parseNpmAuditReport(JSON.stringify(AUDIT_REPORT), fixedLock).filter((v) => v.packageName === 'lodash')).toEqual([]);
  });
  it('surfaces audit errors instead of reporting "no vulnerabilities"', () => {
    const err = JSON.stringify({ error: { code: 'ENOAUDIT', summary: 'registry unreachable' } });
    expect(() => parseNpmAuditReport(err, lock)).toThrow(VPatchError);
    expect(() => parseNpmAuditReport('not json', lock)).toThrow(/invalid JSON/);
  });
  it('extracts GHSA ids from advisory urls', () => {
    expect(advisoryId({ url: 'https://github.com/advisories/GHSA-35jh-r3h4-6jhm' })).toBe('GHSA-35jh-r3h4-6jhm');
    expect(advisoryId({ source: 42 })).toBe('NPM-42');
  });
});
