import { describe, expect, it } from 'vitest';
import { render } from '../src/reporters/index.js';
import type { ReportData } from '../src/types.js';

const data: ReportData = {
  scan: {
    provider: 'npm-audit', scannedAt: 'now', projectDir: '/x', ignored: [],
    vulnerabilities: [{ id: 'GHSA-aaaa-bbbb-cccc', packageName: 'lodash', installedVersions: ['4.17.15'], severity: 'high', title: 'Cmd injection', url: 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc', cwe: ['CWE-77'], cvssScore: 7.2, vulnerableRange: '<4.17.21', isDirect: true, paths: [], source: 'npm-audit' }],
  },
  plan: { unfixable: [], candidates: [{ id: 'lodash@4.17.21', action: 'upgrade-direct', packageName: 'lodash', fromVersion: '4.17.15', toVersion: '4.17.21', bump: 'patch', risk: 'low', severity: 'high', resolves: ['GHSA-aaaa-bbbb-cccc'], autoApply: true, notes: [] }] },
};

describe('reporters', () => {
  it('emits valid-shaped SARIF 2.1.0 with a security-severity for GitHub code scanning', () => {
    const s = JSON.parse(render('sarif', data));
    expect(s.version).toBe('2.1.0');
    expect(s.runs[0].tool.driver.rules[0].properties['security-severity']).toBe('7.2');
    expect(s.runs[0].results[0]).toMatchObject({ ruleId: 'GHSA-aaaa-bbbb-cccc', level: 'error' });
    expect(s.runs[0].results[0].message.text).toContain('upgrade to 4.17.21');
  });
  it('emits a markdown report usable as a PR body', () => {
    const md = render('markdown', data);
    expect(md).toContain('# V-Patch report');
    expect(md).toContain('[GHSA-aaaa-bbbb-cccc](https://github.com/advisories/GHSA-aaaa-bbbb-cccc)');
  });
  it('table output names the fix', () => {
    expect(render('table', data)).toMatch(/4\.17\.21 \(patch, low risk\)/);
  });
});
