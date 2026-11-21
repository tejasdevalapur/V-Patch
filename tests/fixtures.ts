import type { Lock } from '../src/lockfile.js';
import { parseLockfile } from '../src/lockfile.js';

export const lockJson = (pkgs: Record<string, { version: string; dependencies?: Record<string, string> }>) =>
  JSON.stringify({
    name: 'app', lockfileVersion: 3,
    packages: { '': { name: 'app' }, ...Object.fromEntries(Object.entries(pkgs).map(([p, v]) => [p, v])) },
  });

export const lockOf = (pkgs: Parameters<typeof lockJson>[0]): Lock => parseLockfile(lockJson(pkgs));

/** Trimmed real-world shape of `npm audit --json` (auditReportVersion 2). */
export const AUDIT_REPORT = {
  auditReportVersion: 2,
  vulnerabilities: {
    lodash: {
      name: 'lodash', severity: 'high', isDirect: true,
      via: [
        { source: 1106913, name: 'lodash', dependency: 'lodash', title: 'Command Injection in lodash', url: 'https://github.com/advisories/GHSA-35jh-r3h4-6jhm', severity: 'high', cwe: ['CWE-77'], cvss: { score: 7.2, vectorString: 'CVSS:3.1/...' }, range: '<4.17.21' },
        { source: 1106914, name: 'lodash', dependency: 'lodash', title: 'ReDoS in lodash', url: 'https://github.com/advisories/GHSA-29mw-wpgm-hmr9', severity: 'moderate', cwe: ['CWE-400'], cvss: { score: 5.3 }, range: '<4.17.21' },
      ],
      effects: [], range: '<4.17.21', nodes: ['node_modules/lodash'], fixAvailable: true,
    },
    minimist: {
      name: 'minimist', severity: 'critical', isDirect: false,
      via: [{ source: 1096465, name: 'minimist', dependency: 'minimist', title: 'Prototype Pollution in minimist', url: 'https://github.com/advisories/GHSA-xvch-5gv4-984h', severity: 'critical', cwe: ['CWE-1321'], cvss: { score: 9.8 }, range: '<1.2.6' }],
      effects: ['mkdirp'], range: '<1.2.6', nodes: ['node_modules/mkdirp/node_modules/minimist'], fixAvailable: true,
    },
    mkdirp: { name: 'mkdirp', severity: 'critical', isDirect: false, via: ['minimist'], effects: [], range: '0.4.1 - 0.5.1', nodes: ['node_modules/mkdirp'], fixAvailable: true },
  },
  metadata: {},
};
