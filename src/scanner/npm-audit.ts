import semver from 'semver';
import { VPatchError } from '../errors.js';
import { readLockfile, type Lock } from '../lockfile.js';
import type { Severity, Vulnerability } from '../types.js';
import type { AuditProvider, ScanContext } from './provider.js';

const SEVERITY_MAP: Record<string, Severity> = {
  info: 'info', low: 'low', moderate: 'moderate', medium: 'moderate', high: 'high', critical: 'critical',
};
export const toSeverity = (s: unknown): Severity => SEVERITY_MAP[String(s).toLowerCase()] ?? 'moderate';

export function advisoryId(via: { url?: string; source?: number | string }): string {
  const ghsa = /GHSA(-[a-z0-9]{4}){3}/i.exec(via.url ?? '')?.[0];
  return ghsa ? `GHSA${ghsa.slice(4).toLowerCase()}` : `NPM-${via.source}`;
}

/** Parse `npm audit --json` (auditReportVersion 2, npm >= 7) into provider-neutral vulnerabilities. */
export function parseNpmAuditReport(raw: string, lock: Lock): Vulnerability[] {
  let report: any;
  try {
    report = JSON.parse(raw);
  } catch (err) {
    throw new VPatchError('SCAN_FAILED', 'npm audit returned invalid JSON', { cause: err });
  }
  if (report.error) {
    throw new VPatchError('SCAN_FAILED', `npm audit failed: ${report.error.summary ?? report.error.code ?? 'unknown error'}`);
  }
  if (!report.vulnerabilities) {
    throw new VPatchError('SCAN_FAILED', 'Unrecognised npm audit report (need npm 7+ / auditReportVersion 2)');
  }

  const out = new Map<string, Vulnerability>();
  for (const [name, entry] of Object.entries<any>(report.vulnerabilities)) {
    const nodes: string[] = entry.nodes ?? [];
    for (const via of entry.via ?? []) {
      // String entries are just "this package is vulnerable because of another vulnerable package".
      if (typeof via === 'string' || via.name !== name) continue;
      const installed = nodes
        .map((n) => lock.get(n)?.version)
        .filter((v): v is string => Boolean(v) && Boolean(semver.validRange(via.range)) && semver.satisfies(v as string, via.range, { includePrerelease: true }));
      const id = advisoryId(via);
      const key = `${id}|${name}`;
      const existing = out.get(key);
      const versions = [...new Set(installed)];
      if (existing) {
        existing.installedVersions = [...new Set([...existing.installedVersions, ...versions])];
        existing.paths = [...new Set([...existing.paths, ...nodes])];
        continue;
      }
      out.set(key, {
        id,
        packageName: name,
        installedVersions: versions,
        severity: toSeverity(via.severity),
        title: via.title ?? id,
        url: via.url,
        cwe: via.cwe ?? [],
        cvssScore: via.cvss?.score || undefined,
        vulnerableRange: via.range,
        isDirect: Boolean(entry.isDirect),
        paths: nodes,
        source: 'npm-audit',
      });
    }
  }
  return [...out.values()].filter((v) => v.installedVersions.length > 0);
}

export class NpmAuditProvider implements AuditProvider {
  readonly name = 'npm-audit';
  async scan(ctx: ScanContext): Promise<Vulnerability[]> {
    const [raw, lock] = await Promise.all([ctx.pm.audit({ includeDev: ctx.includeDev }), readLockfile(ctx.projectDir)]);
    return parseNpmAuditReport(raw, lock);
  }
}
