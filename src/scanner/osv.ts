import semver from 'semver';
import { VPatchError } from '../errors.js';
import { readManifest, isDirectDependency } from '../project.js';
import { readLockfile } from '../lockfile.js';
import { mapLimit } from '../util.js';
import type { Severity, Vulnerability } from '../types.js';
import type { AuditProvider, ScanContext } from './provider.js';
import { toSeverity } from './npm-audit.js';

type Fetch = typeof fetch;

/** Convert OSV `events` (introduced / fixed / last_affected) into a semver range string. */
export function osvEventsToRange(events: Array<Record<string, string>>): string {
  const parts: string[] = [];
  let start: string | undefined;
  for (const e of events) {
    if ('introduced' in e) start = e.introduced === '0' ? '0.0.0' : e.introduced;
    else if ('fixed' in e && start !== undefined) { parts.push(`>=${start} <${e.fixed}`); start = undefined; }
    else if ('last_affected' in e && start !== undefined) { parts.push(`>=${start} <=${e.last_affected}`); start = undefined; }
  }
  if (start !== undefined) parts.push(`>=${start}`);
  return parts.join(' || ');
}

/** Queries OSV.dev (https://osv.dev) for every package in the lockfile. Works for any registry-hosted package. */
export class OsvProvider implements AuditProvider {
  readonly name = 'osv';
  constructor(private fetchImpl: Fetch = fetch, private baseUrl = 'https://api.osv.dev') {}

  private async json(url: string, init?: RequestInit): Promise<any> {
    const res = await this.fetchImpl(url, init);
    if (!res.ok) throw new VPatchError('SCAN_FAILED', `OSV request failed (${res.status}) for ${url}`);
    return res.json();
  }

  async scan(ctx: ScanContext): Promise<Vulnerability[]> {
    const [lock, manifest] = await Promise.all([readLockfile(ctx.projectDir), readManifest(ctx.projectDir)]);
    const pkgs = new Map<string, { name: string; version: string; paths: string[] }>();
    for (const [p, e] of lock) {
      if (!ctx.includeDev && e.dev) continue;
      const k = `${e.name}@${e.version}`;
      const cur = pkgs.get(k) ?? { name: e.name, version: e.version, paths: [] };
      cur.paths.push(p);
      pkgs.set(k, cur);
    }
    const list = [...pkgs.values()];

    // 1) batch query for ids (OSV caps a batch at 1000 queries)
    const hits: { pkg: (typeof list)[number]; ids: string[] }[] = [];
    for (let i = 0; i < list.length; i += 1000) {
      const chunk = list.slice(i, i + 1000);
      const body = { queries: chunk.map((p) => ({ package: { name: p.name, ecosystem: 'npm' }, version: p.version })) };
      const res = await this.json(`${this.baseUrl}/v1/querybatch`, {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
      });
      (res.results ?? []).forEach((r: any, idx: number) => {
        const ids = (r.vulns ?? []).map((v: any) => v.id as string);
        if (ids.length) hits.push({ pkg: chunk[idx]!, ids });
      });
    }

    // 2) fetch details once per advisory
    const uniqueIds = [...new Set(hits.flatMap((h) => h.ids))];
    ctx.logger.debug(`OSV: ${hits.length} affected package versions, ${uniqueIds.length} advisories`);
    const details = new Map<string, any>();
    await mapLimit(uniqueIds, 8, async (id) => {
      details.set(id, await this.json(`${this.baseUrl}/v1/vulns/${encodeURIComponent(id)}`));
    });

    // 3) normalise
    const out = new Map<string, Vulnerability>();
    for (const { pkg, ids } of hits) {
      for (const id of ids) {
        const d = details.get(id);
        const affected = (d?.affected ?? []).filter((a: any) => a.package?.ecosystem === 'npm' && a.package?.name === pkg.name);
        const range = affected
          .flatMap((a: any) => (a.ranges ?? []).filter((r: any) => r.type === 'SEMVER').map((r: any) => osvEventsToRange(r.events ?? [])))
          .filter(Boolean)
          .join(' || ');
        if (!range || !semver.satisfies(pkg.version, range, { includePrerelease: true })) continue;
        const aliasGhsa: string | undefined = [d.id, ...(d.aliases ?? [])].find((a: string) => /^GHSA-/.test(a));
        const vid = aliasGhsa ?? d.id;
        const key = `${vid}|${pkg.name}`;
        const sev: Severity = toSeverity(d.database_specific?.severity);
        const existing = out.get(key);
        if (existing) {
          existing.installedVersions = [...new Set([...existing.installedVersions, pkg.version])];
          existing.paths.push(...pkg.paths);
          continue;
        }
        out.set(key, {
          id: vid,
          packageName: pkg.name,
          installedVersions: [pkg.version],
          severity: sev,
          title: d.summary ?? vid,
          url: d.references?.find((r: any) => r.type === 'ADVISORY')?.url ?? `https://osv.dev/vulnerability/${d.id}`,
          cwe: d.database_specific?.cwe_ids ?? [],
          vulnerableRange: range,
          isDirect: isDirectDependency(manifest, pkg.name),
          paths: [...pkg.paths],
          source: 'osv',
        });
      }
    }
    return [...out.values()];
  }
}
