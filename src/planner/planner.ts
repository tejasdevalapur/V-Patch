import semver from 'semver';
import type { VPatchConfig } from '../config.js';
import type { Logger } from '../logger.js';
import { dependentRanges, type Lock } from '../lockfile.js';
import type { RegistryReader, RegistryVersion } from '../pm/adapter.js';
import { bumpBetween, declaredRangeOf, savePrefixOf, type Manifest } from '../project.js';
import { mapLimit } from '../util.js';
import {
  BUMP_ORDER,
  maxSeverity,
  severityRank,
  type BumpType,
  type FixCandidate,
  type FixPlan,
  type RiskLevel,
  type UnfixableEntry,
  type Vulnerability,
} from '../types.js';

const RISK_BY_BUMP: Record<BumpType, RiskLevel> = { patch: 'low', minor: 'medium', major: 'high' };
const RISK_ORDER: RiskLevel[] = ['low', 'medium', 'high'];
const escalate = (r: RiskLevel): RiskLevel => RISK_ORDER[Math.min(RISK_ORDER.indexOf(r) + 1, 2)]!;

export interface PlannerDeps {
  registry: RegistryReader;
  manifest: Manifest;
  lock: Lock;
  policy: VPatchConfig['policy'];
  logger: Logger;
  now?: () => Date;
}

/**
 * Turns vulnerabilities into the *smallest safe change* that removes them.
 * It never guesses: every target version comes from the registry and is checked
 * against the advisory's vulnerable range.
 */
export class FixPlanner {
  constructor(private d: PlannerDeps) {}

  async plan(vulns: Vulnerability[]): Promise<FixPlan> {
    const byPackage = new Map<string, Vulnerability[]>();
    for (const v of vulns) byPackage.set(v.packageName, [...(byPackage.get(v.packageName) ?? []), v]);

    const perPackage = await mapLimit([...byPackage.entries()], 5, ([name, list]) => this.planPackage(name, list));
    const candidates = perPackage.flatMap((r) => r.candidates);
    const unfixable = perPackage.flatMap((r) => r.unfixable);

    candidates.sort(
      (a, b) =>
        severityRank(b.severity) - severityRank(a.severity) ||
        RISK_ORDER.indexOf(a.risk) - RISK_ORDER.indexOf(b.risk) ||
        a.packageName.localeCompare(b.packageName),
    );
    return { candidates, unfixable };
  }

  private async planPackage(name: string, vulns: Vulnerability[]): Promise<{ candidates: FixCandidate[]; unfixable: UnfixableEntry[] }> {
    const { manifest, lock, policy } = this.d;
    const candidates: FixCandidate[] = [];
    const unfixable: UnfixableEntry[] = [];

    let versions: RegistryVersion[];
    try {
      versions = await this.d.registry.getVersions(name);
    } catch (err: any) {
      return { candidates, unfixable: [{ packageName: name, vulnerabilityIds: vulns.map((v) => v.id), reason: err.message }] };
    }

    const ranges = [...new Set(vulns.map((v) => v.vulnerableRange))];
    const isVulnerable = (v: string) => ranges.some((r) => semver.satisfies(v, r, { includePrerelease: true }));
    const cutoff = this.d.now?.() ?? new Date();
    const tooNew = (rv: RegistryVersion) =>
      policy.minReleaseAgeDays > 0 &&
      rv.publishedAt !== undefined &&
      (cutoff.getTime() - new Date(rv.publishedAt).getTime()) / 86_400_000 < policy.minReleaseAgeDays;

    // Several vulnerable copies on different major lines need one fix per line.
    const installed = [...new Set(vulns.flatMap((v) => v.installedVersions))].filter((v) => semver.valid(v));
    const lines = new Map<number, string[]>();
    for (const v of installed) lines.set(semver.major(v), [...(lines.get(semver.major(v)) ?? []), v]);

    for (const [major, group] of lines) {
      const from = semver.rsort([...group])[0]!;
      const resolves = vulns.filter((v) => v.installedVersions.some((iv) => group.includes(iv)));
      const eligible = versions
        .filter((rv) => (semver.prerelease(rv.version) ? false : true))
        .filter((rv) => semver.gt(rv.version, from) && !isVulnerable(rv.version))
        .sort((a, b) => semver.compare(a.version, b.version));
      const fresh = eligible.filter((rv) => !tooNew(rv));

      const sameMajor = fresh.filter((rv) => semver.major(rv.version) === major);
      let target: string | undefined;
      if (policy.versionStrategy === 'latest-in-major' && sameMajor.length) target = sameMajor[sameMajor.length - 1]!.version;
      else target = fresh[0]?.version;

      if (!target) {
        const blockedByAge = eligible.length > 0;
        unfixable.push({
          packageName: name,
          vulnerabilityIds: resolves.map((v) => v.id),
          reason: blockedByAge
            ? `Patched version ${eligible[0]!.version} exists but is newer than minReleaseAgeDays (${policy.minReleaseAgeDays}d)`
            : `No patched version of ${name} has been published for ${major}.x and above`,
        });
        continue;
      }

      const bump = bumpBetween(from, target);
      const declaredRange = declaredRangeOf(manifest, name);
      const isDirect = declaredRange !== undefined && semver.satisfies(from, declaredRange);
      const notes: string[] = [];
      let risk = RISK_BY_BUMP[bump];
      if (bump === 'major') notes.push('Major version change: review the changelog; API or behaviour may differ.');

      if (!isDirect) {
        const dependents = dependentRanges(this.d.lock, name).filter((d) => semver.validRange(d.range));
        const outside = dependents.filter((d) => !semver.satisfies(target!, d.range));
        if (outside.length) {
          risk = escalate(risk);
          notes.push(
            `Outside the range declared by ${[...new Set(outside.map((o) => `${o.dependent} (${o.range})`))].join(', ')}; forced via "overrides".`,
          );
        } else {
          notes.push('Within every dependent\'s declared range; applied via "overrides" to pin the patched version.');
        }
      } else if (!semver.satisfies(target, declaredRange!)) {
        notes.push(`package.json range "${declaredRange}" will be widened to include ${target}.`);
      }
      if (isDirect && resolves.some((v) => v.paths.some((p) => p.split('node_modules/').length > 2))) {
        notes.push('A nested copy also exists; re-scan after applying to confirm it is gone.');
      }

      const multi = lines.size > 1;
      candidates.push({
        id: `${name}@${target}`,
        action: isDirect ? 'upgrade-direct' : 'override-transitive',
        packageName: name,
        fromVersion: from,
        toVersion: target,
        declaredRange,
        overrideKey: !isDirect ? (multi ? `${name}@>=${major}.0.0 <${major + 1}.0.0` : name) : undefined,
        bump,
        risk,
        severity: maxSeverity(resolves.map((v) => v.severity)),
        resolves: resolves.map((v) => v.id),
        autoApply: BUMP_ORDER.indexOf(bump) <= BUMP_ORDER.indexOf(policy.autoApplyMaxBump) && risk !== 'high',
        notes,
      });
    }
    return { candidates, unfixable };
  }
}

export { savePrefixOf };
