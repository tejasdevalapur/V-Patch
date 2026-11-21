import pc from 'picocolors';
import { severityRank, type FixCandidate, type ReportData, type Severity, type Vulnerability } from '../types.js';

export const VERSION = '1.0.0';
export type ReportFormat = 'table' | 'json' | 'markdown' | 'sarif';

export function render(format: ReportFormat, data: ReportData): string {
  switch (format) {
    case 'json': return JSON.stringify(data, null, 2) + '\n';
    case 'sarif': return JSON.stringify(toSarif(data), null, 2) + '\n';
    case 'markdown': return toMarkdown(data);
    default: return toTable(data);
  }
}

const sortBySeverity = (v: Vulnerability[]) =>
  [...v].sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || a.packageName.localeCompare(b.packageName));

const fixFor = (data: ReportData, v: Vulnerability): FixCandidate | undefined =>
  data.plan?.candidates.find((c) => c.packageName === v.packageName && c.resolves.includes(v.id));

// ---------------------------------------------------------------- table

const COLOR: Record<Severity, (s: string) => string> = {
  critical: (s) => pc.bgRed(pc.white(s)), high: pc.red, moderate: pc.yellow, low: pc.blue, info: pc.dim,
};

function toTable(data: ReportData): string {
  const lines: string[] = [];
  // After an apply, the interesting list is what is still open, not what was found at the start.
  const vulns = sortBySeverity(data.apply && data.apply.mode && data.apply.snapshotId !== '(dry-run)' ? data.apply.remaining : data.scan.vulnerabilities);
  const label = data.apply && data.apply.snapshotId !== '(dry-run)' ? 'remaining' : 'found';
  lines.push(pc.bold(`V-Patch (${data.scan.provider}) – ${vulns.length} vulnerabilit${vulns.length === 1 ? 'y' : 'ies'} ${label}`));
  if (data.scan.ignored.length) lines.push(pc.dim(`${data.scan.ignored.length} ignored by policy`));
  if (vulns.length) {
    const rows = vulns.map((v) => {
      const fix = fixFor(data, v);
      return [
        v.severity.toUpperCase(), v.packageName, v.installedVersions.join(', '), v.id,
        fix ? `${fix.toVersion} (${fix.bump}, ${fix.risk} risk${fix.autoApply ? '' : ', manual'})` : data.plan ? 'no fix' : '–',
      ];
    });
    const head = ['SEVERITY', 'PACKAGE', 'INSTALLED', 'ADVISORY', 'FIX'];
    const w = head.map((h, i) => Math.max(h.length, ...rows.map((r) => r[i]!.length)));
    const fmt = (r: string[], color = false) => r.map((c, i) => {
      const padded = c.padEnd(w[i]!);
      return color && i === 0 ? COLOR[c.toLowerCase() as Severity](padded) : padded;
    }).join('  ');
    lines.push('', pc.bold(fmt(head)), ...rows.map((r) => fmt(r, true)));
  }
  if (data.plan?.unfixable.length) {
    lines.push('', pc.bold('No automatic fix:'));
    for (const u of data.plan.unfixable) lines.push(`  ${u.packageName}: ${u.reason}`);
  }
  if (data.apply) {
    lines.push('', pc.bold(`Apply result (${data.apply.mode}, snapshot ${data.apply.snapshotId})`));
    for (const o of data.apply.outcomes) {
      const mark = o.status === 'applied' ? pc.green('✔ applied    ') : o.status === 'dry-run' ? pc.dim('○ dry-run    ') : pc.red('✖ rolled back');
      lines.push(`  ${mark} ${o.candidate.packageName} ${o.candidate.fromVersion} → ${o.candidate.toVersion}${o.reason ? pc.dim(`  (${o.reason})`) : ''}`);
    }
    lines.push(`  ${data.apply.changes.length} lockfile entr${data.apply.changes.length === 1 ? 'y' : 'ies'} changed, ${data.apply.remaining.length} vulnerabilit${data.apply.remaining.length === 1 ? 'y' : 'ies'} remaining`);
  }
  return lines.join('\n') + '\n';
}

// ---------------------------------------------------------------- markdown (PR body / job summary)

function toMarkdown(data: ReportData): string {
  const out: string[] = ['# V-Patch report', ''];
  const a = data.apply;
  if (a) {
    const ok = a.outcomes.filter((o) => o.status === 'applied');
    const bad = a.outcomes.filter((o) => o.status === 'rolled-back');
    out.push(`**${ok.length} fix(es) applied**, ${bad.length} rolled back, ${a.remaining.length} vulnerabilit${a.remaining.length === 1 ? 'y' : 'ies'} remaining.`, '');
    if (a.outcomes.length) {
      out.push('| Package | Change | Bump | Risk | Result |', '|---|---|---|---|---|');
      for (const o of a.outcomes) {
        const c = o.candidate;
        out.push(`| \`${c.packageName}\` | ${c.fromVersion} → ${c.toVersion} | ${c.bump} | ${c.risk} | ${o.status === 'applied' ? '✅ applied' : o.status === 'dry-run' ? 'dry-run' : `❌ rolled back: ${(o.reason ?? '').replace(/\|/g, '\\|')}`} |`);
      }
      out.push('');
    }
    out.push(`Verification: each fix was checked for blast radius, dependency-tree health, security re-scan, build, tests and custom commands. Snapshot: \`${a.snapshotId}\`.`, '');
  }
  const vulns = sortBySeverity(a ? a.remaining : data.scan.vulnerabilities);
  out.push(`## ${a ? 'Remaining' : 'Detected'} vulnerabilities (${vulns.length})`, '');
  if (vulns.length) {
    out.push('| Severity | Package | Installed | Advisory | Fix |', '|---|---|---|---|---|');
    for (const v of vulns) {
      const fix = fixFor(data, v);
      out.push(`| ${v.severity} | \`${v.packageName}\` | ${v.installedVersions.join(', ')} | ${v.url ? `[${v.id}](${v.url})` : v.id} | ${fix ? `${fix.toVersion} (${fix.bump})` : '–'} |`);
    }
  } else out.push('None 🎉');
  if (data.plan?.unfixable.length) {
    out.push('', '## No automatic fix', ...data.plan.unfixable.map((u) => `- \`${u.packageName}\`: ${u.reason}`));
  }
  if (data.scan.ignored.length) {
    out.push('', '## Ignored (accepted risk)', ...data.scan.ignored.map((i) => `- ${i.vulnerability.id} (\`${i.vulnerability.packageName}\`): ${i.reason}`));
  }
  return out.join('\n') + '\n';
}

// ---------------------------------------------------------------- SARIF 2.1.0 (GitHub code scanning, Azure DevOps, GitLab)

const LEVEL: Record<Severity, string> = { critical: 'error', high: 'error', moderate: 'warning', low: 'note', info: 'note' };
const SCORE: Record<Severity, string> = { critical: '9.5', high: '8.0', moderate: '5.5', low: '3.0', info: '0.5' };

export function toSarif(data: ReportData) {
  const vulns = data.scan.vulnerabilities;
  const rules = new Map<string, any>();
  for (const v of vulns) {
    if (rules.has(v.id)) continue;
    rules.set(v.id, {
      id: v.id,
      name: v.id,
      shortDescription: { text: v.title },
      helpUri: v.url,
      defaultConfiguration: { level: LEVEL[v.severity] },
      properties: { tags: ['security', 'dependency', ...v.cwe], 'security-severity': v.cvssScore ? String(v.cvssScore) : SCORE[v.severity] },
    });
  }
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: { driver: { name: 'V-Patch', version: VERSION, informationUri: 'https://github.com/your-org/v-patch', rules: [...rules.values()] } },
        results: vulns.map((v) => {
          const fix = fixFor(data, v);
          return {
            ruleId: v.id,
            level: LEVEL[v.severity],
            message: { text: `${v.packageName}@${v.installedVersions.join(', ')} is vulnerable (${v.vulnerableRange}): ${v.title}.${fix ? ` Fix: upgrade to ${fix.toVersion}.` : ''}` },
            locations: [{ physicalLocation: { artifactLocation: { uri: 'package-lock.json' }, region: { startLine: 1 } } }],
            partialFingerprints: { 'vpatch/v1': `${v.id}:${v.packageName}` },
          };
        }),
      },
    ],
  };
}
