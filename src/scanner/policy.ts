import type { VPatchConfig } from '../config.js';
import { severityRank, type IgnoredVulnerability, type Vulnerability } from '../types.js';

export function applyPolicy(
  vulns: Vulnerability[],
  config: Pick<VPatchConfig, 'severityThreshold' | 'ignore'>,
  now = new Date(),
): { kept: Vulnerability[]; ignored: IgnoredVulnerability[] } {
  const kept: Vulnerability[] = [];
  const ignored: IgnoredVulnerability[] = [];
  const min = severityRank(config.severityThreshold);

  for (const v of vulns) {
    if (severityRank(v.severity) < min) continue;
    const rule = config.ignore.find((r) => r.id.toLowerCase() === v.id.toLowerCase());
    // An expired waiver stops applying, so accepted risk cannot rot silently.
    const active = rule && (!rule.expires || new Date(rule.expires).getTime() >= now.getTime());
    if (rule && active) ignored.push({ vulnerability: v, reason: rule.reason });
    else kept.push(v);
  }
  return { kept, ignored };
}
