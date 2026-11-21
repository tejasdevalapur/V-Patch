export const SEVERITIES = ['info', 'low', 'moderate', 'high', 'critical'] as const;
export type Severity = (typeof SEVERITIES)[number];
export const severityRank = (s: Severity): number => SEVERITIES.indexOf(s);
export const maxSeverity = (list: Severity[]): Severity =>
  list.reduce<Severity>((a, b) => (severityRank(b) > severityRank(a) ? b : a), 'info');

export interface Vulnerability {
  /** Stable advisory id (GHSA-xxxx preferred, else provider specific). */
  id: string;
  packageName: string;
  /** Installed versions that fall inside `vulnerableRange`. */
  installedVersions: string[];
  severity: Severity;
  title: string;
  url?: string;
  cwe: string[];
  cvssScore?: number;
  vulnerableRange: string;
  isDirect: boolean;
  /** node_modules paths where the vulnerable copy lives. */
  paths: string[];
  source: string;
}

export interface IgnoredVulnerability {
  vulnerability: Vulnerability;
  reason: string;
}

export interface ScanResult {
  provider: string;
  scannedAt: string;
  projectDir: string;
  vulnerabilities: Vulnerability[];
  ignored: IgnoredVulnerability[];
}

export type BumpType = 'patch' | 'minor' | 'major';
export const BUMP_ORDER: BumpType[] = ['patch', 'minor', 'major'];
export type RiskLevel = 'low' | 'medium' | 'high';
export type FixAction = 'upgrade-direct' | 'override-transitive';

export interface FixCandidate {
  /** Selection id, e.g. `lodash@4.17.21`. */
  id: string;
  action: FixAction;
  packageName: string;
  fromVersion: string;
  toVersion: string;
  declaredRange?: string;
  /** Key written to package.json "overrides" for transitive fixes. */
  overrideKey?: string;
  bump: BumpType;
  risk: RiskLevel;
  severity: Severity;
  resolves: string[];
  /** True when policy allows this fix to be applied without explicit selection. */
  autoApply: boolean;
  notes: string[];
}

export interface UnfixableEntry {
  packageName: string;
  vulnerabilityIds: string[];
  reason: string;
}

export interface FixPlan {
  candidates: FixCandidate[];
  unfixable: UnfixableEntry[];
}

export type StepStatus = 'passed' | 'failed' | 'skipped';
export interface VerificationStep {
  name: string;
  status: StepStatus;
  durationMs: number;
  detail?: string;
}
export interface VerificationReport {
  passed: boolean;
  steps: VerificationStep[];
}

export interface LockfileChange {
  name: string;
  path: string;
  type: 'added' | 'removed' | 'changed';
  from?: string;
  to?: string;
  bump?: BumpType;
}

export type OutcomeStatus = 'applied' | 'rolled-back' | 'dry-run';
export interface FixOutcome {
  candidate: FixCandidate;
  status: OutcomeStatus;
  reason?: string;
  verification?: VerificationReport;
  durationMs: number;
}

export interface ApplyResult {
  snapshotId: string;
  mode: 'isolated' | 'batch';
  outcomes: FixOutcome[];
  changes: LockfileChange[];
  remaining: Vulnerability[];
  baseline?: VerificationReport;
}

export interface ReportData {
  scan: ScanResult;
  plan?: FixPlan;
  apply?: ApplyResult;
}
