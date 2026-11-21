import checkbox from '@inquirer/checkbox';
import pc from 'picocolors';
import type { FixCandidate, FixPlan } from '../types.js';

const riskColor = { low: pc.green, medium: pc.yellow, high: pc.red } as const;

export const describe = (c: FixCandidate): string =>
  `${c.severity.toUpperCase().padEnd(8)} ${c.packageName} ${c.fromVersion} → ${c.toVersion}  ` +
  `${riskColor[c.risk](`${c.bump}/${c.risk} risk`)}  fixes ${c.resolves.length} advisor${c.resolves.length === 1 ? 'y' : 'ies'}` +
  (c.action === 'override-transitive' ? pc.dim('  [transitive → overrides]') : '');

/** Let a human pick which fixes to apply. Low-risk fixes are pre-selected; major bumps never are. */
export async function selectInteractively(plan: FixPlan): Promise<FixCandidate[]> {
  if (!plan.candidates.length) return [];
  const chosen = await checkbox<string>({
    message: 'Select the fixes to apply (space = toggle, a = all, enter = confirm)',
    pageSize: 15,
    loop: false,
    choices: plan.candidates.map((c) => ({
      name: describe(c),
      value: c.id,
      checked: c.autoApply,
      description: c.notes.join('\n') || undefined,
    })),
  });
  return plan.candidates.filter((c) => chosen.includes(c.id));
}
