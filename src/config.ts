import { z } from 'zod';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { SEVERITIES } from './types.js';
import { VPatchError } from './errors.js';

const severity = z.enum(SEVERITIES);

export const ConfigSchema = z.object({
  provider: z.enum(['npm-audit', 'osv']).default('npm-audit'),
  /** Vulnerabilities below this severity are not reported or fixed. */
  severityThreshold: severity.default('low'),
  /** `scan` exits non-zero when an unresolved vulnerability at/above this severity exists. */
  failOn: severity.default('high'),
  includeDev: z.boolean().default(true),
  policy: z
    .object({
      /** Largest bump that `--all-safe` may apply without explicit selection. */
      autoApplyMaxBump: z.enum(['patch', 'minor', 'major']).default('minor'),
      /** minimal: lowest patched version. latest-in-major: newest patched version in the same major. */
      versionStrategy: z.enum(['minimal', 'latest-in-major']).default('minimal'),
      /** Ignore versions published less than N days ago (supply-chain protection). */
      minReleaseAgeDays: z.number().int().min(0).default(0),
      /** Blast-radius guard: max number of lockfile entries a run may change. */
      maxChangedPackages: z.number().int().min(1).default(40),
    })
    .default({
      autoApplyMaxBump: 'minor',
      versionStrategy: 'minimal',
      minReleaseAgeDays: 0,
      maxChangedPackages: 40,
    }),
  ignore: z
    .array(
      z.object({
        id: z.string(),
        reason: z.string().min(1, 'an ignore entry needs a reason'),
        /** ISO date; after this day the ignore no longer applies. */
        expires: z.string().optional(),
      }),
    )
    .default([]),
  verify: z
    .object({
      /** Verify the project passes BEFORE patching, so breakage can be attributed correctly. */
      baseline: z.boolean().default(true),
      runBuild: z.boolean().default(true),
      runTests: z.boolean().default(true),
      /** Extra smoke / contract-test commands, run through the shell. */
      commands: z.array(z.string()).default([]),
      /** Re-run the scanner and confirm the fix worked and introduced nothing new. */
      rescan: z.boolean().default(true),
      timeoutSeconds: z.number().int().min(10).default(900),
    })
    .default({ baseline: true, runBuild: true, runTests: true, commands: [], rescan: true, timeoutSeconds: 900 }),
  apply: z
    .object({
      /** isolated: verify after every fix, roll back only the bad one. batch: apply all, verify once. */
      mode: z.enum(['isolated', 'batch']).default('isolated'),
      /** Pass --ignore-scripts to npm installs. Recommended for hardened pipelines. */
      ignoreScripts: z.boolean().default(false),
      snapshotDir: z.string().default('.vpatch'),
    })
    .default({ mode: 'isolated', ignoreScripts: false, snapshotDir: '.vpatch' }),
});

export type VPatchConfig = z.infer<typeof ConfigSchema>;
export type VPatchConfigInput = z.input<typeof ConfigSchema>;

export function parseConfig(input: unknown): VPatchConfig {
  const parsed = ConfigSchema.safeParse(input ?? {});
  if (!parsed.success) {
    const msg = parsed.error.issues.map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`).join('; ');
    throw new VPatchError('CONFIG_INVALID', `Invalid V-Patch configuration: ${msg}`);
  }
  return parsed.data;
}

export const CONFIG_FILENAME = 'vpatch.config.json';

export async function loadConfig(projectDir: string, explicitPath?: string): Promise<VPatchConfig> {
  const file = explicitPath ? path.resolve(explicitPath) : path.join(projectDir, CONFIG_FILENAME);
  try {
    return parseConfig(JSON.parse(await readFile(file, 'utf8')));
  } catch (err: any) {
    if (err?.code === 'ENOENT' && !explicitPath) return parseConfig({});
    if (err instanceof VPatchError) throw err;
    throw new VPatchError('CONFIG_INVALID', `Cannot read ${file}: ${err.message}`, { cause: err });
  }
}
