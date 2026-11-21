import { readFile } from 'node:fs/promises';
import path from 'node:path';
import semver from 'semver';
import { VPatchError } from './errors.js';
import { bumpBetween } from './project.js';
import type { LockfileChange } from './types.js';

export interface LockEntry {
  name: string;
  version: string;
  dev: boolean;
  /** Dependency ranges this package declares (used to judge override risk). */
  requires: Record<string, string>;
}
export type Lock = Map<string, LockEntry>; // key: node_modules path

export const LOCKFILE = 'package-lock.json';

export const nameFromPath = (p: string): string => {
  const idx = p.lastIndexOf('node_modules/');
  return idx === -1 ? p : p.slice(idx + 'node_modules/'.length);
};

export function parseLockfile(text: string): Lock {
  const json = JSON.parse(text);
  if (!json.packages) {
    throw new VPatchError(
      'UNSUPPORTED_PROJECT',
      'package-lock.json uses lockfileVersion 1 (npm 6). Run `npm install --package-lock-only` with npm 7+ to upgrade it.',
    );
  }
  const lock: Lock = new Map();
  for (const [p, info] of Object.entries<any>(json.packages)) {
    if (p === '' || !info.version || info.link) continue;
    lock.set(p, {
      name: info.name ?? nameFromPath(p),
      version: info.version,
      dev: Boolean(info.dev),
      requires: { ...(info.dependencies ?? {}), ...(info.optionalDependencies ?? {}) },
    });
  }
  return lock;
}

export async function readLockfile(projectDir: string): Promise<Lock> {
  try {
    return parseLockfile(await readFile(path.join(projectDir, LOCKFILE), 'utf8'));
  } catch (err: any) {
    if (err instanceof VPatchError) throw err;
    throw new VPatchError('UNSUPPORTED_PROJECT', `Cannot read ${LOCKFILE} in ${projectDir}: a lockfile is required.`, { cause: err });
  }
}

export const installedVersions = (lock: Lock, name: string): string[] =>
  [...new Set([...lock.values()].filter((e) => e.name === name).map((e) => e.version))];

/** Ranges that other installed packages declare for `name`. */
export function dependentRanges(lock: Lock, name: string): { dependent: string; range: string }[] {
  const out: { dependent: string; range: string }[] = [];
  for (const e of lock.values()) {
    const r = e.requires[name];
    if (r) out.push({ dependent: e.name, range: r });
  }
  return out;
}

export function diffLockfiles(before: Lock, after: Lock): LockfileChange[] {
  const changes: LockfileChange[] = [];
  for (const [p, a] of after) {
    const b = before.get(p);
    if (!b) changes.push({ name: a.name, path: p, type: 'added', to: a.version });
    else if (b.version !== a.version) {
      changes.push({
        name: a.name,
        path: p,
        type: 'changed',
        from: b.version,
        to: a.version,
        bump: semver.valid(b.version) && semver.valid(a.version) ? bumpBetween(b.version, a.version) : undefined,
      });
    }
  }
  for (const [p, b] of before) if (!after.has(p)) changes.push({ name: b.name, path: p, type: 'removed', from: b.version });
  return changes.sort((x, y) => x.path.localeCompare(y.path));
}
