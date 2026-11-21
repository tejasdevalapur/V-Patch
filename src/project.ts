import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import semver from 'semver';
import { VPatchError } from './errors.js';
import type { BumpType } from './types.js';

export interface Manifest {
  raw: Record<string, any>;
  dependencies: Record<string, string>;
  devDependencies: Record<string, string>;
  optionalDependencies: Record<string, string>;
  scripts: Record<string, string>;
  overrides: Record<string, unknown>;
}

export interface RawManifestFile {
  text: string;
}

export async function readManifest(projectDir: string): Promise<Manifest> {
  const file = path.join(projectDir, 'package.json');
  let text: string;
  try {
    text = await readFile(file, 'utf8');
  } catch {
    throw new VPatchError('UNSUPPORTED_PROJECT', `No package.json found in ${projectDir}`);
  }
  const raw = JSON.parse(text);
  return {
    raw,
    dependencies: raw.dependencies ?? {},
    devDependencies: raw.devDependencies ?? {},
    optionalDependencies: raw.optionalDependencies ?? {},
    scripts: raw.scripts ?? {},
    overrides: raw.overrides ?? {},
  };
}

/** Write package.json back preserving indentation and trailing newline. */
export async function writeOverride(projectDir: string, key: string, version: string): Promise<void> {
  const file = path.join(projectDir, 'package.json');
  const text = await readFile(file, 'utf8');
  const indent = /^(\s+)"/m.exec(text)?.[1] ?? '  ';
  const raw = JSON.parse(text);
  raw.overrides ??= {};
  const existing = raw.overrides[key];
  if (existing && typeof existing === 'object') existing['.'] = version;
  else raw.overrides[key] = version;
  await writeFile(file, JSON.stringify(raw, null, indent) + (text.endsWith('\n') ? '\n' : ''));
}

export function declaredRangeOf(m: Manifest, name: string): string | undefined {
  return m.dependencies[name] ?? m.devDependencies[name] ?? m.optionalDependencies[name];
}

export const isDirectDependency = (m: Manifest, name: string): boolean => declaredRangeOf(m, name) !== undefined;

export function savePrefixOf(range: string | undefined): '^' | '~' | '' {
  if (!range) return '^';
  if (range.startsWith('~')) return '~';
  if (range.startsWith('^')) return '^';
  return '';
}

export function bumpBetween(from: string, to: string): BumpType {
  const diff = semver.diff(from, to);
  if (diff === 'major' || diff === 'premajor') return 'major';
  if (diff === 'minor' || diff === 'preminor') return 'minor';
  return 'patch';
}

/** Whether the project's scripts.test is real (npm init's default placeholder doesn't count). */
export const hasRealScript = (m: Manifest, name: string): boolean => {
  const s = m.scripts[name];
  return Boolean(s) && !/no test specified/.test(s as string);
};
