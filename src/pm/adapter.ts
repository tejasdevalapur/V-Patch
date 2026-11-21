import type { ExecResult } from '../exec.js';

export interface RegistryVersion {
  version: string;
  publishedAt?: string;
}
export interface RegistryReader {
  getVersions(name: string): Promise<RegistryVersion[]>;
}

/**
 * Everything V-Patch needs from a package manager. Only npm is implemented today;
 * adding pnpm / yarn means implementing this interface, nothing else changes.
 */
export interface PackageManager extends RegistryReader {
  readonly name: string;
  readonly lockfile: string;
  audit(opts: { includeDev: boolean }): Promise<string>;
  installExact(name: string, version: string, savePrefix: '^' | '~' | ''): Promise<void>;
  /** Re-resolve the tree after package.json changed (e.g. overrides). */
  install(): Promise<void>;
  /** Reproducible install from the lockfile; used after a rollback. */
  cleanInstall(): Promise<void>;
  runScript(name: string): Promise<ExecResult>;
  /** Dependency-tree problems (invalid / missing / extraneous). */
  listProblems(): Promise<string[]>;
}
