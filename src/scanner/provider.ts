import type { PackageManager } from '../pm/adapter.js';
import type { Logger } from '../logger.js';
import type { Vulnerability } from '../types.js';

export interface ScanContext {
  projectDir: string;
  includeDev: boolean;
  pm: PackageManager;
  logger: Logger;
}

/** A source of vulnerability intelligence. Implement this to plug in Snyk, internal feeds, etc. */
export interface AuditProvider {
  readonly name: string;
  scan(ctx: ScanContext): Promise<Vulnerability[]>;
}
