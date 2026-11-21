import pc from 'picocolors';

export type LogLevel = 'silent' | 'error' | 'warn' | 'info' | 'debug';
const ORDER: LogLevel[] = ['silent', 'error', 'warn', 'info', 'debug'];

export interface Logger {
  error(msg: string): void;
  warn(msg: string): void;
  info(msg: string): void;
  debug(msg: string): void;
}

/** Logs to stderr so stdout stays clean for machine-readable output (json/sarif). */
export class ConsoleLogger implements Logger {
  constructor(private level: LogLevel = 'info') {}
  private enabled(l: LogLevel) {
    return ORDER.indexOf(l) <= ORDER.indexOf(this.level);
  }
  error(m: string) { if (this.enabled('error')) console.error(pc.red(`✖ ${m}`)); }
  warn(m: string) { if (this.enabled('warn')) console.error(pc.yellow(`! ${m}`)); }
  info(m: string) { if (this.enabled('info')) console.error(pc.cyan('›') + ` ${m}`); }
  debug(m: string) { if (this.enabled('debug')) console.error(pc.dim(`  ${m}`)); }
}

export const silentLogger: Logger = { error() {}, warn() {}, info() {}, debug() {} };
