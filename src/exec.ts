import { execFile, exec } from 'node:child_process';
import { VPatchError } from './errors.js';

export interface ExecOptions {
  cwd: string;
  timeoutMs?: number;
  env?: NodeJS.ProcessEnv;
}
export interface ExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  timedOut: boolean;
}

/** Abstraction over process execution so everything above it is unit-testable. */
export interface Executor {
  /** Run a binary with an argument vector (no shell interpretation of args). */
  run(cmd: string, args: string[], opts: ExecOptions): Promise<ExecResult>;
  /** Run a trusted, user-configured command line through the shell. */
  runShell(commandLine: string, opts: ExecOptions): Promise<ExecResult>;
}

const MAX_BUFFER = 128 * 1024 * 1024;
const isWin = process.platform === 'win32';

const toResult = (err: any, stdout: string, stderr: string): ExecResult => ({
  stdout: String(stdout ?? ''),
  stderr: String(stderr ?? ''),
  exitCode: err ? (typeof err.code === 'number' ? err.code : 1) : 0,
  timedOut: Boolean(err?.killed && err?.signal),
});

export class NodeExecutor implements Executor {
  run(cmd: string, args: string[], opts: ExecOptions): Promise<ExecResult> {
    // On Windows npm is a .cmd shim that needs a shell; args are validated by callers
    // (see assertSafePackageName / assertSafeVersion) before they reach this point.
    return new Promise((resolve) => {
      execFile(
        cmd,
        args,
        {
          cwd: opts.cwd,
          timeout: opts.timeoutMs,
          maxBuffer: MAX_BUFFER,
          env: { ...process.env, ...opts.env },
          shell: isWin,
        },
        (err, stdout, stderr) => resolve(toResult(err, stdout, stderr)),
      );
    });
  }

  runShell(commandLine: string, opts: ExecOptions): Promise<ExecResult> {
    return new Promise((resolve) => {
      exec(
        commandLine,
        {
          cwd: opts.cwd,
          timeout: opts.timeoutMs,
          maxBuffer: MAX_BUFFER,
          env: { ...process.env, CI: 'true', ...opts.env },
        },
        (err, stdout, stderr) => resolve(toResult(err, stdout, stderr)),
      );
    });
  }
}

const NAME_RE = /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/;
const VERSION_RE = /^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$/;

/** Advisory feeds are untrusted input; never let them smuggle shell metacharacters. */
export function assertSafePackageName(name: string): void {
  if (!NAME_RE.test(name)) throw new VPatchError('UNSAFE_ARGUMENT', `Refusing unsafe package name: ${JSON.stringify(name)}`);
}
export function assertSafeVersion(version: string): void {
  if (!VERSION_RE.test(version)) throw new VPatchError('UNSAFE_ARGUMENT', `Refusing unsafe version: ${JSON.stringify(version)}`);
}

export const tail = (s: string, lines = 25): string => s.trim().split('\n').slice(-lines).join('\n');
