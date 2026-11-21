export type ErrorCode =
  | 'CONFIG_INVALID'
  | 'UNSUPPORTED_PROJECT'
  | 'SCAN_FAILED'
  | 'REGISTRY_FAILED'
  | 'BASELINE_FAILED'
  | 'APPLY_FAILED'
  | 'ROLLBACK_FAILED'
  | 'UNSAFE_ARGUMENT'
  | 'NO_SNAPSHOT';

export class VPatchError extends Error {
  constructor(
    public readonly code: ErrorCode,
    message: string,
    options?: { cause?: unknown },
  ) {
    super(message, options);
    this.name = 'VPatchError';
  }
}

export const ExitCode = {
  Ok: 0,
  VulnerabilitiesFound: 1,
  Error: 2,
  FixIncomplete: 3,
} as const;
