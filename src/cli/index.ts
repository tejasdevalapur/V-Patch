#!/usr/bin/env node
import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import { Command, Option } from 'commander';
import { CONFIG_FILENAME } from '../config.js';
import { ExitCode, VPatchError } from '../errors.js';
import { ConsoleLogger } from '../logger.js';
import { render, VERSION, type ReportFormat } from '../reporters/index.js';
import { SEVERITIES, type FixCandidate, type ReportData, type Severity } from '../types.js';
import { gate, VPatch } from '../vpatch.js';
import { selectInteractively } from './select.js';

const FORMATS: ReportFormat[] = ['table', 'json', 'markdown', 'sarif'];

interface Common {
  cwd?: string;
  config?: string;
  provider?: 'npm-audit' | 'osv';
  format: ReportFormat;
  output?: string;
  verbose?: boolean;
  quiet?: boolean;
}

const program = new Command('vpatch')
  .description('Scan dependencies for vulnerabilities and apply verified, reversible fixes.')
  .version(VERSION)
  .option('-C, --cwd <dir>', 'project directory', process.cwd())
  .option('-c, --config <file>', `config file (default: ./${CONFIG_FILENAME})`)
  .addOption(new Option('-p, --provider <name>', 'vulnerability source').choices(['npm-audit', 'osv']))
  .addOption(new Option('-f, --format <format>', 'report format').choices(FORMATS).default('table'))
  .option('-o, --output <file>', 'write the report to a file instead of stdout')
  .option('-v, --verbose', 'debug logging')
  .option('-q, --quiet', 'only print errors');

async function boot(opts: Common): Promise<VPatch> {
  const logger = new ConsoleLogger(opts.quiet ? 'error' : opts.verbose ? 'debug' : 'info');
  const v = await VPatch.create({ projectDir: opts.cwd, configPath: opts.config, logger });
  if (opts.provider) (v.config as { provider: string }).provider = opts.provider; // CLI flag wins over file
  return v;
}

async function emit(opts: Common, data: ReportData): Promise<void> {
  const text = render(opts.format, data);
  if (opts.output) await writeFile(path.resolve(opts.output), text);
  else process.stdout.write(text);
}

program
  .command('scan')
  .description('List vulnerabilities. Exits 1 if any are at or above --fail-on (CI gate).')
  .addOption(new Option('--fail-on <severity>', 'gate threshold (default: config failOn)').choices([...SEVERITIES]))
  .action(async (local: { failOn?: Severity }) => {
    const opts = program.opts<Common>();
    const v = await boot(opts);
    const scan = await v.scan();
    await emit(opts, { scan });
    const failing = gate(scan, local.failOn ?? v.config.failOn);
    process.exitCode = failing.length ? ExitCode.VulnerabilitiesFound : ExitCode.Ok;
  });

program
  .command('plan')
  .description('Show the fix V-Patch would apply for each vulnerability, without changing anything.')
  .action(async () => {
    const opts = program.opts<Common>();
    const v = await boot(opts);
    const scan = await v.scan();
    const plan = await v.plan(scan);
    await emit(opts, { scan, plan });
  });

program
  .command('fix')
  .description('Apply fixes with snapshot → verify → rollback protection.')
  .option('-s, --select <ids>', 'comma separated fix ids or package names, e.g. lodash@4.17.21,minimist')
  .option('--all-safe', 'apply every fix that policy marks safe (no major bumps by default)')
  .option('--dry-run', 'show what would be applied and stop')
  .addOption(new Option('--mode <mode>', 'verify after every fix (isolated) or once at the end (batch)').choices(['isolated', 'batch']))
  .option('--skip-baseline', 'do not require the project to pass before patching')
  .action(async (local: { select?: string; allSafe?: boolean; dryRun?: boolean; mode?: 'isolated' | 'batch'; skipBaseline?: boolean }) => {
    const opts = program.opts<Common>();
    const v = await boot(opts);
    const scan = await v.scan();
    if (!scan.vulnerabilities.length) {
      await emit(opts, { scan });
      return;
    }
    const plan = await v.plan(scan);

    let chosen: FixCandidate[];
    if (local.select || local.allSafe) {
      chosen = v.select(plan, { ids: local.select?.split(',').map((s) => s.trim()).filter(Boolean), allSafe: local.allSafe });
    } else if (process.stdin.isTTY && process.stdout.isTTY && !local.dryRun) {
      process.stderr.write(render('table', { scan, plan }));
      chosen = await selectInteractively(plan);
    } else if (local.dryRun) {
      chosen = plan.candidates;
    } else {
      throw new VPatchError('CONFIG_INVALID', 'Non-interactive session: pass --all-safe or --select <ids> (or use --dry-run to preview).');
    }

    const apply = await v.apply(chosen, scan, { dryRun: local.dryRun, mode: local.mode, skipBaseline: local.skipBaseline });
    await emit(opts, { scan, plan, apply });
    process.exitCode = apply.outcomes.some((o) => o.status === 'rolled-back') ? ExitCode.FixIncomplete : ExitCode.Ok;
  });

program
  .command('rollback [snapshot]')
  .description('Restore package.json and the lockfile from a snapshot (default: latest) and reinstall.')
  .action(async (snapshot?: string) => {
    const v = await boot(program.opts<Common>());
    const id = await v.rollback(snapshot);
    console.error(`Restored snapshot ${id}`);
  });

program
  .command('init')
  .description(`Write a starter ${CONFIG_FILENAME}.`)
  .action(async () => {
    const file = path.join(path.resolve(program.opts<Common>().cwd ?? '.'), CONFIG_FILENAME);
    const starter = {
      provider: 'npm-audit',
      severityThreshold: 'low',
      failOn: 'high',
      policy: { autoApplyMaxBump: 'minor', versionStrategy: 'minimal', minReleaseAgeDays: 3, maxChangedPackages: 40 },
      ignore: [],
      verify: { baseline: true, runBuild: true, runTests: true, commands: [], rescan: true },
      apply: { mode: 'isolated', ignoreScripts: false },
    };
    await writeFile(file, JSON.stringify(starter, null, 2) + '\n', { flag: 'wx' }).catch((e) => {
      throw new VPatchError('CONFIG_INVALID', e.code === 'EEXIST' ? `${file} already exists` : e.message);
    });
    console.error(`Created ${file}`);
  });

program.parseAsync().catch((err: unknown) => {
  if (err instanceof VPatchError) console.error(`\n✖ [${err.code}] ${err.message}`);
  else if ((err as Error)?.name === 'ExitPromptError') console.error('\nCancelled – nothing was changed.');
  else console.error(err);
  process.exitCode = ExitCode.Error;
});
