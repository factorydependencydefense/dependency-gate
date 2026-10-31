// Generated file. Do not edit here.
// Source: droid-dependency-defense tools/gate.ts at 53df8fa0f1b1b90ea998ba21ca2b75429955e801
// Sync with: npx tsx tools/publish-gate.ts <path-to-dependency-gate-clone>
// There is one gate implementation (SPEC Decision 1). This copy exists only because
// pull_request_target runs the workflow from the gate repo, which needs the code locally.
// Self-contained on purpose: this file is published verbatim to the dependency-gate repo
// (SPEC Decision 15), so it must not import anything from this kit.
import { spawn } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const DEFAULT_ALLOWED_HOSTS = [
  'registry.npmjs.org',
  'npm.pkg.github.com',
  'localhost:4873',
  '127.0.0.1:4873',
];
const DEFAULT_MAX_AGE_HOURS = 168;
const DEFAULT_INSTALL_SCRIPT_ALLOWLIST = ['esbuild'];
const UNSIGNED_SCOPES = ['@factorydependencydefense'];

export type Severity = 'block' | 'review' | 'info';

export interface Finding {
  rule:
    | 'new_package'
    | 'version_change'
    | 'install_script'
    | 'native_build_file'
    | 'unexpected_registry'
    | 'recent_publish'
    | 'integrity_mismatch'
    | 'missing_integrity'
    | 'registry_unreachable'
    | 'publish_dates_skipped'
    | 'audit_signatures'
    | 'signatures_unavailable';
  severity: Severity;
  package: string;
  version?: string;
  message: string;
}

export interface GateReport {
  passed: boolean;
  checked_at: string;
  lockfile: string;
  registry_reachable: boolean;
  counts: { new: number; changed: number; block: number; review: number; info: number };
  findings: Finding[];
}

interface CommandResult {
  code: number;
  stdout: string;
  stderr: string;
}

function runCommand(
  command: string,
  args: string[],
  options: { cwd?: string; timeoutMs?: number } = {},
): Promise<CommandResult> {
  return new Promise((resolvePromise) => {
    const child = spawn(command, args, { cwd: options.cwd, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    const timer = options.timeoutMs
      ? setTimeout(() => child.kill('SIGKILL'), options.timeoutMs)
      : undefined;
    child.stdout.on('data', (chunk: Buffer) => (stdout += chunk.toString()));
    child.stderr.on('data', (chunk: Buffer) => (stderr += chunk.toString()));
    child.on('error', (error: Error) => {
      if (timer) clearTimeout(timer);
      resolvePromise({ code: 127, stdout, stderr: error.message });
    });
    child.on('close', (code) => {
      if (timer) clearTimeout(timer);
      resolvePromise({ code: code ?? 1, stdout, stderr });
    });
  });
}

export interface LockEntry {
  path: string;
  name: string;
  version: string;
  resolved?: string;
  integrity?: string;
  hasInstallScript?: boolean;
  gypfile?: boolean;
  link?: boolean;
  dev?: boolean;
}

export interface Lockfile {
  packages: Record<string, LockEntry>;
}

export function packageNameFromPath(path: string): string {
  const index = path.lastIndexOf('node_modules/');
  return index === -1 ? path : path.slice(index + 'node_modules/'.length);
}

export function parseLockfile(contents: string): Lockfile {
  const raw = JSON.parse(contents) as {
    packages?: Record<string, Partial<LockEntry> & { version?: string }>;
    dependencies?: Record<string, { version?: string; resolved?: string; integrity?: string }>;
  };
  const packages: Record<string, LockEntry> = {};

  if (raw.packages) {
    for (const [path, entry] of Object.entries(raw.packages)) {
      if (path === '') continue;
      packages[path] = {
        path,
        name: entry.name ?? packageNameFromPath(path),
        version: entry.version ?? '',
        resolved: entry.resolved,
        integrity: entry.integrity,
        hasInstallScript: entry.hasInstallScript,
        gypfile: entry.gypfile,
        link: entry.link,
        dev: entry.dev,
      };
    }
    return { packages };
  }

  for (const [name, entry] of Object.entries(raw.dependencies ?? {})) {
    const path = `node_modules/${name}`;
    packages[path] = {
      path,
      name,
      version: entry.version ?? '',
      resolved: entry.resolved,
      integrity: entry.integrity,
    };
  }
  return { packages };
}

export function hostOf(resolvedUrl: string | undefined): string | null {
  if (!resolvedUrl) return null;
  try {
    const url = new URL(resolvedUrl);
    return url.port === '' ? url.hostname : `${url.hostname}:${url.port}`;
  } catch {
    return null;
  }
}

export interface JudgeOptions {
  allowedHosts?: string[];
  maxAgeHours?: number;
  repoPath?: string;
  publishTimes?: Map<string, string>;
  registryReachable?: boolean;
  publishDatesSkipped?: boolean;
  lockfileName?: string;
  installScriptAllowlist?: string[];
  extraFindings?: Finding[];
}

export function judgeLockfiles(base: Lockfile | null, head: Lockfile, options: JudgeOptions = {}): GateReport {
  const allowedHosts = options.allowedHosts ?? DEFAULT_ALLOWED_HOSTS;
  const maxAgeHours = options.maxAgeHours ?? DEFAULT_MAX_AGE_HOURS;
  const installScriptAllowlist = options.installScriptAllowlist ?? DEFAULT_INSTALL_SCRIPT_ALLOWLIST;
  const findings: Finding[] = [...(options.extraFindings ?? [])];
  let added = 0;
  let changed = 0;

  for (const [path, entry] of Object.entries(head.packages)) {
    if (entry.link) continue;
    const previous = base?.packages[path];
    const isNew = !previous;
    const isChanged = Boolean(previous && previous.version !== entry.version);
    const isRetagged = Boolean(
      previous &&
        previous.version === entry.version &&
        previous.integrity &&
        entry.integrity &&
        previous.integrity !== entry.integrity,
    );
    if (!isNew && !isChanged && !isRetagged) continue;
    if (isNew) added += 1;
    if (isChanged) changed += 1;

    const label = `${entry.name}@${entry.version}`;
    if (isRetagged) {
      findings.push({
        rule: 'integrity_mismatch',
        severity: 'block',
        package: entry.name,
        version: entry.version,
        message:
          `${label} keeps the same version but its integrity hash changed ` +
          `(${previous?.integrity} -> ${entry.integrity}). A published version is immutable, so this tarball is not ` +
          `what the base branch resolved.`,
      });
    } else if (isNew) {
      findings.push({
        rule: 'new_package',
        severity: 'review',
        package: entry.name,
        version: entry.version,
        message: `new package in the lockfile: ${label} (${path}). A new dependency is a new publisher to trust.`,
      });
    } else {
      findings.push({
        rule: 'version_change',
        severity: 'info',
        package: entry.name,
        version: entry.version,
        message: `version change: ${entry.name} ${previous?.version} -> ${entry.version}`,
      });
    }

    if (entry.hasInstallScript) {
      const allowed = installScriptAllowlist.includes(entry.name);
      findings.push({
        rule: 'install_script',
        severity: allowed ? 'review' : 'block',
        package: entry.name,
        version: entry.version,
        message: allowed
          ? `${label} runs an install script and is on the reviewed allowlist (${installScriptAllowlist.join(', ')}). ` +
            `The version changed, so the script changed too: check it.`
          : `${label} runs an install script. Install scripts execute on every \`npm install\`, so a poisoned ` +
            `release needs no application code to run. Remove the dependency, pin to a version without the script, ` +
            `or add a reviewed exception with \`ignore-scripts=true\` in place.`,
      });
    }

    const nativeFile = options.repoPath ? nativeBuildFile(options.repoPath, path) : null;
    if (entry.gypfile || nativeFile) {
      findings.push({
        rule: 'native_build_file',
        severity: 'block',
        package: entry.name,
        version: entry.version,
        message:
          `${label} ships a native build file (${nativeFile ?? 'gypfile flag in the lockfile'}). Native builds compile ` +
          `and run code at install time. Prefer a pure-JavaScript alternative or a reviewed exception.`,
      });
    }

    const host = hostOf(entry.resolved);
    if (host && !allowedHosts.includes(host)) {
      findings.push({
        rule: 'unexpected_registry',
        severity: 'block',
        package: entry.name,
        version: entry.version,
        message: `${label} resolves to ${host}, which is not in the allowed registry list (${allowedHosts.join(', ')}).`,
      });
    }

    if (!entry.integrity && entry.resolved) {
      findings.push({
        rule: 'missing_integrity',
        severity: 'block',
        package: entry.name,
        version: entry.version,
        message: `${label} has no integrity hash, so the download cannot be verified against what was reviewed.`,
      });
    }

    const published = options.publishTimes?.get(label);
    if (published) {
      const ageHours = (Date.now() - Date.parse(published)) / 3_600_000;
      if (ageHours < maxAgeHours) {
        findings.push({
          rule: 'recent_publish',
          severity: 'review',
          package: entry.name,
          version: entry.version,
          message:
            `${label} was published ${ageHours.toFixed(1)} hours ago, inside the ${maxAgeHours}h window where ` +
            `poisoned releases are usually still live. This does not fail the check: a security fix is often hours old. ` +
            `A code owner reviews it (Decision 12).`,
        });
      }
    }
  }

  if (options.publishDatesSkipped) {
    findings.push({
      rule: 'publish_dates_skipped',
      severity: 'info',
      package: '-',
      message: 'publish dates were not checked: --skip-publish-dates was set.',
    });
  } else if (options.registryReachable === false) {
    findings.push({
      rule: 'registry_unreachable',
      severity: 'info',
      package: '-',
      message: 'publish dates were not checked: the registry could not be reached.',
    });
  }

  const counts = {
    new: added,
    changed,
    block: findings.filter((finding) => finding.severity === 'block').length,
    review: findings.filter((finding) => finding.severity === 'review').length,
    info: findings.filter((finding) => finding.severity === 'info').length,
  };

  return {
    passed: counts.block === 0,
    checked_at: new Date().toISOString(),
    lockfile: options.lockfileName ?? 'package-lock.json',
    registry_reachable: options.registryReachable ?? false,
    counts,
    findings,
  };
}

function nativeBuildFile(repoPath: string, packagePath: string): string | null {
  for (const candidate of ['binding.gyp', 'prebuild.js']) {
    const full = join(repoPath, packagePath, candidate);
    if (existsSync(full)) return `${packagePath}/${candidate}`;
  }
  return null;
}

export function renderGateReport(report: GateReport): string {
  const order: Severity[] = ['block', 'review', 'info'];
  const lines = [
    `Dependency gate: ${report.passed ? 'PASS' : 'FAIL'} (${report.lockfile})`,
    `New packages: ${report.counts.new}, version changes: ${report.counts.changed}, ` +
      `blocking: ${report.counts.block}, needs review: ${report.counts.review}`,
  ];
  if (report.counts.review > 0 && report.counts.block === 0) {
    lines.push('Review findings do not fail this check. A code owner decides (Decision 12).');
  }
  if (!report.registry_reachable && !report.findings.some((f) => f.rule === 'publish_dates_skipped')) {
    lines.push('Registry unreachable: publish dates were not checked.');
  }
  for (const severity of order) {
    const matching = report.findings.filter((finding) => finding.severity === severity);
    if (matching.length === 0) continue;
    lines.push('');
    lines.push(`${severity.toUpperCase()}:`);
    for (const finding of matching) lines.push(`- [${finding.rule}] ${finding.message}`);
  }
  return lines.join('\n');
}

export function parseAuditSignatures(stdout: string): Finding[] {
  const findings: Finding[] = [];
  let parsed: {
    invalid?: { name?: string; version?: string; registry?: string }[];
    missing?: { name?: string; version?: string }[];
  };
  try {
    parsed = JSON.parse(stdout) as typeof parsed;
  } catch {
    return findings;
  }
  for (const entry of parsed.invalid ?? []) {
    findings.push({
      rule: 'audit_signatures',
      severity: 'block',
      package: entry.name ?? '(unknown)',
      version: entry.version,
      message:
        `${entry.name}@${entry.version} has an invalid registry signature. The tarball is not what the registry signed.`,
    });
  }
  for (const entry of parsed.missing ?? []) {
    if (UNSIGNED_SCOPES.some((scope) => (entry.name ?? '').startsWith(`${scope}/`))) continue;
    findings.push({
      rule: 'audit_signatures',
      severity: 'review',
      package: entry.name ?? '(unknown)',
      version: entry.version,
      message: `${entry.name}@${entry.version} has no registry signature to verify.`,
    });
  }
  return findings;
}

async function auditSignatures(repoPath: string): Promise<Finding[]> {
  const result = await runCommand('npm', ['audit', 'signatures', '--json'], {
    cwd: repoPath,
    timeoutMs: 60_000,
  });
  if (result.stdout.trim() === '') {
    return [
      {
        rule: 'signatures_unavailable',
        severity: 'info',
        package: '-',
        message: `npm audit signatures produced no output (exit ${result.code}). Signatures were not verified.`,
      },
    ];
  }
  const findings = parseAuditSignatures(result.stdout);
  findings.push({
    rule: 'signatures_unavailable',
    severity: 'info',
    package: '-',
    message:
      `GitHub Packages publishes no provenance signatures, so ${UNSIGNED_SCOPES.join(', ')} is excluded from the ` +
      `signature check rather than reported as verified (Decision 12).`,
  });
  return findings;
}

async function readLockfileFromGit(repoPath: string, ref: string, name: string): Promise<string | null> {
  const result = await runCommand('git', ['-C', repoPath, 'show', `${ref}:${name}`], { timeoutMs: 30_000 });
  return result.code === 0 ? result.stdout : null;
}

async function fetchPublishTimes(
  entries: LockEntry[],
  registry: string | undefined,
): Promise<{ times: Map<string, string>; reachable: boolean }> {
  const times = new Map<string, string>();
  const names = [...new Set(entries.map((entry) => entry.name))];
  if (names.length === 0) return { times, reachable: true };

  let reachable = true;
  for (const name of names) {
    const args = ['view', name, 'time', '--json'];
    if (registry) args.push('--registry', registry);
    const result = await runCommand('npm', args, { timeoutMs: 20_000 });
    if (result.code !== 0 || result.stdout.trim() === '') {
      reachable = false;
      break;
    }
    const parsed = JSON.parse(result.stdout) as Record<string, string>;
    for (const entry of entries.filter((candidate) => candidate.name === name)) {
      const published = parsed[entry.version];
      if (published) times.set(`${entry.name}@${entry.version}`, published);
    }
  }
  return { times, reachable };
}

export async function runGate(options: {
  repoPath: string;
  baseRef?: string;
  baseFile?: string;
  headFile?: string;
  lockfileName?: string;
  registry?: string;
  allowedHosts?: string[];
  maxAgeHours?: number;
  skipPublishDates?: boolean;
  skipSignatures?: boolean;
  installScriptAllowlist?: string[];
}): Promise<GateReport> {
  const repoPath = resolve(options.repoPath);
  const lockfileName = options.lockfileName ?? 'package-lock.json';
  const headPath = options.headFile ? resolve(options.headFile) : join(repoPath, lockfileName);
  if (!existsSync(headPath)) throw new Error(`no lockfile at ${headPath}`);
  const head = parseLockfile(readFileSync(headPath, 'utf8'));

  let base: Lockfile | null = null;
  if (options.baseFile) {
    base = existsSync(options.baseFile) ? parseLockfile(readFileSync(options.baseFile, 'utf8')) : null;
  } else {
    for (const ref of [options.baseRef, 'origin/main', 'origin/master', 'HEAD'].filter(Boolean) as string[]) {
      const contents = await readLockfileFromGit(repoPath, ref, lockfileName);
      if (contents) {
        base = parseLockfile(contents);
        break;
      }
    }
  }

  const candidates = Object.entries(head.packages)
    .filter(([path, entry]) => {
      const previous = base?.packages[path];
      return !previous || previous.version !== entry.version;
    })
    .map(([, entry]) => entry);

  const { times, reachable } = options.skipPublishDates
    ? { times: new Map<string, string>(), reachable: false }
    : await fetchPublishTimes(candidates, options.registry);

  const extraFindings =
    options.skipSignatures || !reachable || !existsSync(join(repoPath, 'node_modules'))
      ? []
      : await auditSignatures(repoPath);

  return judgeLockfiles(base, head, {
    repoPath,
    lockfileName,
    allowedHosts: options.allowedHosts,
    maxAgeHours: options.maxAgeHours,
    installScriptAllowlist: options.installScriptAllowlist,
    publishTimes: times,
    registryReachable: reachable,
    publishDatesSkipped: options.skipPublishDates === true,
    extraFindings,
  });
}

async function main(argv: string[]): Promise<number> {
  const positional: string[] = [];
  const flags: Record<string, string> = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i] as string;
    if (arg.startsWith('--')) {
      const key = arg.slice(2);
      if (key === 'json' || key === 'skip-publish-dates' || key === 'skip-signatures') flags[key] = 'true';
      else {
        i += 1;
        flags[key] = argv[i] ?? '';
      }
    } else positional.push(arg);
  }

  if (positional.length === 0) {
    console.error(
      'usage: tsx tools/gate.ts <repo-path> [--base-ref <ref>] [--base-file <path>] [--head-file <path>] ' +
        '[--lockfile <name>] [--registry <url>] [--allow-host <host,host>] [--max-age-hours <n>] ' +
        '[--allow-install-script <pkg,pkg>] [--skip-publish-dates] [--skip-signatures] [--json]',
    );
    return 2;
  }

  const report = await runGate({
    repoPath: positional[0] as string,
    baseRef: flags['base-ref'],
    baseFile: flags['base-file'],
    headFile: flags['head-file'],
    lockfileName: flags.lockfile,
    registry: flags.registry,
    allowedHosts: flags['allow-host'] ? flags['allow-host'].split(',') : undefined,
    maxAgeHours: flags['max-age-hours'] ? Number(flags['max-age-hours']) : undefined,
    installScriptAllowlist: flags['allow-install-script']
      ? flags['allow-install-script'].split(',')
      : undefined,
    skipPublishDates: flags['skip-publish-dates'] === 'true',
    skipSignatures: flags['skip-signatures'] === 'true',
  });

  console.log(flags.json === 'true' ? JSON.stringify(report, null, 2) : renderGateReport(report));
  return report.passed ? 0 : 1;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main(process.argv.slice(2))
    .then((code) => process.exit(code))
    .catch((error: unknown) => {
      console.error(error instanceof Error ? error.message : error);
      process.exit(2);
    });
}
