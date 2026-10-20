import { existsSync, mkdirSync, realpathSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join, relative, resolve } from "node:path";
import { inspect, iterateFindings, type CheckResult, type InspectOptions } from "./scanner/index.ts";

/** Matches the native DEFAULT_MAX_FINDINGS, applied after baseline subtraction. */
const defaultMaxFindings = 10_000;

export interface Baseline {
  readonly ref: string;
  /** Current findings that the baseline commit also has. */
  readonly hiddenCount: number;
}

/**
 * Check `paths` in the working tree and at `ref`, with the same rules, and keep only the findings
 * that `ref` does not have. A finding exists at `ref` when that commit has a finding of the same
 * rule, in the same repository-relative file, whose owner has identical source text. Repeated
 * identical owners are matched by count.
 */
export async function checkAgainstRef(
  ref: string,
  options: InspectOptions,
): Promise<{ result: CheckResult; baseline: Baseline }> {
  const root = realpathSync.native(git(["rev-parse", "--show-toplevel"], process.cwd()).trim());
  const commit = git(["rev-parse", "--verify", "--quiet", `${ref}^{commit}`], root,
    `baseline ref ${ref} is not a commit in this repository; a shallow clone may not contain it`).trim();
  // Subtraction needs every finding on both sides; the output limit applies afterwards.
  const complete = { ...options, maxFindings: 0xffffffff };
  const current = await inspect(complete);

  const scratch = await mkdtemp(join(tmpdir(), "badbox-baseline-"));
  const tree = join(scratch, "tree");
  // An empty hooks directory keeps the temporary checkout from running repository hooks.
  const hooks = join(scratch, "hooks");
  mkdirSync(hooks);
  let added = false;
  try {
    git(["-c", `core.hooksPath=${hooks}`, "worktree", "add", "--detach", "--quiet", tree, commit], root);
    added = true;
    const treeRoot = realpathSync.native(tree);
    const basePaths = options.paths
      .map((path) => join(treeRoot, repositoryPath(root, realpathSync.native(resolve(path)))))
      .filter((path) => existsSync(path));
    const base = basePaths.length ? await inspect({ ...complete, paths: basePaths }) : undefined;

    const known = new Map<string, number>();
    for (const key of base ? await findingKeys(base, treeRoot) : []) known.set(key, (known.get(key) ?? 0) + 1);
    const keys = await findingKeys(current, root);
    const limit = options.maxFindings ?? defaultMaxFindings;
    const kept: number[] = [];
    let newCount = 0;
    keys.forEach((key, index) => {
      const remaining = known.get(key) ?? 0;
      if (remaining > 0) {
        known.set(key, remaining - 1);
        return;
      }
      newCount += 1;
      if (kept.length < limit) kept.push(index);
    });

    const width = current.recordWidth;
    const findings = new Uint32Array(kept.length * width);
    kept.forEach((index, position) => {
      findings.set(current.findings.subarray(index * width, (index + 1) * width), position * width);
    });
    const baseDiagnostics = (base?.diagnostics ?? []).map((diagnostic) => ({
      file: join(root, repositoryPath(treeRoot, diagnostic.file)),
      message: `at ${ref}: ${diagnostic.message}`,
    }));
    return {
      result: {
        ...current,
        findingCount: newCount,
        findings,
        truncated: newCount > kept.length,
        diagnostics: [...current.diagnostics, ...baseDiagnostics],
      },
      baseline: { ref, hiddenCount: keys.length - newCount },
    };
  } finally {
    if (added) git(["worktree", "remove", "--force", tree], root);
    await rm(scratch, { recursive: true, force: true });
  }
}

async function findingKeys(result: CheckResult, root: string): Promise<string[]> {
  const sources = new Map<string, Uint8Array>();
  const decoder = new TextDecoder();
  const keys: string[] = [];
  for (const finding of iterateFindings(result)) {
    let source = sources.get(finding.file);
    if (!source) {
      source = new Uint8Array(await Bun.file(finding.file).arrayBuffer());
      sources.set(finding.file, source);
    }
    const owner = decoder.decode(source.subarray(finding.ownerStart, finding.ownerEnd));
    keys.push(`${finding.rule.id}\0${repositoryPath(root, finding.file)}\0${owner}`);
  }
  if (result.truncated) throw new Error("baseline comparison needs every finding record");
  return keys;
}

function repositoryPath(root: string, path: string): string {
  const relativePath = relative(root, path);
  if (relativePath.startsWith("..") || isAbsolute(relativePath)) {
    throw new Error(`${path} is outside the git repository at ${root}`);
  }
  return relativePath.replaceAll("\\", "/");
}

function git(args: string[], cwd: string, failure?: string): string {
  const result = Bun.spawnSync(["git", ...args], { cwd, stdout: "pipe", stderr: "pipe" });
  if (result.exitCode !== 0) {
    throw new Error(failure ?? `git ${args.join(" ")} failed: ${result.stderr.toString().trim()}`);
  }
  return result.stdout.toString();
}
