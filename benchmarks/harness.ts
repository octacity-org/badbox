import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { iterateFindings, type CheckResult, type InspectOptions, type PerformanceProfile } from "../src/scanner/index.ts";

export type Language = "rust" | "go";
export type Density = "sparse" | "dense";
const node = (kind: string) => `node ${kind}`;

/** DSL `find` selectors. */
const selectors: Record<Language, Record<Density, readonly string[]>> = {
  rust: {
    sparse: ["clone", "unwrap", "is_some", "is_none", "ok", "to_owned", "to_string", "is_empty", "len"]
      .map((method) => `code(value) \`value.${method}()\``)
      .concat(["code(value, args...) `value.expect(args)`"]),
    dense: ["call_expression", "identifier", "field_identifier", "field_expression", "arguments",
      "let_declaration", "return_expression", "reference_expression", "type_identifier", "block"]
      .map(node),
  },
  go: {
    sparse: [node("go_statement"), ...["panic", "close"].map((name) => `code(args...) \`${name}(args)\``),
      "code() `recover()`", ...["copy", "delete", "make", "append"].map((name) => `code(args...) \`${name}(args)\``),
      "code(type_name) `new(type_name)`", "code(value) `len(value)`"],
    dense: ["call_expression", "identifier", "argument_list", "selector_expression", "short_var_declaration",
      "assignment_statement", "return_statement", "binary_expression", "expression_statement", "block"]
      .map(node),
  },
};

/** Benchmark-only selectors; these are not product rules or engineering recommendations. */
export function makeRules(language: Language, density: Density, count: number) {
  if (!Number.isInteger(count) || count < 1 || count > 100) throw new Error("rule count must be 1..100");
  return Array.from({ length: count }, (_, index) => {
    const id = `bench/${language}-${density}-${String(index).padStart(3, "0")}`;
    const select = selectors[language][density][index % 10]!;
    return { id, language, select, source: `#badbox 1

rule ${id} for ${language} {
  summary "Benchmark selection, not a code-quality recommendation"
  find ${select}
  group by nearest callable
  when count > 0
  report {
    severity info
    message "Benchmark selection, not a code-quality recommendation"
    evidence "selected syntax sites"
  }
}
` };
  });
}

/** Hash every compact owner/count record. Rule IDs are map keys, not part of each digest. */
export function fingerprints(result: CheckResult): Record<string, string> {
  if (result.diagnostics.length) throw new Error(`benchmark scan has diagnostics: ${JSON.stringify(result.diagnostics)}`);
  if (result.truncated) throw new Error("benchmark scan unexpectedly truncated full-output validation");
  const hashes = new Map<string, ReturnType<typeof createHash>>();
  for (const finding of iterateFindings(result)) {
    const id = finding.rule.id;
    let hash = hashes.get(id);
    if (!hash) { hash = createHash("sha256"); hashes.set(id, hash); }
    hash.update(JSON.stringify([
      finding.file, finding.ownerStart, finding.ownerEnd, finding.observed,
    ])).update("\n");
  }
  return Object.fromEntries([...hashes.entries()].sort(([a], [b]) => a.localeCompare(b))
    .map(([id, hash]) => [id, hash.digest("hex")]));
}

export function summarize(values: readonly number[]) {
  if (!values.length || values.some((value) => !Number.isFinite(value))) throw new Error("expected finite samples");
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return { min: sorted[0]!, median: sorted.length % 2 ? sorted[middle]!
    : (sorted[middle - 1]! + sorted[middle]!) / 2, max: sorted.at(-1)! };
}

export interface WorkerConfig {
  options: InspectOptions;
  expected: Record<string, string>;
  checkedFiles: number;
  warmups: number;
  samples: number;
  profile?: boolean;
}

export interface WorkerResult {
  scanMs: number[];
  warmupMs: number[];
  findings: number;
  findingBytes: number;
  processWallMs: number;
  peakRssBytes: number;
  cpuTimeMicroseconds: number;
  performance?: PerformanceProfile;
}

export function workerTimeoutMs(config: Pick<WorkerConfig, "samples" | "warmups">): number {
  if (!Number.isInteger(config.samples) || config.samples < 1 ||
      !Number.isInteger(config.warmups) || config.warmups < 0) throw new Error("invalid worker sample counts");
  return 60_000 * (config.samples + config.warmups);
}

export async function measureWorker(configPath: string): Promise<WorkerResult> {
  const timeoutMs = workerTimeoutMs(await Bun.file(configPath).json());
  const started = performance.now();
  const worker = fileURLToPath(new URL("./worker.ts", import.meta.url));
  const process = Bun.spawn([globalThis.process.execPath, worker, configPath], {
    stdout: "pipe", stderr: "pipe",
  });
  const timeout = setTimeout(() => process.kill(), timeoutMs);
  try {
    const [stdout, stderr, code] = await Promise.all([
      new Response(process.stdout).text(), new Response(process.stderr).text(), process.exited,
    ]);
    const processWallMs = performance.now() - started;
    if (code !== 0) throw new Error(`benchmark worker failed (${code}): ${stderr}`);
    const usage = process.resourceUsage();
    if (!usage || usage.maxRSS <= 0) throw new Error("peak RSS is unavailable on this runtime");
    return { ...JSON.parse(stdout), processWallMs, peakRssBytes: Number(usage.maxRSS), cpuTimeMicroseconds: Number(usage.cpuTime.total) };
  } finally {
    clearTimeout(timeout);
  }
}
