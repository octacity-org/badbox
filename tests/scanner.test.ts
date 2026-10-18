import { afterAll, describe, expect, test } from "bun:test";
import { mkdtemp, mkdir, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { fileURLToPath } from "node:url";
import { inspect, iterateFindings, type CheckResult, type FindingRecord } from "../src/scanner/index.ts";

const fixtureRoot = fileURLToPath(new URL("./fixtures/counts", import.meta.url));
const exampleRulePack = fileURLToPath(new URL("../examples/rules", import.meta.url));
const rustRulePath = fileURLToPath(new URL("../examples/rules/rust/excessive-clones.badbox", import.meta.url));
const goRulePath = fileURLToPath(new URL("../examples/rules/go/excessive-goroutines.badbox", import.meta.url));
const powershellRulePath = fileURLToPath(new URL(
  "../examples/rules/powershell/excessive-invoke-expression.badbox", import.meta.url,
));
const zigRulePath = fileURLToPath(new URL("../examples/rules/zig/excessive-as-casts.badbox", import.meta.url));
const temporaryRoots: string[] = [];

const records = (result: CheckResult) => [...iterateFindings(result)];

async function ownerText(finding: FindingRecord): Promise<string> {
  const bytes = new Uint8Array(await Bun.file(finding.file).arrayBuffer());
  return new TextDecoder().decode(bytes.slice(finding.ownerStart, finding.ownerEnd));
}

async function temporaryRoot(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "badbox-test-"));
  temporaryRoots.push(root);
  return root;
}

afterAll(async () => {
  await Promise.all(temporaryRoots.map((root) => rm(root, { recursive: true, force: true })));
});

describe("native counting capability probes", () => {
  test("loads a multi-rule tiny DSL pack through the native engine", async () => {
    const root = await temporaryRoot();
    const source = join(root, "input.rs");
    const rules = join(root, "rules");
    await mkdir(rules);
    await Bun.write(
      source,
      "fn example() { a.clone(); b.clone(); a.unwrap(); b.unwrap(); }",
    );
    await Bun.write(join(rules, "rust.badbox"), `#badbox 1

rule rust/excessive-clones for rust {
  summary "Function contains multiple clone calls"
  param limit = 1
  find code(value) \`value.clone()\`
  group by nearest callable
  when count > limit
  report {
    severity info
    message "Callable contains too many clone call sites"
    evidence "clone call sites"
  }
}

rule rust/excessive-unwraps for rust {
  summary "Function contains multiple unwrap calls"
  find code(value) \`value.unwrap()\`
  group by nearest node(function_item, closure_expression)
  when count > 1
  report {
    severity warning
    message "Callable contains too many unwrap call sites"
    evidence "unwrap call sites"
  }
}

test rust/excessive-clones "reports excessive clones" {
  input "fixtures/excessive.rs"
  expect findings 1
}
`);

    const result = await inspect({ paths: [source], rulePaths: [rules] });

    expect(result.diagnostics).toEqual([]);
    expect(records(result).map((finding) => [
      finding.rule.id,
      finding.rule.message,
      finding.observed,
    ])).toEqual([
      ["rust/excessive-clones", "Callable contains too many clone call sites", 2],
      ["rust/excessive-unwraps", "Callable contains too many unwrap call sites", 2],
    ]);

    const overridden = await inspect({
      paths: [source],
      rulePaths: [rules],
      parameters: { "rust/excessive-clones.limit": 2 },
    });
    expect(records(overridden).map((finding) => finding.rule.id)).toEqual([
      "rust/excessive-unwraps",
    ]);
    expect(overridden.rules[0]?.threshold).toBe(2);

    await expect(inspect({
      paths: [source],
      rulePaths: [rules],
      parameters: { "rust/excessive-clones.unknown": 2 },
    })).rejects.toThrow("unknown parameter");
    await expect(inspect({
      paths: [source],
      rulePaths: [rules],
      parameters: { "rust/excessive-clones.limit": "two" },
    })).rejects.toThrow("must be an integer");
  });

  test("Rust, Go, PowerShell, and Zig share compact nearest-owner counting", async () => {
    const result = await inspect({ paths: [fixtureRoot], rulePaths: [exampleRulePack], threshold: 1 });
    const findings = records(result);
    expect(result.languages).toEqual(["go", "powershell", "rust", "zig"]);
    expect(result.checkedFiles).toBe(4);
    expect(result.diagnostics).toEqual([]);
    expect(result.findingCount).toBe(9);
    expect(findings).toHaveLength(9);
    expect(findings.filter((finding) => finding.rule.language === "rust")).toHaveLength(4);
    expect(findings.filter((finding) => finding.rule.language === "go")).toHaveLength(3);
    expect(findings.filter((finding) => finding.rule.language === "powershell")).toHaveLength(1);
    expect(findings.filter((finding) => finding.rule.language === "zig")).toHaveLength(1);
    for (const finding of findings) {
      expect(finding.observed).toBe(2);
      expect(finding.ownerStart).toBeLessThan(finding.ownerEnd);
      expect((await ownerText(finding)).length).toBeGreaterThan(0);
    }
  });

  test("a built-in ast-grep language outside the original Rust and Go pair scans end to end", async () => {
    const root = await temporaryRoot();
    const source = join(root, "input.py");
    const rule = join(root, "python.badbox");
    await Bun.write(source, [
      "def example():",
      '    print("first")',
      '    print("second")',
      "",
    ].join("\n"));
    await Bun.write(rule, `#badbox 1

rule python/excessive-prints for python {
  summary "Function contains multiple print calls"
  find code(value) \`print(value)\`
  group by nearest node(function_definition)
  when count > 1
  report {
    severity info
    message "Function contains multiple print calls"
    evidence "print call sites"
  }
}
`);

    const result = await inspect({ paths: [source], rulePaths: [rule] });
    expect(result.languages).toEqual(["python"]);
    expect(result.checkedFiles).toBe(1);
    expect(result.diagnostics).toEqual([]);
    expect(records(result).map((finding) => [finding.rule.language, finding.observed]))
      .toEqual([["python", 2]]);
  });

  test("Zig uses the generic nearest-owner counting pipeline", async () => {
    const source = join(fixtureRoot, "sample.zig");
    const result = await inspect({ paths: [source], rulePaths: [zigRulePath] });
    const repeated = await inspect({ paths: [source], rulePaths: [zigRulePath] });
    const findings = records(result);

    expect(result.languages).toEqual(["zig"]);
    expect(result.checkedFiles).toBe(1);
    expect(result.diagnostics).toEqual([]);
    expect(result.findingCount).toBe(1);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.rule.id).toBe("zig/excessive-as-casts");
    expect(findings[0]?.observed).toBe(2);
    expect(await ownerText(findings[0]!)).toContain("fn crowded");
    expect(repeated.files).toEqual(result.files);
    expect(repeated.rules).toEqual(result.rules);
    expect([...repeated.findings]).toEqual([...result.findings]);
  });

  test("PowerShell uses hash captures in the generic nearest-owner counting pipeline", async () => {
    const source = join(fixtureRoot, "sample.ps1");
    const result = await inspect({ paths: [source], rulePaths: [powershellRulePath] });
    const repeated = await inspect({ paths: [source], rulePaths: [powershellRulePath] });
    const findings = records(result);

    expect(result.languages).toEqual(["powershell"]);
    expect(result.checkedFiles).toBe(1);
    expect(result.diagnostics).toEqual([]);
    expect(result.findingCount).toBe(1);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.rule.id).toBe("powershell/excessive-invoke-expression");
    expect(findings[0]?.observed).toBe(2);
    expect(await ownerText(findings[0]!)).toContain("function Invoke-Repeatedly");
    expect(repeated.files).toEqual(result.files);
    expect(repeated.rules).toEqual(result.rules);
    expect([...repeated.findings]).toEqual([...result.findings]);
  });

  test("PowerShell syntax errors produce diagnostics without partial findings", async () => {
    const root = await temporaryRoot();
    const source = join(root, "broken.ps1");
    await Bun.write(source, "function Broken { Invoke-Expression $first");
    const result = await inspect({ paths: [source], rulePaths: [powershellRulePath] });

    expect(result.languages).toEqual(["powershell"]);
    expect(result.checkedFiles).toBe(0);
    expect(result.findingCount).toBe(0);
    expect(result.diagnostics).toHaveLength(1);
    expect(result.diagnostics[0]?.message).toContain("syntax errors");
  });

  test("counts lexical sites, respects strict greater-than, and is reproducible", async () => {
    expect((await inspect({ paths: [fixtureRoot], rulePaths: [exampleRulePack], threshold: 2 })).findingCount).toBe(0);
    const first = await inspect({ paths: [fixtureRoot], rulePaths: [exampleRulePack], threshold: 0 });
    const second = await inspect({ paths: [fixtureRoot, fixtureRoot], rulePaths: [exampleRulePack], threshold: 0 });
    expect(second.files).toEqual(first.files);
    expect(second.rules).toEqual(first.rules);
    expect([...second.findings]).toEqual([...first.findings]);
    expect(records(first).filter((finding) => finding.observed === 1)).toHaveLength(4);
  });

  test("rejects invalid scalar options instead of coercing them", async () => {
    await expect(inspect({ paths: [fixtureRoot], rulePaths: [exampleRulePack], threshold: -1 })).rejects.toThrow();
    await expect(inspect({ paths: [fixtureRoot], rulePaths: [exampleRulePack], threshold: 1.5 })).rejects.toThrow();
    await expect(inspect({ paths: [], rulePaths: [exampleRulePack] })).rejects.toThrow();
    await expect(inspect({
      paths: [fixtureRoot], rulePaths: [exampleRulePack], maxFindings: 0x1_0000_0000,
    })).rejects.toThrow();
  });

  test("changing only the rule file selects different syntax and metadata", async () => {
    const root = await temporaryRoot();
    const source = join(root, "input.rs");
    await Bun.write(source, 'fn example() { let label = "🦀"; value.clone().clone(); value.clone(); value.unwrap(); value.unwrap(); }');
    const original = await Bun.file(rustRulePath).text();
    const changedRule = join(root, "changed.badbox");
    await Bun.write(changedRule, original
      .replace("rust/excessive-clones", "probe/changed-pattern")
      .replace("value.clone()", "value.unwrap()")
      .replaceAll("clone call sites", "unwrap call sites"));

    const result = await inspect({ paths: [source], rulePaths: [rustRulePath, changedRule] });
    expect(records(result).map((finding) => [finding.rule.id, finding.observed])).toEqual([
      ["rust/excessive-clones", 3], ["probe/changed-pattern", 2],
    ]);
    expect(result.rules[1]?.evidenceSubject).toBe("unwrap call sites");

    await Bun.write(changedRule, (await Bun.file(changedRule).text()).replace("param limit = 1", "param limit = 2"));
    expect((await inspect({ paths: [source], rulePaths: [changedRule] })).findingCount).toBe(0);
  });

  test("only relevant rules run while discovery reports every supported language", async () => {
    const root = await temporaryRoot();
    for (const file of ["a.rs", "b.rs"]) {
      await Bun.write(join(root, file), "fn same() { a.clone(); b.clone(); }");
    }
    await Bun.write(join(root, "broken.go"), "func malformed(");
    await Bun.write(join(root, "unrelated.ts"), "not even valid TypeScript");
    const result = await inspect({ paths: [root], rulePaths: [rustRulePath] });
    expect(result.languages).toEqual(["go", "rust", "typescript"]);
    expect(result.checkedFiles).toBe(2);
    expect(result.diagnostics).toEqual([]);
    expect(new Set(records(result).map((finding) => finding.file)).size).toBe(2);
  });

  test("gitignored files, hidden directories, build output, and symlink loops are skipped", async () => {
    const root = await temporaryRoot();
    const source = "fn counted() { a.clone(); b.clone(); }";
    await Bun.write(join(root, ".gitignore"), "ignored.rs\n");
    await Bun.write(join(root, "ignored.rs"), source);
    await Bun.write(join(root, "kept.rs"), source);
    for (const directory of [".cache", "target", "vendor", "node_modules"]) {
      await mkdir(join(root, directory));
      await Bun.write(join(root, directory, "excluded.rs"), source);
    }
    await symlink(root, join(root, "loop"), "dir");
    const result = await inspect({ paths: [root], rulePaths: [rustRulePath] });
    expect(result.checkedFiles).toBe(1);
    expect(result.findingCount).toBe(1);
    expect(records(result).map((finding) => basename(finding.file))).toEqual(["kept.rs"]);
  });

  test("syntax errors produce diagnostics without partial findings", async () => {
    const root = await temporaryRoot();
    await Bun.write(join(root, "broken.rs"), "fn broken() { value.clone(); value.clone(); fn (");
    const result = await inspect({ paths: [root], rulePaths: [rustRulePath] });
    expect(result.checkedFiles).toBe(0);
    expect(result.findings.length).toBe(0);
    expect(result.diagnostics).toHaveLength(1);
    expect(result.diagnostics[0]?.message).toContain("syntax errors");
  });

  test("invalid rules and unreadable paths fail explicitly", async () => {
    const root = await temporaryRoot();
    const original = await Bun.file(rustRulePath).text();
    const rulePath = join(root, "invalid.badbox");
    const find = "find code(value) `value.clone()`";
    for (const rule of [
      original.replace("#badbox 1", "#badbox 99"),
      original.replace("rust/excessive-clones", "no-namespace"),
      original.replace("for rust", "for klingon"),
      original.replace("when count", "when sum"),
      original.replace("param limit = 1", "param limit = -1"),
      original.replace("nearest callable", "nearest node()"),
      original.replace("nearest callable", "nearest node(nonexistent_kind)"),
      original.replace(find, "find node nonexistent_kind"),
      original.replace(find, "find code(value) ``"),
      original.replace(find, `${find}\n  find node call_expression`),
      original.replace(find, `${find}\n  unexpected true`),
    ]) {
      await Bun.write(rulePath, rule);
      await expect(inspect({ paths: [fixtureRoot], rulePaths: [rulePath] })).rejects.toThrow();
    }
    const yamlRule = join(root, "rule.yaml");
    await Bun.write(yamlRule, "id: rust/excessive-clones\n");
    await expect(inspect({ paths: [fixtureRoot], rulePaths: [yamlRule] })).rejects.toThrow("unsupported rule file");
    await expect(inspect({ paths: [fixtureRoot], rulePaths: [] })).rejects.toThrow("rulePaths");
    await expect(inspect({ paths: [fixtureRoot], rulePaths: [rustRulePath, rustRulePath] })).rejects.toThrow("duplicate rule ID");
    await expect(inspect({ paths: [join(root, "missing")], rulePaths: [goRulePath] })).rejects.toThrow("source path");
    await expect(inspect({ paths: [fixtureRoot], rulePaths: [join(root, "missing.badbox")] })).rejects.toThrow("rule");
  });

  test("profiles phases, shares execution, and invalidates native caches", async () => {
    const root = await temporaryRoot();
    const source = join(root, "input.rs");
    await Bun.write(source, "fn example() { a.clone(); b.clone(); }");
    const original = await Bun.file(rustRulePath).text();
    const firstRule = join(root, "first.badbox");
    const secondRule = join(root, "second.badbox");
    await Bun.write(firstRule, original.replace("rust/excessive-clones", "probe/first"));
    await Bun.write(secondRule, original.replace("rust/excessive-clones", "probe/second"));
    const run = async () => await inspect({
      paths: [source], rulePaths: [firstRule, secondRule], profile: true,
    });

    const cold = await run();
    expect(cold.findingCount).toBe(2);
    expect(cold.performance?.selectorExecutions).toBe(1);
    expect(cold.performance?.ruleEvaluations).toBe(2);
    expect(cold.performance?.ruleCacheMisses).toBe(2);
    expect(cold.performance?.resultCacheMisses).toBe(1);
    expect(cold.performance?.parseCacheMisses).toBe(1);
    const warm = await run();
    expect([...warm.findings]).toEqual([...cold.findings]);
    expect(warm.performance?.ruleCacheHits).toBe(2);
    expect(warm.performance?.resultCacheHits).toBe(1);
    expect(warm.performance?.parseCacheHits).toBe(0);
    expect(warm.performance?.selectorExecutions).toBe(0);
    expect(warm.performance?.ruleEvaluations).toBe(0);

    await Bun.write(source, "fn example() { a.clone(); b.clone(); c.clone(); }");
    const changedSource = await run();
    expect(changedSource.performance?.resultCacheMisses).toBe(1);
    expect(changedSource.performance?.parseCacheMisses).toBe(1);
    expect(records(changedSource).map((finding) => finding.observed)).toEqual([3, 3]);

    await Bun.write(firstRule, (await Bun.file(firstRule).text()).replace("severity info", "severity warning"));
    const changedRule = await run();
    expect(changedRule.performance?.ruleCacheHits).toBe(1);
    expect(changedRule.performance?.ruleCacheMisses).toBe(1);
    expect(changedRule.performance?.resultCacheMisses).toBe(1);
    expect(changedRule.performance?.parseCacheHits).toBe(1);
  });

  test("reuses compact results beyond the bounded AST cache and remaps file IDs", async () => {
    const root = await temporaryRoot();
    const fileCount = 300;
    for (let index = 0; index < fileCount; index++) {
      await Bun.write(
        join(root, `${String(index).padStart(3, "0")}.rs`),
        `fn owner_${index}() { a.clone(); b.clone(); }`,
      );
    }

    const options = { paths: [root], rulePaths: [rustRulePath], profile: true } as const;
    const cold = await inspect(options);
    const warm = await inspect(options);

    expect(cold.findingCount).toBe(fileCount);
    expect(cold.performance?.resultCacheMisses).toBe(fileCount);
    expect(warm.findingCount).toBe(fileCount);
    expect(warm.performance?.resultCacheHits).toBe(fileCount);
    expect(warm.performance?.resultCacheMisses).toBe(0);
    expect(warm.performance?.parseCacheHits).toBe(0);
    expect(warm.performance?.parseCacheMisses).toBe(0);
    expect(warm.performance?.selectorExecutions).toBe(0);
    expect(records(warm).map((finding) => finding.file)).toEqual([...warm.files]);
  });

  test("bounds native file parallelism", async () => {
    const root = await temporaryRoot();
    for (let index = 0; index < 8; index++) {
      await Bun.write(join(root, `${index}.rs`), `fn owner_${index}() { a.clone(); b.clone(); }`);
    }
    const result = await inspect({ paths: [root], rulePaths: [rustRulePath], profile: true });
    expect(result.checkedFiles).toBe(8);
    expect(result.performance?.workerThreads).toBeGreaterThanOrEqual(1);
    expect(result.performance?.workerThreads).toBeLessThanOrEqual(4);
  });

  test("bounds compact findings without hiding the exact count", async () => {
    const root = await temporaryRoot();
    for (let index = 0; index < 5; index++) {
      await Bun.write(join(root, `${index}.rs`),
        `fn owner_${index}() { a.clone(); b.clone(); c.clone(); }`);
    }
    const result = await inspect({ paths: [root], rulePaths: [rustRulePath], maxFindings: 2 });
    expect(result.findingCount).toBe(5);
    expect(result.findings.length / result.recordWidth).toBe(2);
    expect(result.truncated).toBe(true);
    expect(records(result).map((finding) => finding.observed)).toEqual([3, 3]);
  });

  test("keeps the earliest owners when findings are truncated within one file", async () => {
    const root = await temporaryRoot();
    const source = join(root, "owners.rs");
    await Bun.write(source, Array.from({ length: 30 }, (_, index) =>
      `fn owner_${index}() { a.clone(); b.clone(); }\n`).join(""));
    const result = await inspect({ paths: [source], rulePaths: [rustRulePath], maxFindings: 3 });
    expect(result.findingCount).toBe(30);
    expect(await Promise.all(records(result).map(ownerText))).toEqual(
      [0, 1, 2].map((index) => `fn owner_${index}() { a.clone(); b.clone(); }`),
    );
  });

  test("orders findings that share an owner start by owner end", async () => {
    const root = await temporaryRoot();
    const source = join(root, "chain.rs");
    const rules = join(root, "chain.badbox");
    await Bun.write(source, "fn chain() { a.b(x.clone()).c(y.clone()); }");
    await Bun.write(rules, `#badbox 1
rule rust/clone-arguments for rust {
  summary "Clone calls grouped by the enclosing call"
  find code(value) \`value.clone()\`
  group by nearest node(call_expression)
  when count > 0
  report {
    severity info
    message "Call has clone arguments"
    evidence "clone call sites"
  }
}
`);
    const result = await inspect({ paths: [source], rulePaths: [rules] });
    expect(await Promise.all(records(result).map(ownerText))).toEqual([
      "a.b(x.clone())",
      "a.b(x.clone()).c(y.clone())",
    ]);
  });

  test("source text that is not UTF-8 becomes a diagnostic without discarding other files", async () => {
    const root = await temporaryRoot();
    const encoder = new TextEncoder();
    await Bun.write(join(root, "good.rs"), "fn good() { a.clone(); b.clone(); }");
    await Bun.write(join(root, "latin1.rs"), new Uint8Array([
      ...encoder.encode("// caf"), 0xe9, ...encoder.encode("\nfn bad() { a.clone(); b.clone(); }\n"),
    ]));
    const result = await inspect({ paths: [root], rulePaths: [rustRulePath] });
    expect(result.checkedFiles).toBe(1);
    expect(records(result).map((finding) => basename(finding.file))).toEqual(["good.rs"]);
    expect(result.diagnostics).toHaveLength(1);
    expect(basename(result.diagnostics[0]!.file)).toBe("latin1.rs");
    expect(result.diagnostics[0]?.message).toContain("UTF-8");
  });

  test("match inside requires an enclosing node, not the match itself", async () => {
    const root = await temporaryRoot();
    const rustSource = join(root, "nested.rs");
    const goSource = join(root, "statement.go");
    const rules = join(root, "inside.badbox");
    await Bun.write(rustSource, "fn calls() { outer(inner(1)); alone(2); }");
    await Bun.write(goSource, "package p\n\nfunc calls() {\n\trun()\n}\n");
    await Bun.write(rules, `#badbox 1
rule rust/nested-calls for rust {
  summary "Calls nested in another call"
  find node call_expression
  group by nearest callable
  where match inside any { node call_expression }
  when count > 0
  report {
    severity info
    message "Callable has nested calls"
    evidence "nested calls"
  }
}

rule go/statement-calls for go {
  summary "Calls inside expression statements"
  find node call_expression
  group by nearest callable
  where match inside any { node expression_statement }
  when count > 0
  report {
    severity info
    message "Callable has statement calls"
    evidence "statement calls"
  }
}
`);
    const result = await inspect({ paths: [root], rulePaths: [rules] });
    expect(result.diagnostics).toEqual([]);
    expect(records(result).map((finding) => [finding.rule.id, finding.observed])).toEqual([
      ["rust/nested-calls", 1],
      ["go/statement-calls", 1],
    ]);
  });

  test("profiles aggregation and compact output construction separately", async () => {
    const result = await inspect({ paths: [fixtureRoot], rulePaths: [exampleRulePack], profile: true });
    expect(result.performance?.aggregationMs).toBeGreaterThanOrEqual(0);
    expect(result.performance?.outputBuildMs).toBeGreaterThanOrEqual(0);
    expect(result.performance?.resultMergeMs).toBeGreaterThanOrEqual(0);
  });

  test("executes capture text, match ancestry, and group evidence conditions", async () => {
    const root = await temporaryRoot();
    const source = join(root, "input.rs");
    const rules = join(root, "relational.badbox");
    await Bun.write(source, `
fn flagged() { loop { unwrap(value); break; } }
fn wrong_method() { loop { inspect(value); break; } }
fn outside_loop() { unwrap(value); }
fn guarded() { loop { expect(value); break; } cancel(); }
fn has_evidence() { write(value); transaction(); }
fn lacks_evidence() { write(value); }
`);
    await Bun.write(rules, `#badbox 1
rule rust/loop-without-cancel for rust {
  summary "Selected calls inside loops without cancellation evidence"
  find code(method, value) \`method(value)\`
  group by nearest callable
  where text(method) in ["unwrap", "expect"]
  where text(method) != "inspect"
  where text(method) not in ["inspect", "debug"]
  where text(method) matches "^(unwrap|expect)$"
  where match inside any { node loop_expression }
  where group lacks any { code() \`cancel()\` }
  when count > 0
  report {
    severity warning
    message "Loop call has no recognized cancellation evidence"
    evidence "selected loop calls"
  }
}

rule rust/write-with-transaction for rust {
  summary "Writes in functions with transaction evidence"
  find code(method, value) \`method(value)\`
  group by nearest callable
  where text(method) == "write"
  where group has all {
    code() \`transaction()\`
    node function_item
  }
  where group lacks any { code() \`cancel()\` }
  when count > 0
  report {
    severity info
    message "Write has recognized transaction evidence"
    evidence "write calls"
  }
}
`);

    const result = await inspect({ paths: [source], rulePaths: [rules], profile: true });
    expect(result.diagnostics).toEqual([]);
    expect(result.performance?.selectorExecutions).toBe(5);
    expect(result.performance?.ruleEvaluations).toBe(2);
    const actual = await Promise.all(records(result).map(async (finding) => [
      finding.rule.id, await ownerText(finding), finding.observed,
    ]));
    expect(actual).toEqual([
      ["rust/loop-without-cancel", "fn flagged() { loop { unwrap(value); break; } }", 1],
      ["rust/write-with-transaction", "fn has_evidence() { write(value); transaction(); }", 1],
    ]);
  });

  test("executes follows and precedes only between statements in the same lexical block and callable", async () => {
    const root = await temporaryRoot();
    const source = join(root, "ordering.rs");
    const rules = join(root, "ordering.badbox");
    await Bun.write(source, `
fn follows_any() { prepare(); middle(); target(); }
fn precedes_any() { target(); middle(); cleanup(); }
fn follows_all() { prepare(); lock(); target(); }
fn missing_all() { prepare(); target(); }
fn wrong_order() { target(); prepare(); }
fn separate_branches(flag: bool) { if flag { prepare(); } else { target(); } }
fn match_branches(flag: bool) { match flag { true => prepare(), false => target(), } }
fn nested_block() { prepare(); loop { target(); break; } }
fn same_statement() { combine(prepare(), target()); }
fn nested_callable() { prepare(); let inner = || { target(); }; inner(); }
`);
    await Bun.write(rules, `#badbox 1
rule rust/follows-any for rust {
  summary "Target follows preparation"
  find code() \`target()\`
  group by nearest callable
  where match follows any { code() \`prepare()\` }
  when count > 0
  report {
    severity warning
    message "Target follows preparation"
    evidence "target calls"
  }
}

rule rust/precedes-any for rust {
  summary "Target precedes cleanup"
  find code() \`target()\`
  group by nearest callable
  where match precedes any { code() \`cleanup()\` }
  when count > 0
  report {
    severity warning
    message "Target precedes cleanup"
    evidence "target calls"
  }
}

rule rust/follows-all for rust {
  summary "Target follows all preparation selectors"
  find code() \`target()\`
  group by nearest callable
  where match follows all {
    code() \`prepare()\`
    code() \`lock()\`
  }
  when count > 0
  report {
    severity warning
    message "Target follows all preparation selectors"
    evidence "target calls"
  }
}
`);

    const result = await inspect({ paths: [source], rulePaths: [rules], profile: true });
    expect(result.diagnostics).toEqual([]);
    expect(result.performance?.selectorExecutions).toBe(4);
    expect(result.performance?.ruleEvaluations).toBe(3);
    const actual = await Promise.all(records(result).map(async (finding) => [
      finding.rule.id, await ownerText(finding), finding.observed,
    ] as const));
    actual.sort((left, right) => `${left[0]}\0${left[1]}`.localeCompare(`${right[0]}\0${right[1]}`));
    expect(actual).toEqual([
      ["rust/follows-all", "fn follows_all() { prepare(); lock(); target(); }", 1],
      ["rust/follows-any", "fn follows_all() { prepare(); lock(); target(); }", 1],
      ["rust/follows-any", "fn follows_any() { prepare(); middle(); target(); }", 1],
      ["rust/follows-any", "fn missing_all() { prepare(); target(); }", 1],
      ["rust/precedes-any", "fn precedes_any() { target(); middle(); cleanup(); }", 1],
    ]);
  });

  test("executes statement ordering across Go, PowerShell, and Zig callable groups", async () => {
    const cases = [
      {
        language: "go",
        extension: "go",
        source: `package probe
func ordered() { prepare(); target() }
func branches(flag bool) { if flag { prepare() } else { target() } }
func nested() { prepare(); inner := func() { target() }; inner() }
`,
        owner: "func ordered() { prepare(); target() }",
        prepare: "prepare()",
        target: "target()",
      },
      {
        language: "powershell",
        extension: "ps1",
        source: `function Ordered { Invoke-Prepare; Invoke-Target }
function Branches { if ($true) { Invoke-Prepare } else { Invoke-Target } }
function Nested { Invoke-Prepare; function Inner { Invoke-Target }; Inner }
`,
        owner: "function Ordered { Invoke-Prepare; Invoke-Target }",
        prepare: "Invoke-Prepare",
        target: "Invoke-Target",
      },
      {
        language: "zig",
        extension: "zig",
        source: `fn ordered() void { prepare(); target(); }
fn branches(flag: bool) void { if (flag) { prepare(); } else { target(); } }
fn nested() void { prepare(); const Inner = struct { fn run() void { target(); } }; Inner.run(); }
`,
        owner: "fn ordered() void { prepare(); target(); }",
        prepare: "prepare()",
        target: "target()",
      },
    ] as const;

    for (const probe of cases) {
      const root = await temporaryRoot();
      const source = join(root, `ordering.${probe.extension}`);
      const rules = join(root, `ordering-${probe.language}.badbox`);
      await Bun.write(source, probe.source);
      await Bun.write(rules, `#badbox 1
rule ${probe.language}/ordering for ${probe.language} {
  summary "Target follows preparation"
  find code() \`${probe.target}\`
  group by nearest callable
  where match follows any { code() \`${probe.prepare}\` }
  when count > 0
  report {
    severity warning
    message "Target follows preparation"
    evidence "target sites"
  }
}
`);

      const result = await inspect({ paths: [source], rulePaths: [rules] });
      expect(result.diagnostics).toEqual([]);
      expect(result.findingCount).toBe(1);
      expect(await ownerText(records(result)[0]!)).toBe(probe.owner);
    }
  });

  test("correlates repeated capture names across primary and ordering selectors", async () => {
    const root = await temporaryRoot();
    const source = join(root, "capture-ordering.zig");
    const rules = join(root, "capture-ordering.badbox");
    await Bun.write(source, `
fn sameReceiver() void { stmt.reset(); stmt.clearBindings(); }
fn differentReceivers() void { first.reset(); second.clearBindings(); }
fn anotherSameReceiver() void { other.reset(); other.clearBindings(); }
`);
    await Bun.write(rules, `#badbox 1
rule zig/correlated-ordering for zig {
  summary "A statement is reset before its bindings are cleared"
  find code(statement) \`statement.clearBindings()\`
  group by nearest callable
  where match follows any {
    code(statement) \`statement.reset()\`
  }
  when count > 0
  report {
    severity info
    message "Statement reset is followed by clearing its bindings"
    evidence "same-receiver reset and clear sites"
  }
}
`);

    const result = await inspect({ paths: [source], rulePaths: [rules] });
    expect(result.diagnostics).toEqual([]);
    expect(result.recordWidth).toBe(5);
    const owners = await Promise.all(records(result).map(ownerText));
    expect(owners).toEqual([
      "fn sameReceiver() void { stmt.reset(); stmt.clearBindings(); }",
      "fn anotherSameReceiver() void { other.reset(); other.clearBindings(); }",
    ]);
  });

  test("requires every shared capture in an ordering selector to match", async () => {
    const root = await temporaryRoot();
    const source = join(root, "multi-capture-ordering.zig");
    const rules = join(root, "multi-capture-ordering.badbox");
    await Bun.write(source, `
fn bothMatch() void { db.prepare(sql); db.execute(sql); }
fn databaseDiffers() void { first.prepare(sql); second.execute(sql); }
fn statementDiffers() void { db.prepare(first_sql); db.execute(second_sql); }
`);
    await Bun.write(rules, `#badbox 1
rule zig/multi-capture-ordering for zig {
  summary "A database executes the statement it prepared"
  find code(database, statement) \`database.execute(statement)\`
  group by nearest callable
  where match follows any {
    code(database, statement) \`database.prepare(statement)\`
  }
  when count > 0
  report {
    severity info
    message "Database execution follows matching preparation"
    evidence "same-database and same-statement sites"
  }
}
`);

    const result = await inspect({ paths: [source], rulePaths: [rules] });
    expect(result.diagnostics).toEqual([]);
    expect(result.findingCount).toBe(1);
    expect(await ownerText(records(result)[0]!)).toBe(
      "fn bothMatch() void { db.prepare(sql); db.execute(sql); }",
    );
  });

  test("interns exact selectors across distinct rule plans", async () => {
    const root = await temporaryRoot();
    const source = join(root, "input.rs");
    const rules = join(root, "shared-selectors.badbox");
    await Bun.write(source, "fn example() { clone(value); }");
    const definitions = Array.from({ length: 50 }, (_, index) => `
rule rust/shared-${index} for rust {
  summary "Shared selector probe ${index}"
  find code(method, value) \`method(value)\`
  group by nearest callable
  where text(method) matches "^(clone|never_${index})$"
  where group lacks any { code() \`cancel()\` }
  when count > 0
  report {
    severity info
    message "Shared selector matched"
    evidence "call sites"
  }
}`).join("\n");
    await Bun.write(rules, `#badbox 1\n${definitions}\n`);

    const result = await inspect({ paths: [source], rulePaths: [rules], profile: true });
    expect(result.findingCount).toBe(50);
    expect(result.performance?.selectorExecutions).toBe(2);
    expect(result.performance?.ruleEvaluations).toBe(50);
  });
});

describe("rule features", () => {
  const ruleBody = (id: string, language: string, body: string) => `rule ${id} for ${language} {
  summary "probe"
${body}
  when count > 0
  report {
    severity info
    message "probe"
    evidence "probe sites"
  }
}
`;
  const ownerSummary = async (result: CheckResult) => await Promise.all(records(result).map(async (finding) => [
    finding.rule.id, /(?:fn|void) (\w+)/.exec(await ownerText(finding))?.[1], finding.observed,
  ]));

  test("match not inside keeps only matches outside the listed nodes", async () => {
    const root = await temporaryRoot();
    await Bun.write(join(root, "input.rs"), `
fn outside() { a.unwrap(); b.unwrap(); }
fn mixed() { a.unwrap(); loop { b.unwrap(); break; } let f = || c.unwrap(); }
fn nested() { loop { let f = || d.unwrap(); break; } }
`);
    const rules = join(root, "rules.badbox");
    const select = `  find code(value) \`value.unwrap()\`
  group by nearest node(function_item)`;
    await Bun.write(rules, `#badbox 1
${ruleBody("rust/outside-any", "rust", `${select}
  where match not inside any { node loop_expression node closure_expression }`)}
${ruleBody("rust/outside-all", "rust", `${select}
  where match not inside all { node loop_expression node closure_expression }`)}`);

    const result = await inspect({ paths: [root], rulePaths: [rules] });
    expect(result.diagnostics).toEqual([]);
    expect(await ownerSummary(result)).toEqual([
      ["rust/outside-any", "outside", 2],
      ["rust/outside-all", "outside", 2],
      ["rust/outside-any", "mixed", 1],
      ["rust/outside-all", "mixed", 3],
    ]);
  });

  test("text conditions read string parameters and their overrides", async () => {
    const root = await temporaryRoot();
    const source = join(root, "input.rs");
    await Bun.write(source, "fn calls() { a.clone(); b.unwrap(); c.unwrap(); }");
    const body = `  param method = "clone"
  find code(value, name) \`value.name()\`
  group by nearest callable
  where text(name) == method`;
    const first = join(root, "first.badbox");
    const second = join(root, "second.badbox");
    const regex = join(root, "regex.badbox");
    await Bun.write(first, `#badbox 1\n${ruleBody("rust/named-calls", "rust", body)}`);
    await Bun.write(second, `#badbox 1\n${ruleBody("rust/named-calls-copy", "rust", body)}`);
    await Bun.write(regex, `#badbox 1\n${ruleBody("rust/matched-calls", "rust", `  param pattern = "^un"
  find code(value, name) \`value.name()\`
  group by nearest callable
  where text(name) in ["clone", pattern]
  where text(name) matches pattern`)}`);
    const observed = async (rulePaths: string[], parameters = {}) =>
      records(await inspect({ paths: [source], rulePaths, parameters })).map((finding) => [finding.rule.id, finding.observed]);

    expect(await observed([first])).toEqual([["rust/named-calls", 1]]);
    expect(await observed([first], { "rust/named-calls.method": "unwrap" })).toEqual([["rust/named-calls", 2]]);
    // Identical rules with different effective values must not share execution.
    expect(await observed([first, second], { "rust/named-calls.method": "unwrap" })).toEqual([
      ["rust/named-calls", 2], ["rust/named-calls-copy", 1],
    ]);
    expect(await observed([first])).toEqual([["rust/named-calls", 1]]);
    // `in` compares literally, so "^un" only matters through `matches`.
    expect(await observed([regex])).toEqual([]);
    expect(await observed([regex], { "rust/matched-calls.pattern": "clone" })).toEqual([["rust/matched-calls", 1]]);
    await expect(inspect({
      paths: [source], rulePaths: [regex], parameters: { "rust/matched-calls.pattern": "(" },
    })).rejects.toThrow("rust/matched-calls");
  });

  test("code patterns select a node from a parsing context", async () => {
    const root = await temporaryRoot();
    await Bun.write(join(root, "input.c"), `
void releases(void *a, void *b) { free(a); free(b); }
void prints(void) { puts("x"); }
`);
    const rules = join(root, "rules.badbox");
    const group = "  group by nearest node(function_definition)";
    await Bun.write(rules, `#badbox 1
${ruleBody("c/free-bare", "c", `  find code(pointer) \`free(pointer)\`\n${group}`)}
${ruleBody("c/free-calls", "c", `  find code(pointer) \`void f() { free(pointer); }\` select call_expression\n${group}`)}
${ruleBody("c/calls-with-free", "c", `  find node call_expression
${group}
  where group has any { code(pointer) \`void f() { free(pointer); }\` select call_expression }`)}`);

    const result = await inspect({ paths: [root], rulePaths: [rules] });
    expect(result.diagnostics).toEqual([]);
    // Without context, \`free(pointer);\` parses as a declaration and matches no calls.
    expect(await ownerSummary(result)).toEqual([
      ["c/free-calls", "releases", 2],
      ["c/calls-with-free", "releases", 2],
    ]);

    await Bun.write(rules, `#badbox 1
${ruleBody("c/free-calls", "c", `  find code(pointer) \`void f() { free(pointer); }\` select no_such_kind\n${group}`)}`);
    await expect(inspect({ paths: [root], rulePaths: [rules] })).rejects.toThrow("no_such_kind");
  });
});

describe("callable mappings", () => {
  // Each probe gives every mapped callable kind one target site, then checks ordering against the
  // same-block, branch, nested-callable, and switch-case boundaries used by Rust, Go, and Zig.
  const code = (pattern: string) => `code() \`${pattern}\``;
  const javascriptFamily = {
    target: code("target()"),
    prepare: code("prepare()"),
    callables: {
      source: `function declared() { target(); }
function* generated() { target(); }
const expression = function () { target(); };
const generator = function* () { target(); };
const arrow = () => { target(); };
class Owner { method() { target(); } }
`,
      owners: [
        "function declared() { target(); }",
        "function* generated() { target(); }",
        "function () { target(); }",
        "function* () { target(); }",
        "() => { target(); }",
        "method() { target(); }",
      ],
    },
    ordering: {
      source: `function ordered() { prepare(); target(); }
function branches(flag) { if (flag) { prepare(); } else { target(); } }
function nested() { prepare(); const inner = () => { target(); }; inner(); }
function cases(x) { switch (x) { case 1: prepare(); break; default: target(); } }
function inCase(x) { switch (x) { case 1: prepare(); target(); } }
function inDefault(x) { switch (x) { default: prepare(); target(); } }
`,
      owners: [
        "function ordered() { prepare(); target(); }",
        "function inCase(x) { switch (x) { case 1: prepare(); target(); } }",
        "function inDefault(x) { switch (x) { default: prepare(); target(); } }",
      ],
    },
  };
  const probes = [
    { language: "typescript", extension: "ts", ...javascriptFamily },
    { language: "tsx", extension: "tsx", ...javascriptFamily },
    { language: "javascript", extension: "js", ...javascriptFamily },
    {
      language: "python",
      extension: "py",
      target: code("target()"),
      prepare: code("prepare()"),
      callables: {
        source: `def declared():
    target()

anonymous = lambda: target()
`,
        owners: ["def declared():\n    target()", "lambda: target()"],
      },
      ordering: {
        source: `def ordered():
    prepare()
    target()

def branches(flag):
    if flag:
        prepare()
    else:
        target()

def nested():
    prepare()
    inner = lambda: target()
`,
        owners: ["def ordered():\n    prepare()\n    target()"],
      },
    },
    {
      language: "java",
      extension: "java",
      target: code("target()"),
      prepare: code("prepare()"),
      callables: {
        source: `class Owner {
  Owner() { target(); }
  void method() { target(); }
  Runnable lambda = () -> { target(); };
}
record Point(int x) { Point { target(); } }
`,
        owners: [
          "Owner() { target(); }",
          "void method() { target(); }",
          "() -> { target(); }",
          "Point { target(); }",
        ],
      },
      ordering: {
        source: `class Ordering {
  void ordered() { prepare(); target(); }
  void branches(boolean flag) { if (flag) { prepare(); } else { target(); } }
  void nested() { prepare(); Runnable inner = () -> { target(); }; }
  void cases(int x) { switch (x) { case 1: prepare(); break; default: target(); } }
  void inCase(int x) { switch (x) { case 1: prepare(); target(); } }
  Ordering() { prepare(); target(); }
}
`,
        owners: [
          "void ordered() { prepare(); target(); }",
          "void inCase(int x) { switch (x) { case 1: prepare(); target(); } }",
          "Ordering() { prepare(); target(); }",
        ],
      },
    },
    {
      language: "c",
      extension: "c",
      target: code("target()"),
      prepare: code("prepare()"),
      callables: {
        source: "void declared(void) { target(); }\n",
        owners: ["void declared(void) { target(); }"],
      },
      ordering: {
        source: `void ordered(void) { prepare(); target(); }
void branches(int flag) { if (flag) { prepare(); } else { target(); } }
void cases(int x) { switch (x) { case 1: prepare(); break; default: target(); } }
void inCase(int x) { switch (x) { case 1: prepare(); target(); } }
`,
        owners: [
          "void ordered(void) { prepare(); target(); }",
          "void inCase(int x) { switch (x) { case 1: prepare(); target(); } }",
        ],
      },
    },
    {
      language: "cpp",
      extension: "cpp",
      target: code("target()"),
      prepare: code("prepare()"),
      callables: {
        source: `void declared() { target(); }
struct Owner { void method() { target(); } };
auto lambda = []() { target(); };
`,
        owners: ["void declared() { target(); }", "void method() { target(); }", "[]() { target(); }"],
      },
      ordering: {
        source: `void ordered() { prepare(); target(); }
void branches(bool flag) { if (flag) { prepare(); } else { target(); } }
void nested() { prepare(); auto inner = [&]() { target(); }; inner(); }
void cases(int x) { switch (x) { case 1: prepare(); break; default: target(); } }
void inCase(int x) { switch (x) { case 1: prepare(); target(); } }
`,
        owners: [
          "void ordered() { prepare(); target(); }",
          "void inCase(int x) { switch (x) { case 1: prepare(); target(); } }",
        ],
      },
    },
    {
      language: "csharp",
      extension: "cs",
      target: code("target()"),
      prepare: code("prepare()"),
      callables: {
        source: `class Owner {
  Owner() { target(); }
  ~Owner() { target(); }
  void Method() { target(); void Local() { target(); } }
  Action lambda = () => { target(); };
  Action anonymous = delegate { target(); };
  int Property { get { return target(); } }
  public static Owner operator +(Owner a, Owner b) { return target(); }
}
`,
        owners: [
          "Owner() { target(); }",
          "~Owner() { target(); }",
          "void Method() { target(); void Local() { target(); } }",
          "void Local() { target(); }",
          "() => { target(); }",
          "delegate { target(); }",
          "get { return target(); }",
          "public static Owner operator +(Owner a, Owner b) { return target(); }",
        ],
      },
      ordering: {
        source: `class Ordering {
  void Ordered() { prepare(); target(); }
  void Branches(bool flag) { if (flag) { prepare(); } else { target(); } }
  void Nested() { prepare(); Action inner = () => { target(); }; }
  void Cases(int x) { switch (x) { case 1: prepare(); break; default: target(); break; } }
  void InCase(int x) { switch (x) { case 1: prepare(); target(); break; } }
}
`,
        owners: [
          "void Ordered() { prepare(); target(); }",
          "void InCase(int x) { switch (x) { case 1: prepare(); target(); break; } }",
        ],
      },
    },
    {
      language: "php",
      extension: "php",
      target: code("target()"),
      prepare: code("prepare()"),
      callables: {
        source: `<?php
function declared() { target(); }
class Owner { function method() { target(); } }
$anonymous = function () { target(); };
$arrow = fn() => target();
`,
        owners: [
          "function declared() { target(); }",
          "function method() { target(); }",
          "function () { target(); }",
          "fn() => target()",
        ],
      },
      ordering: {
        source: `<?php
function ordered() { prepare(); target(); }
function branches($flag) { if ($flag) { prepare(); } else { target(); } }
function nested() { prepare(); $inner = function () { target(); }; }
function cases($x) { switch ($x) { case 1: prepare(); break; default: target(); } }
function inCase($x) { switch ($x) { case 1: prepare(); target(); } }
function inDefault($x) { switch ($x) { default: prepare(); target(); } }
function colon($flag) { if ($flag): prepare(); target(); endif; }
`,
        owners: [
          "function ordered() { prepare(); target(); }",
          "function inCase($x) { switch ($x) { case 1: prepare(); target(); } }",
          "function inDefault($x) { switch ($x) { default: prepare(); target(); } }",
          "function colon($flag) { if ($flag): prepare(); target(); endif; }",
        ],
      },
    },
    {
      language: "lua",
      extension: "lua",
      target: code("target()"),
      prepare: code("prepare()"),
      callables: {
        source: `function declared() target() end
local anonymous = function() target() end
`,
        owners: ["function declared() target() end", "function() target() end"],
      },
      ordering: {
        source: `function ordered() prepare() target() end
function branches(flag) if flag then prepare() else target() end end
function nested() prepare() local inner = function() target() end end
`,
        owners: ["function ordered() prepare() target() end"],
      },
    },
    {
      language: "kotlin",
      extension: "kt",
      target: code("target()"),
      prepare: code("prepare()"),
      callables: {
        source: `fun declared() { target() }
val anonymous = fun() { target() }
val lambda = { target() }
class Owner {
  constructor(x: Int) { target() }
}
`,
        owners: ["fun declared() { target() }", "fun() { target() }", "{ target() }", "constructor(x: Int) { target() }"],
      },
      ordering: {
        source: `fun ordered() { prepare(); target() }
fun branches(flag: Boolean) { if (flag) { prepare() } else { target() } }
fun nested() { prepare(); val inner = { target() } }
fun cases(x: Int) { when (x) { 1 -> { prepare() } else -> { target() } } }
fun inCase(x: Int) { when (x) { 1 -> { prepare(); target() } } }
`,
        owners: [
          "fun ordered() { prepare(); target() }",
          "fun inCase(x: Int) { when (x) { 1 -> { prepare(); target() } } }",
        ],
      },
    },
    {
      language: "swift",
      extension: "swift",
      target: code("target()"),
      prepare: code("prepare()"),
      callables: {
        source: `func declared() { target() }
let lambda = { target() }
class Owner {
  init() { target() }
  deinit { target() }
}
`,
        owners: ["func declared() { target() }", "{ target() }", "init() { target() }", "deinit { target() }"],
      },
      ordering: {
        source: `func ordered() { prepare(); target() }
func branches(flag: Bool) { if flag { prepare() } else { target() } }
func nested() { prepare(); let inner = { target() }; inner() }
func cases(x: Int) {
  switch x {
  case 1: prepare()
  default: target()
  }
}
func inCase(x: Int) {
  switch x {
  case 1:
    prepare()
    target()
  default: break
  }
}
`,
        owners: [
          "func ordered() { prepare(); target() }",
          "func inCase(x: Int) {\n  switch x {\n  case 1:\n    prepare()\n    target()\n  default: break\n  }\n}",
        ],
      },
    },
    {
      language: "dart",
      extension: "dart",
      // A bare \`target()\` parses as a Dart function signature, so it needs a context.
      target: "code() `void f() { target(); }` select call_expression",
      prepare: "code() `void f() { prepare(); }` select call_expression",
      callables: {
        source: `void declared() { target(); }
var anonymous = () { target(); };
int get topValue { return target(); }
set topValue(int v) { target(); }
class Owner {
  void method() { target(); }
}
void outer() { void local() { target(); } }
`,
        owners: [
          "void declared() { target(); }",
          "() { target(); }",
          "int get topValue { return target(); }",
          "set topValue(int v) { target(); }",
          "void method() { target(); }",
          "void local() { target(); }",
        ],
      },
      ordering: {
        source: `void ordered() { prepare(); target(); }
void branches(bool flag) { if (flag) { prepare(); } else { target(); } }
void nested() { prepare(); var inner = () { target(); }; }
void cases(int x) { switch (x) { case 1: prepare(); break; default: target(); } }
void inCase(int x) { switch (x) { case 1: prepare(); target(); } }
void inDefault(int x) { switch (x) { default: prepare(); target(); } }
`,
        owners: [
          "void ordered() { prepare(); target(); }",
          "void inCase(int x) { switch (x) { case 1: prepare(); target(); } }",
          "void inDefault(int x) { switch (x) { default: prepare(); target(); } }",
        ],
      },
    },
    {
      language: "bash",
      extension: "sh",
      target: code("target"),
      prepare: code("prepare"),
      callables: {
        source: "declared() { target; }\n",
        owners: ["declared() { target; }"],
      },
      ordering: {
        source: `ordered() { prepare; target; }
branches() { if flag; then prepare; else target; fi; }
looped() { for x in y; do prepare; target; done; }
cases() { case x in a) prepare;; b) target;; esac; }
inCase() { case x in a) prepare; target;; esac; }
`,
        owners: [
          "ordered() { prepare; target; }",
          "looped() { for x in y; do prepare; target; done; }",
          "inCase() { case x in a) prepare; target;; esac; }",
        ],
      },
    },
    {
      language: "ruby",
      extension: "rb",
      target: code("target()"),
      prepare: code("prepare()"),
      callables: {
        source: `def declared
  target()
end
def self.singleton
  target()
end
items.each do |x| target() end
items.map { |x| target() }
`,
        owners: [
          "def declared\n  target()\nend",
          "def self.singleton\n  target()\nend",
          "do |x| target() end",
          "{ |x| target() }",
        ],
      },
      ordering: {
        source: `def ordered
  prepare()
  target()
end
def branches(flag)
  if flag
    prepare()
  else
    target()
  end
end
def nested
  prepare()
  items.each { target() }
end
def cases(x)
  case x
  when 1
    prepare()
  else
    target()
  end
end
def in_branch(flag)
  if flag
    prepare()
    target()
  end
end
def in_loop
  while running
    prepare()
    target()
  end
end
def in_begin
  begin
    prepare()
    target()
  end
end
def in_ensure
  work()
ensure
  prepare()
  target()
end
`,
        owners: [
          "def ordered\n  prepare()\n  target()\nend",
          "def in_branch(flag)\n  if flag\n    prepare()\n    target()\n  end\nend",
          "def in_loop\n  while running\n    prepare()\n    target()\n  end\nend",
          "def in_begin\n  begin\n    prepare()\n    target()\n  end\nend",
          "def in_ensure\n  work()\nensure\n  prepare()\n  target()\nend",
        ],
      },
    },
  ];
  const rule = (language: string, target: string, clause = "") => `#badbox 1
rule ${language}/probe for ${language} {
  summary "probe"
  find ${target}
  group by nearest callable
${clause}
  when count > 0
  report {
    severity info
    message "probe"
    evidence "probe sites"
  }
}
`;
  const owners = async (language: string, extension: string, name: string, source: string, rules: string) => {
    const root = await temporaryRoot();
    const path = join(root, `${name}.${extension}`);
    const rulePath = join(root, `${name}.badbox`);
    await Bun.write(path, source);
    await Bun.write(rulePath, rules);
    const result = await inspect({ paths: [path], rulePaths: [rulePath] });
    return [
      language,
      result.diagnostics,
      await Promise.all(records(result).map(async (finding) => [await ownerText(finding), finding.observed])),
    ];
  };
  const once = (texts: string[]) => texts.map((text) => [text, 1]);

  test("group every mapped callable kind under its own owner", async () => {
    for (const probe of probes) {
      expect(await owners(probe.language, probe.extension, "callables", probe.callables.source,
        rule(probe.language, probe.target))).toEqual([probe.language, [], once(probe.callables.owners)]);
    }
  });

  test("order statements only within one callable and statement list", async () => {
    for (const probe of probes) {
      const clause = `  where match follows any { ${probe.prepare} }`;
      expect(await owners(probe.language, probe.extension, "ordering", probe.ordering.source,
        rule(probe.language, probe.target, clause))).toEqual([probe.language, [], once(probe.ordering.owners)]);
    }
  });

  test("languages without a callable mapping still reject callable grouping", async () => {
    const root = await temporaryRoot();
    const rulePath = join(root, "scala.badbox");
    await Bun.write(rulePath, rule("scala", code("target()")));
    await expect(inspect({ paths: [root], rulePaths: [rulePath] }))
      .rejects.toThrow("callable grouping, which is not mapped for scala");
  });
});
