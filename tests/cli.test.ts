import { afterAll, expect, test } from "bun:test";
import { mkdtemp, mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

const cli = fileURLToPath(new URL("../src/cli.ts", import.meta.url));
const temporaryRoots: string[] = [];

afterAll(async () => {
  await Promise.all(temporaryRoots.map((root) => rm(root, { recursive: true, force: true })));
});

async function projectWithRules(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "badbox-cli-test-"));
  temporaryRoots.push(root);
  await mkdir(join(root, ".badbox"));
  await mkdir(join(root, ".badbox", "nested"));
  await mkdir(join(root, "src"));
  await Bun.write(join(root, ".badbox", "clones.badbox"), `#badbox 1

rule rust/excessive-clones for rust {
  summary "Function contains multiple clone calls"
  find code(value) \`value.clone()\`
  group by nearest callable
  when count > 1
  report {
    severity info
    message "Callable contains too many clone call sites"
    evidence "clone call sites"
  }
}
`);
  await Bun.write(join(root, ".badbox", "nested", "unwraps.badbox"), `#badbox 1

rule rust/excessive-unwraps for rust {
  summary "Function contains multiple unwrap calls"
  find code(value) \`value.unwrap()\`
  group by nearest callable
  when count > 1
  report {
    severity warning
    message "Callable contains too many unwrap call sites"
    evidence "unwrap call sites"
  }
}
`);
  await Bun.write(
    join(root, "src", "sample.rs"),
    "fn example() { a.clone(); b.clone(); a.unwrap(); b.unwrap(); }",
  );
  return root;
}

test("check loads every rule from the project's .badbox directory", async () => {
  const project = await projectWithRules();
  const proc = Bun.spawn([process.execPath, cli, "check"], {
    cwd: project, stdout: "pipe", stderr: "pipe",
  });
  const [stdout, stderr, code] = await Promise.all([
    new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited,
  ]);
  expect(code).toBe(0);
  expect(stderr).toBe("");
  expect(stdout).toContain("rust/excessive-clones");
  expect(stdout).toContain("rust/excessive-unwraps");
  expect(stdout).toContain("2 > 1");
  expect(stdout).toContain("1 files checked, 2 findings");
});

test("check accepts explicit source paths but still gets rules from .badbox", async () => {
  const project = await projectWithRules();
  const proc = Bun.spawn([process.execPath, cli, "check", "src"], {
    cwd: project, stdout: "pipe", stderr: "pipe",
  });
  const stdout = await new Response(proc.stdout).text();
  expect(await proc.exited).toBe(0);
  expect(stdout).toContain("1 files checked, 2 findings");
});

test("check requires a project .badbox directory", async () => {
  const project = await mkdtemp(join(tmpdir(), "badbox-cli-empty-"));
  temporaryRoots.push(project);
  const proc = Bun.spawn([process.execPath, cli, "check"], {
    cwd: project, stdout: "pipe", stderr: "pipe",
  });
  const stderr = await new Response(proc.stderr).text();
  expect(await proc.exited).toBe(1);
  expect(stderr).toContain(".badbox");
});

test("the old scan command and unsupported flags are rejected", async () => {
  const project = await projectWithRules();
  const proc = Bun.spawn([process.execPath, cli, "scan"], {
    cwd: project, stdout: "pipe", stderr: "pipe",
  });
  const stderr = await new Response(proc.stderr).text();
  expect(await proc.exited).toBe(1);
  expect(stderr).toContain("Usage: badbox check");
  expect(stderr).not.toContain("badbox scan");
});

test("create initializes a versioned example rule under .badbox", async () => {
  const project = await mkdtemp(join(tmpdir(), "badbox-cli-create-"));
  temporaryRoots.push(project);
  const proc = Bun.spawn([process.execPath, cli, "create", "rust-rules.badbox"], {
    cwd: project, stdout: "pipe", stderr: "pipe",
  });
  const [stdout, stderr, code] = await Promise.all([
    new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited,
  ]);
  expect(code).toBe(0);
  expect(stderr).toBe("");
  expect(stdout).toContain(".badbox/rust-rules.badbox");
  const source = await Bun.file(join(project, ".badbox", "rust-rules.badbox")).text();
  expect(source.startsWith("#badbox 1\n")).toBe(true);
  expect(source).toContain("rule rust/example-excessive-clones for rust");
});

test("create refuses to overwrite an existing rule file", async () => {
  const project = await mkdtemp(join(tmpdir(), "badbox-cli-existing-"));
  temporaryRoots.push(project);
  await mkdir(join(project, ".badbox"));
  const path = join(project, ".badbox", "rust-rules.badbox");
  await Bun.write(path, "keep me");
  const proc = Bun.spawn([process.execPath, cli, "create", "rust-rules.badbox"], {
    cwd: project, stdout: "pipe", stderr: "pipe",
  });
  const stderr = await new Response(proc.stderr).text();
  expect(await proc.exited).toBe(1);
  expect(stderr).toContain("already exists");
  expect(await Bun.file(path).text()).toBe("keep me");
});

async function runCli(project: string, ...args: string[]) {
  const proc = Bun.spawn([process.execPath, cli, ...args], {
    cwd: project, stdout: "pipe", stderr: "pipe",
  });
  const [stdout, stderr, code] = await Promise.all([
    new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited,
  ]);
  return { stdout, stderr, code };
}

test("test runs rule fixtures declared under .badbox and fails on mismatches", async () => {
  const project = await projectWithRules();
  await mkdir(join(project, ".badbox", "fixtures"));
  await Bun.write(join(project, ".badbox", "fixtures", "clones.rs"), "fn f() { a.clone(); b.clone(); }");
  const rulePath = join(project, ".badbox", "clones.badbox");
  const rules = await Bun.file(rulePath).text();
  await Bun.write(rulePath, `${rules}
test rust/excessive-clones "reports clones" {
  input "fixtures/clones.rs"
  expect {
    findings 1
    count 2
  }
}
`);

  const passing = await runCli(project, "test");
  expect(passing.code).toBe(0);
  expect(passing.stderr).toBe("");
  expect(passing.stdout).toContain('PASS rust/excessive-clones "reports clones"');
  expect(passing.stdout).toContain("1 tests, 0 failed");

  await Bun.write(rulePath, `${await Bun.file(rulePath).text()}
test rust/excessive-clones "expects nothing" {
  input "fixtures/clones.rs"
  expect findings 0
}
`);
  const failing = await runCli(project, "test");
  expect(failing.code).toBe(1);
  expect(failing.stdout).toContain('FAIL rust/excessive-clones "expects nothing": expected 0 findings, got 1');
  expect(failing.stdout).toContain("2 tests, 1 failed");
});

test("test fails when the project declares no rule tests", async () => {
  const project = await projectWithRules();
  const result = await runCli(project, "test");
  expect(result.code).toBe(1);
  expect(result.stderr).toContain("no rule tests");
});

test("check flags select rules, override parameters, cap findings, and print JSON", async () => {
  const project = await projectWithRules();
  const rules = join(project, ".badbox", "clones.badbox");
  await Bun.write(rules, (await Bun.file(rules).text())
    .replace("  find code", "  param limit = 1\n  param method = \"clone\"\n  find code")
    .replace("when count > 1", "when count > limit")
    .replace('"Callable contains too many clone call sites"', '"{count} {method} calls, limit {limit}"'));
  await Bun.write(join(project, "src", "more.rs"), "fn more() { a.clone(); b.clone(); c.clone(); }");

  const json = await runCli(project, "check", "--rules", rules, "--json", "--max-findings", "1");
  expect(json.code).toBe(0);
  const output = JSON.parse(json.stdout);
  expect(output).toMatchObject({ checkedFiles: 2, findingCount: 2, suppressedCount: 0, truncated: true });
  expect(output.findings).toHaveLength(1);
  expect(output.findings[0]).toMatchObject({
    rule: "rust/excessive-clones",
    message: "3 clone calls, limit 1",
    start: { line: 1, column: 1, offset: 0 },
  });

  const overridden = await runCli(project, "check", "--rules", rules,
    "--param", "rust/excessive-clones.limit=2", "--param", 'rust/excessive-clones.method="42"');
  expect(overridden.code).toBe(0);
  expect(overridden.stdout).toContain("more.rs:1:1-1:47 [info] rust/excessive-clones: 3 42 calls, limit 2");
  expect(overridden.stdout).toContain("2 files checked, 1 findings, 0 suppressed, 0 diagnostics");

  const wrongType = await runCli(project, "check", "--param", "rust/excessive-clones.limit=many");
  expect(wrongType.code).toBe(1);
  expect(wrongType.stderr).toContain("must be an integer");

  const unknown = await runCli(project, "check", "--bogus");
  expect(unknown.code).toBe(1);
  expect(unknown.stderr).toContain("Usage: badbox check");
});

test("check reports how many findings badbox-ignore comments suppressed", async () => {
  const project = await projectWithRules();
  await Bun.write(join(project, "src", "sample.rs"),
    "// badbox-ignore rust/excessive-clones\nfn example() { a.clone(); b.clone(); a.unwrap(); b.unwrap(); }");
  const result = await runCli(project, "check");
  expect(result.code).toBe(0);
  expect(result.stdout).not.toContain("rust/excessive-clones");
  expect(result.stdout).toContain("2:1-2:63 [warning] rust/excessive-unwraps");
  expect(result.stdout).toContain("1 files checked, 1 findings, 1 suppressed, 0 diagnostics");
});

test("check --baseline-ref reports only findings the ref does not have", async () => {
  const project = await projectWithRules();
  const git = (...args: string[]) => {
    const result = Bun.spawnSync(["git", "-c", "user.name=badbox", "-c", "user.email=badbox@example.com", ...args],
      { cwd: project, stdout: "pipe", stderr: "pipe" });
    if (result.exitCode !== 0) throw new Error(result.stderr.toString());
  };
  git("init", "-q");
  git("add", "-A");
  git("commit", "-q", "-m", "base");
  const sample = join(project, "src", "sample.rs");
  await Bun.write(sample, `// unchanged code moved down a line\n${await Bun.file(sample).text()}\n` +
    "fn added() { a.clone(); b.clone(); }\n");
  await Bun.write(join(project, "src", "new.rs"), "fn fresh() { a.unwrap(); b.unwrap(); }");

  const result = await runCli(project, "check", "--baseline-ref", "HEAD");
  expect(result.stderr).toBe("");
  expect(result.code).toBe(0);
  expect(result.stdout).not.toContain("sample.rs:2:");
  expect(result.stdout).toContain("sample.rs:3:1-3:37 [info] rust/excessive-clones");
  expect(result.stdout).toContain("new.rs:1:1-1:39 [warning] rust/excessive-unwraps");
  expect(result.stdout).toContain("2 files checked, 2 findings, 2 also at HEAD, 0 suppressed, 0 diagnostics");
  const worktrees = Bun.spawnSync(["git", "worktree", "list"], { cwd: project, stdout: "pipe" });
  expect(worktrees.stdout.toString().trim().split("\n")).toHaveLength(1);

  const missing = await runCli(project, "check", "--baseline-ref", "no-such-ref");
  expect(missing.code).toBe(1);
  expect(missing.stderr).toContain("baseline ref no-such-ref is not a commit");
});
