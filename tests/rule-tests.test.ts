import { afterAll, describe, expect, test } from "bun:test";
import { mkdtemp, mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { testRules } from "../src/scanner/index.ts";

const temporaryRoots: string[] = [];

afterAll(async () => {
  await Promise.all(temporaryRoots.map((root) => rm(root, { recursive: true, force: true })));
});

async function temporaryRoot(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "badbox-rule-test-"));
  temporaryRoots.push(root);
  return root;
}

const cloneRule = `rule rust/excessive-clones for rust {
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
`;

describe("rule tests", () => {
  test("run each declared fixture against its rule and compare findings and count", async () => {
    const root = await temporaryRoot();
    await mkdir(join(root, "fixtures"));
    await Bun.write(join(root, "fixtures", "two.rs"), "fn two() { a.clone(); b.clone(); }");
    await Bun.write(join(root, "fixtures", "one.rs"), "fn one() { a.clone(); }");
    const rules = join(root, "clones.badbox");
    await Bun.write(rules, `#badbox 1

${cloneRule}
test rust/excessive-clones "reports two clones" {
  input "fixtures/two.rs"
  expect {
    findings 1
    count 2
  }
}

test rust/excessive-clones "accepts one clone" {
  input "fixtures/one.rs"
  expect findings 0
}

test rust/excessive-clones "wrong finding count" {
  input "fixtures/one.rs"
  expect findings 1
}

test rust/excessive-clones "wrong observed count" {
  input "fixtures/two.rs"
  expect {
    findings 1
    count 3
  }
}
`);

    const results = await testRules({ rulePaths: [rules] });
    expect(results.map((result) => [result.name, result.passed])).toEqual([
      ["reports two clones", true],
      ["accepts one clone", true],
      ["wrong finding count", false],
      ["wrong observed count", false],
    ]);
    expect(results[0]).toMatchObject({
      ruleFile: rules,
      ruleId: "rust/excessive-clones",
      input: join(root, "fixtures", "two.rs"),
      expected: { findings: 1, count: 2 },
      actual: { findings: 1, count: 2 },
    });
    expect(results[2]).toMatchObject({ expected: { findings: 1 }, actual: { findings: 0 } });
    expect(results[3]).toMatchObject({ expected: { findings: 1, count: 3 }, actual: { findings: 1, count: 2 } });
    expect(results.every((result) => result.error === undefined)).toBe(true);
  });

  test("fixture problems fail only that test with an explanation", async () => {
    const root = await temporaryRoot();
    await Bun.write(join(root, "broken.rs"), "fn broken() { a.clone(); fn (");
    await Bun.write(join(root, "wrong.go"), "package p\n");
    await Bun.write(join(root, "good.rs"), "fn good() {}");
    const rules = join(root, "clones.badbox");
    await Bun.write(rules, `#badbox 1

${cloneRule}
test rust/excessive-clones "missing fixture" {
  input "missing.rs"
  expect findings 0
}

test rust/excessive-clones "syntax error" {
  input "broken.rs"
  expect findings 0
}

test rust/excessive-clones "other language" {
  input "wrong.go"
  expect findings 0
}

test rust/excessive-clones "still runs" {
  input "good.rs"
  expect findings 0
}
`);

    const results = await testRules({ rulePaths: [rules] });
    expect(results.map((result) => result.passed)).toEqual([false, false, false, true]);
    expect(results[0]?.error).toContain("missing.rs");
    expect(results[1]?.error).toContain("syntax errors");
    expect(results[2]?.error).toContain("rust");
    expect(results.slice(0, 3).every((result) => result.actual === undefined)).toBe(true);
  });

  test("tests must name a rule declared in the same file", async () => {
    const root = await temporaryRoot();
    const rules = join(root, "clones.badbox");
    await Bun.write(rules, `#badbox 1

${cloneRule}
test rust/missing-rule "unknown" {
  input "good.rs"
  expect findings 0
}
`);
    await expect(testRules({ rulePaths: [rules] })).rejects.toThrow("rust/missing-rule");
  });

  test("files without tests contribute no results", async () => {
    const root = await temporaryRoot();
    const rules = join(root, "clones.badbox");
    await Bun.write(rules, `#badbox 1\n\n${cloneRule}`);
    expect(await testRules({ rulePaths: [rules] })).toEqual([]);
  });
});
