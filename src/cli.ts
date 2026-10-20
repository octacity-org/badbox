#!/usr/bin/env bun

import { inspect, testRules } from "./scanner/index.ts";
import type { RuleTestResult } from "./scanner/index.ts";
import { reportCheck } from "./reporters/terminal.ts";
import { formatJson } from "./reporters/json.ts";
import { checkAgainstRef } from "./baseline.ts";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, join } from "node:path";
import { parseArgs } from "node:util";

const usage = "Usage: badbox check [path ...] [--rules <path>]... [--param <rule.name=value>]...\n" +
  "                    [--max-findings <n>] [--json] [--baseline-ref <ref>]\n" +
  "       badbox test\n" +
  "       badbox create <name.badbox>";
const ruleTemplate = `#badbox 1

# Replace or remove this example rule.
rule rust/example-excessive-clones for rust {
  summary "Function contains excessive clone calls"
  param limit = 4
  find code(value) \`value.clone()\`
  group by nearest callable
  when count > limit
  report {
    severity warning
    message "Function contains more clone calls than the configured limit"
    evidence "clone call sites"
  }
}
`;

const [command, ...args] = Bun.argv.slice(2);

if (command === "check") {
  try {
    const { values, positionals } = parseArgs({
      args,
      allowPositionals: true,
      options: {
        rules: { type: "string", multiple: true },
        param: { type: "string", multiple: true },
        "max-findings": { type: "string" },
        json: { type: "boolean" },
        "baseline-ref": { type: "string" },
      },
    });
    const options = {
      paths: positionals.length ? positionals : [process.cwd()],
      rulePaths: values.rules ?? [join(process.cwd(), ".badbox")],
      parameters: Object.fromEntries((values.param ?? []).map(parameter)),
      maxFindings: values["max-findings"] === undefined ? undefined : count(values["max-findings"]),
    };
    const ref = values["baseline-ref"];
    const { result, baseline } = ref === undefined
      ? { result: await inspect(options), baseline: undefined }
      : await checkAgainstRef(ref, options);
    if (values.json) {
      console.log(formatJson(result, baseline));
    } else {
      reportCheck(result, baseline);
    }
    // Findings are observations, not errors. Incomplete checks are errors.
    if (result.diagnostics.length) process.exitCode = 1;
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    if (error instanceof Error && "code" in error && String(error.code).startsWith("ERR_PARSE_ARGS")) {
      console.error(usage);
    }
    process.exitCode = 1;
  }
} else if (command === "test" && args.length === 0) {
  try {
    const results = await testRules({ rulePaths: [join(process.cwd(), ".badbox")] });
    if (!results.length) {
      console.error("Found no rule tests in .badbox");
      process.exitCode = 1;
    } else {
      for (const result of results) {
        const label = `${result.ruleId} ${JSON.stringify(result.name)}`;
        console.log(result.passed ? `PASS ${label}` : `FAIL ${label}: ${failureReason(result)}`);
      }
      const failed = results.filter((result) => !result.passed).length;
      console.log(`${results.length} tests, ${failed} failed`);
      if (failed) process.exitCode = 1;
    }
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
} else if (command === "create" && args.length === 1) {
  const [name] = args;
  const segments = name!.split(/[\\/]/);
  if (!name!.endsWith(".badbox") || isAbsolute(name!) || segments.includes("..")) {
    console.error(usage);
    process.exitCode = 1;
  } else {
    const path = join(process.cwd(), ".badbox", name!);
    try {
      await mkdir(dirname(path), { recursive: true });
      await writeFile(path, ruleTemplate, { flag: "wx" });
      console.log(`Created .badbox/${name!.replaceAll("\\", "/")}`);
    } catch (error) {
      if (error && typeof error === "object" && "code" in error && error.code === "EEXIST") {
        console.error(`Rule file already exists: .badbox/${name!.replaceAll("\\", "/")}`);
      } else {
        console.error(error instanceof Error ? error.message : String(error));
      }
      process.exitCode = 1;
    }
  }
} else {
  console.error(usage);
  process.exitCode = 1;
}

/**
 * `rule.name=value`. Digits are an integer, `true`/`false` a boolean, anything else a string;
 * wrap the value in double quotes to force a string, as in `x/y.pattern="42"`.
 */
function parameter(argument: string): [string, string | number | boolean] {
  const separator = argument.indexOf("=");
  if (separator <= 0) throw new Error(`--param ${argument}: expected rule.name=value`);
  const [key, value] = [argument.slice(0, separator), argument.slice(separator + 1)];
  if (/^"[^]*"$/.test(value)) return [key, value.slice(1, -1)];
  if (/^\d+$/.test(value)) return [key, count(value)];
  if (value === "true" || value === "false") return [key, value === "true"];
  return [key, value];
}

function count(text: string): number {
  const value = Number(text);
  if (!/^\d+$/.test(text) || value > 0xffffffff) throw new Error(`${text} is not an unsigned 32-bit integer`);
  return value;
}

function failureReason(result: RuleTestResult): string {
  const { expected, actual } = result;
  if (!actual) return result.error ?? "fixture was not checked";
  if (actual.findings !== expected.findings) {
    return `expected ${expected.findings} findings, got ${actual.findings}`;
  }
  return `expected count ${expected.count}, got ${actual.count}`;
}
